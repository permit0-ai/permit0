#![forbid(unsafe_code)]

use permit0_scoring::template::RiskTemplate;
use permit0_types::FlagRole;

use crate::eval::matcher::{MatchContext, NamedSets, eval_condition};
use crate::schema::risk_rule::{MutationDef, RiskRuleDef};

/// Build a RiskTemplate from a risk rule definition and action data.
///
/// Back-compat wrapper: evaluates rules with no named sets available. Rules
/// using `in_set` / `not_in_set` fail closed under this path — use
/// [`execute_risk_rules_with_sets`] to pass named sets in.
pub fn execute_risk_rules(
    rule_def: &RiskRuleDef,
    data: &serde_json::Value,
    tool_name: Option<&str>,
) -> RiskTemplate {
    execute_risk_rules_with_sets(rule_def, data, tool_name, None)
}

/// Build a RiskTemplate from a risk rule definition and action data, with access
/// to named sets (for `in_set` / `not_in_set` predicates).
///
/// Steps:
/// 1. Initialize template from the `base` section (flags + amplifiers).
/// 2. Evaluate each `rule` — if its `when` matches, apply its `then` mutations.
/// 3. Return the fully-mutated template (session_rules are evaluated later by the engine).
pub fn execute_risk_rules_with_sets(
    rule_def: &RiskRuleDef,
    data: &serde_json::Value,
    tool_name: Option<&str>,
    named_sets: Option<&NamedSets>,
) -> RiskTemplate {
    let mut template = build_base(&rule_def.base);

    let ctx = MatchContext::with_sets(data, tool_name, named_sets);

    for rule in &rule_def.rules {
        if eval_condition(&rule.when, &ctx) {
            apply_mutations(&mut template, &rule.then);
        }
    }

    template
}

/// Build template from base definition.
fn build_base(base: &crate::schema::risk_rule::RiskBaseDef) -> RiskTemplate {
    let mut template = RiskTemplate::new();
    for (flag, role_str) in &base.flags {
        let role = match role_str.as_str() {
            "primary" => FlagRole::Primary,
            _ => FlagRole::Secondary,
        };
        template.add(flag, role);
    }
    for (dim, value) in &base.amplifiers {
        *template.amplifiers.entry(dim.clone()).or_insert(0) = *value;
    }
    template
}

/// Apply a list of mutations to a template.
fn apply_mutations(template: &mut RiskTemplate, mutations: &[MutationDef]) {
    for m in mutations {
        apply_one(template, m);
    }
}

fn apply_one(template: &mut RiskTemplate, mutation: &MutationDef) {
    match mutation {
        MutationDef::Gate { gate } => {
            template.gate(gate);
        }
        MutationDef::AddFlag { add_flag } => {
            let role = match add_flag.role.as_str() {
                "primary" => FlagRole::Primary,
                _ => FlagRole::Secondary,
            };
            template.add(&add_flag.flag, role);
        }
        MutationDef::RemoveFlag { remove_flag } => {
            template.remove(remove_flag);
        }
        MutationDef::PromoteFlag { promote_flag } => {
            template.promote(promote_flag);
        }
        MutationDef::Upgrade { upgrade } => {
            template.upgrade(&upgrade.dim, upgrade.delta);
        }
        MutationDef::Downgrade { downgrade } => {
            template.downgrade(&downgrade.dim, downgrade.delta);
        }
        MutationDef::Override { override_amp } => {
            template.override_amp(&override_amp.dim, override_amp.value);
        }
        MutationDef::Split { split } => {
            let mut child = RiskTemplate::new();
            for (flag, role_str) in &split.flags {
                let role = match role_str.as_str() {
                    "primary" => FlagRole::Primary,
                    _ => FlagRole::Secondary,
                };
                child.add(flag, role);
            }
            for (dim, value) in &split.amplifiers {
                *child.amplifiers.entry(dim.clone()).or_insert(0) = *value;
            }
            template.split(child);
        }
    }
}

/// Evaluate session rules against session data (back-compat, no named sets).
pub fn execute_session_rules(
    rule_def: &RiskRuleDef,
    template: &mut RiskTemplate,
    session_data: &serde_json::Value,
) {
    execute_session_rules_with_sets(rule_def, template, session_data, None);
}

/// Evaluate session rules against session data with named sets available.
pub fn execute_session_rules_with_sets(
    rule_def: &RiskRuleDef,
    template: &mut RiskTemplate,
    session_data: &serde_json::Value,
    named_sets: Option<&NamedSets>,
) {
    let ctx = MatchContext::with_sets(session_data, None, named_sets);
    for rule in &rule_def.session_rules {
        if eval_condition(&rule.when, &ctx) {
            apply_mutations(template, &rule.then);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RISK_RULE_YAML: &str = r#"
permit0_pack: "permit0/stripe"
action_type: "payments.charge"
base:
  flags:
    financial_write: primary
    external_transfer: secondary
  amplifiers:
    amount: 5
    scope: 3
    reversibility: 4
rules:
  - when:
      body.amount:
        gt: 10000
    then:
      - upgrade:
          dim: amount
          delta: 3
      - add_flag:
          flag: high_value
          role: primary
  - when:
      body.currency:
        in: [btc, eth, xmr]
    then:
      - gate: "crypto_currency_block"
  - when:
      body.amount:
        lte: 100
    then:
      - downgrade:
          dim: amount
          delta: 2
session_rules:
  - when:
      daily_total:
        gt: 50000
    then:
      - add_flag:
          flag: velocity_alert
          role: primary
      - upgrade:
          dim: scope
          delta: 2
"#;

    fn parse_rule() -> RiskRuleDef {
        serde_yaml::from_str(RISK_RULE_YAML).unwrap()
    }

    #[test]
    fn base_template() {
        let rule_def = parse_rule();
        let data = json!({"body": {"amount": 5000, "currency": "usd"}});
        let template = execute_risk_rules(&rule_def, &data, None);

        assert_eq!(
            template.flags.get("financial_write"),
            Some(&FlagRole::Primary)
        );
        assert_eq!(
            template.flags.get("external_transfer"),
            Some(&FlagRole::Secondary)
        );
        assert_eq!(template.amplifiers.get("amount"), Some(&5));
        assert!(!template.blocked);
    }

    #[test]
    fn high_value_upgrade() {
        let rule_def = parse_rule();
        let data = json!({"body": {"amount": 50000, "currency": "usd"}});
        let template = execute_risk_rules(&rule_def, &data, None);

        // amount should be upgraded by 3: 5 + 3 = 8
        assert_eq!(template.amplifiers.get("amount"), Some(&8));
        assert_eq!(template.flags.get("high_value"), Some(&FlagRole::Primary));
    }

    #[test]
    fn crypto_gate() {
        let rule_def = parse_rule();
        let data = json!({"body": {"amount": 1000, "currency": "btc"}});
        let template = execute_risk_rules(&rule_def, &data, None);

        assert!(template.blocked);
        assert_eq!(
            template.block_reason.as_deref(),
            Some("crypto_currency_block")
        );
    }

    #[test]
    fn low_value_downgrade() {
        let rule_def = parse_rule();
        let data = json!({"body": {"amount": 50, "currency": "usd"}});
        let template = execute_risk_rules(&rule_def, &data, None);

        // amount should be downgraded by 2: 5 - 2 = 3
        assert_eq!(template.amplifiers.get("amount"), Some(&3));
    }

    #[test]
    fn session_rules_apply() {
        let rule_def = parse_rule();
        let data = json!({"body": {"amount": 5000, "currency": "usd"}});
        let mut template = execute_risk_rules(&rule_def, &data, None);

        let session_data = json!({"daily_total": 60000});
        execute_session_rules(&rule_def, &mut template, &session_data);

        assert_eq!(
            template.flags.get("velocity_alert"),
            Some(&FlagRole::Primary)
        );
        // scope upgraded by 2: 3 + 2 = 5
        assert_eq!(template.amplifiers.get("scope"), Some(&5));
    }

    #[test]
    fn no_rules_match() {
        let rule_def = parse_rule();
        let data = json!({"body": {"amount": 5000, "currency": "usd"}});
        let template = execute_risk_rules(&rule_def, &data, None);

        // No rules should have matched except base
        assert!(!template.blocked);
        assert_eq!(template.flags.len(), 2);
        assert_eq!(template.amplifiers.get("amount"), Some(&5));
    }
}
