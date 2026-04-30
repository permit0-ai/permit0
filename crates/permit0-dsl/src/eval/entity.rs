#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde_json::Value;

use crate::eval::path::resolve_path;
use crate::helpers::HelperFn;
use crate::schema::normalizer::EntityDef;

/// Extract entities from raw parameters according to entity definitions.
pub fn extract_entities(
    params: &Value,
    entity_defs: &HashMap<String, EntityDef>,
    helpers: &HashMap<&str, (HelperFn, usize)>,
) -> Result<HashMap<String, Value>, EntityError> {
    let mut result = HashMap::new();
    for (name, def) in entity_defs {
        let val = extract_one(params, def, helpers)?;
        let is_required = def.required.unwrap_or(false);
        let is_optional = def.optional.unwrap_or(false);

        match val {
            Some(v) => {
                result.insert(name.clone(), v);
            }
            None => {
                if is_required && !is_optional {
                    return Err(EntityError::MissingRequired(name.clone()));
                }
                if let Some(ref default) = def.default {
                    result.insert(name.clone(), default.clone());
                }
            }
        }
    }
    Ok(result)
}

fn extract_one(
    params: &Value,
    def: &EntityDef,
    helpers: &HashMap<&str, (HelperFn, usize)>,
) -> Result<Option<Value>, EntityError> {
    // If compute is specified, use a helper function
    if let Some(ref compute) = def.compute {
        return compute_entity(params, compute, def.args.as_deref(), helpers);
    }

    // Otherwise extract from path
    let path = match def.from.as_deref() {
        Some(p) => p,
        None => return Ok(None),
    };
    let raw = match resolve_path(params, path) {
        Some(v) => v.clone(),
        None => return Ok(None),
    };

    // Apply type coercion
    let coerced = match def.value_type.as_deref() {
        Some("string") => coerce_to_string(&raw),
        Some("number" | "int" | "integer") => coerce_to_number(&raw),
        Some("bool" | "boolean") => coerce_to_bool(&raw),
        _ => raw,
    };

    // Apply transformations
    let transformed = apply_transforms(&coerced, def);
    Ok(Some(transformed))
}

fn compute_entity(
    params: &Value,
    helper_name: &str,
    args: Option<&[String]>,
    helpers: &HashMap<&str, (HelperFn, usize)>,
) -> Result<Option<Value>, EntityError> {
    let (func, arity) = helpers
        .get(helper_name)
        .ok_or_else(|| EntityError::UnknownHelper(helper_name.to_string()))?;

    let arg_paths = args.unwrap_or(&[]);
    if arg_paths.len() != *arity {
        return Err(EntityError::ArityMismatch {
            helper: helper_name.to_string(),
            expected: *arity,
            got: arg_paths.len(),
        });
    }

    let resolved: Vec<Value> = arg_paths
        .iter()
        .map(|path| resolve_path(params, path).cloned().unwrap_or(Value::Null))
        .collect();

    let result = func(&resolved);
    Ok(Some(result))
}

fn coerce_to_string(v: &Value) -> Value {
    match v {
        Value::String(_) => v.clone(),
        Value::Number(n) => Value::String(n.to_string()),
        Value::Bool(b) => Value::String(b.to_string()),
        Value::Null => Value::String(String::new()),
        _ => v.clone(),
    }
}

fn coerce_to_number(v: &Value) -> Value {
    match v {
        Value::Number(_) => v.clone(),
        Value::String(s) => s
            .parse::<f64>()
            .map(|n| serde_json::json!(n))
            .unwrap_or(Value::Null),
        Value::Bool(b) => serde_json::json!(if *b { 1 } else { 0 }),
        _ => Value::Null,
    }
}

fn coerce_to_bool(v: &Value) -> Value {
    match v {
        Value::Bool(_) => v.clone(),
        Value::String(s) => match s.as_str() {
            "true" | "1" | "yes" => Value::Bool(true),
            "false" | "0" | "no" | "" => Value::Bool(false),
            _ => Value::Null,
        },
        Value::Number(n) => Value::Bool(n.as_f64().is_some_and(|f| f != 0.0)),
        Value::Null => Value::Bool(false),
        _ => Value::Null,
    }
}

fn apply_transforms(v: &Value, def: &EntityDef) -> Value {
    let mut val = v.clone();
    if let Value::String(ref mut s) = val {
        if def.trim.unwrap_or(false) {
            *s = s.trim().to_string();
        }
        if def.lowercase.unwrap_or(false) {
            *s = s.to_lowercase();
        }
        if def.uppercase.unwrap_or(false) {
            *s = s.to_uppercase();
        }
    }
    val
}

/// Entity extraction errors.
#[derive(Debug, thiserror::Error)]
pub enum EntityError {
    #[error("missing required entity: {0}")]
    MissingRequired(String),
    #[error("unknown helper: {0}")]
    UnknownHelper(String),
    #[error("helper `{helper}` expects {expected} args, got {got}")]
    ArityMismatch {
        helper: String,
        expected: usize,
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::build_helper_registry;
    use serde_json::json;

    fn make_def(from: Option<&str>) -> EntityDef {
        EntityDef {
            from: from.map(|s| s.to_string()),
            value_type: None,
            required: None,
            optional: None,
            default: None,
            lowercase: None,
            uppercase: None,
            trim: None,
            compute: None,
            args: None,
        }
    }

    #[test]
    fn extract_from_path() {
        let params = json!({"url": "https://api.stripe.com", "method": "POST"});
        let mut defs = HashMap::new();
        defs.insert("url".to_string(), make_def(Some("url")));
        defs.insert("method".to_string(), make_def(Some("method")));

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers).unwrap();
        assert_eq!(result["url"], json!("https://api.stripe.com"));
        assert_eq!(result["method"], json!("POST"));
    }

    #[test]
    fn extract_nested_path() {
        let params = json!({"body": {"amount": 5000}});
        let mut defs = HashMap::new();
        defs.insert("amount".to_string(), make_def(Some("body.amount")));

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers).unwrap();
        assert_eq!(result["amount"], json!(5000));
    }

    #[test]
    fn missing_required() {
        let params = json!({});
        let mut defs = HashMap::new();
        let mut def = make_def(Some("missing_field"));
        def.required = Some(true);
        defs.insert("val".to_string(), def);

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers);
        assert!(result.is_err());
    }

    #[test]
    fn default_value() {
        let params = json!({});
        let mut defs = HashMap::new();
        let mut def = make_def(Some("missing_field"));
        def.default = Some(json!("fallback"));
        defs.insert("val".to_string(), def);

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers).unwrap();
        assert_eq!(result["val"], json!("fallback"));
    }

    #[test]
    fn compute_helper() {
        let params = json!({"url": "https://api.stripe.com/v1/charges"});
        let mut defs = HashMap::new();
        let mut def = make_def(None);
        def.compute = Some("url_host".to_string());
        def.args = Some(vec!["url".to_string()]);
        defs.insert("host".to_string(), def);

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers).unwrap();
        assert_eq!(result["host"], json!("api.stripe.com"));
    }

    #[test]
    fn lowercase_transform() {
        let params = json!({"name": "  HELLO  "});
        let mut defs = HashMap::new();
        let mut def = make_def(Some("name"));
        def.trim = Some(true);
        def.lowercase = Some(true);
        defs.insert("name".to_string(), def);

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers).unwrap();
        assert_eq!(result["name"], json!("hello"));
    }

    #[test]
    fn type_coercion_to_string() {
        let params = json!({"count": 42});
        let mut defs = HashMap::new();
        let mut def = make_def(Some("count"));
        def.value_type = Some("string".to_string());
        defs.insert("count".to_string(), def);

        let helpers = build_helper_registry();
        let result = extract_entities(&params, &defs, &helpers).unwrap();
        assert_eq!(result["count"], json!("42"));
    }
}
