#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use permit0_types::Tier;

use crate::types::{ActionRecord, SessionFilter};

/// Session context: the history of prior actions in the current session.
///
/// All methods operate on the `records` vec, which is ordered by timestamp (oldest first).
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub records: Vec<ActionRecord>,
}

impl SessionContext {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            records: Vec::new(),
        }
    }

    /// Add an action record to the session.
    pub fn push(&mut self, record: ActionRecord) {
        self.records.push(record);
    }

    /// Current time as unix seconds.
    fn now_secs() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }

    // ── Basic operations ────────────────────────────────────────

    /// Records within the last N seconds.
    pub fn recent(&self, seconds: u64) -> Vec<&ActionRecord> {
        let cutoff = Self::now_secs() - seconds as f64;
        self.records
            .iter()
            .filter(|r| r.timestamp >= cutoff)
            .collect()
    }

    /// Count records matching optional action_type and/or flag.
    pub fn count(&self, action_type: Option<&str>, flag: Option<&str>) -> usize {
        self.records
            .iter()
            .filter(|r| {
                action_type.is_none_or(|at| r.action_type == at)
                    && flag.is_none_or(|f| r.flags.contains(&f.to_string()))
            })
            .count()
    }

    /// Highest tier observed in the session.
    pub fn max_tier(&self) -> Tier {
        self.records
            .iter()
            .map(|r| r.tier)
            .max()
            .unwrap_or(Tier::Minimal)
    }

    /// Flags from the last N actions (most recent first).
    pub fn flag_sequence(&self, last_n: usize) -> Vec<String> {
        self.records
            .iter()
            .rev()
            .take(last_n)
            .flat_map(|r| r.flags.iter().cloned())
            .collect()
    }

    /// Actions per minute for a given action type (over entire session).
    pub fn rate_per_minute(&self, action_type: &str) -> f64 {
        let matching: Vec<&ActionRecord> = self
            .records
            .iter()
            .filter(|r| r.action_type == action_type)
            .collect();
        if matching.len() < 2 {
            return matching.len() as f64;
        }
        let first = matching.first().unwrap().timestamp;
        let last = matching.last().unwrap().timestamp;
        let span_min = (last - first) / 60.0;
        if span_min < 0.001 {
            return matching.len() as f64;
        }
        matching.len() as f64 / span_min
    }

    /// Whether any of the listed action types appeared in the last `within` actions.
    pub fn preceded_by(&self, action_types: &[&str], within: usize) -> bool {
        let recent: Vec<&str> = self
            .records
            .iter()
            .rev()
            .take(within)
            .map(|r| r.action_type.as_str())
            .collect();
        action_types.iter().any(|at| recent.contains(at))
    }

    // ── Filtering helpers ───────────────────────────────────────

    /// Apply a SessionFilter to get matching records.
    pub fn filter_records<'a>(&'a self, filter: &SessionFilter) -> Vec<&'a ActionRecord> {
        let now = Self::now_secs();
        self.records
            .iter()
            .filter(|r| {
                // Time window
                if let Some(mins) = filter.within_minutes {
                    if r.timestamp < now - (mins as f64 * 60.0) {
                        return false;
                    }
                }
                // Action type
                if let Some(ref at) = filter.action_type {
                    if r.action_type != *at {
                        return false;
                    }
                }
                // Action types (OR)
                if let Some(ref ats) = filter.action_types {
                    if !ats.contains(&r.action_type) {
                        return false;
                    }
                }
                // Entity match
                if let Some(ref matches) = filter.entity_match {
                    for (field, expected) in matches {
                        match r.entities.get(field) {
                            Some(actual) if actual == expected => {}
                            _ => return false,
                        }
                    }
                }
                true
            })
            .collect()
    }

    /// Filter records, returning those matching + numeric comparison on entity field.
    fn filter_numeric_values(&self, field: &str, filter: &SessionFilter) -> Vec<f64> {
        self.filter_records(filter)
            .iter()
            .filter_map(|r| r.entities.get(field).and_then(as_f64))
            .collect()
    }

    // ── Numeric aggregation (10b) ───────────────────────────────

    /// Sum of an entity field across matching records.
    pub fn sum(&self, field: &str, filter: &SessionFilter) -> f64 {
        self.filter_numeric_values(field, filter).iter().sum()
    }

    /// Maximum value of an entity field.
    pub fn max_val(&self, field: &str, filter: &SessionFilter) -> Option<f64> {
        self.filter_numeric_values(field, filter)
            .iter()
            .copied()
            .reduce(f64::max)
    }

    /// Minimum value of an entity field.
    pub fn min_val(&self, field: &str, filter: &SessionFilter) -> Option<f64> {
        self.filter_numeric_values(field, filter)
            .iter()
            .copied()
            .reduce(f64::min)
    }

    /// Average value of an entity field.
    pub fn avg(&self, field: &str, filter: &SessionFilter) -> Option<f64> {
        let vals = self.filter_numeric_values(field, filter);
        if vals.is_empty() {
            None
        } else {
            Some(vals.iter().sum::<f64>() / vals.len() as f64)
        }
    }

    // ── Advanced counting (10c) ─────────────────────────────────

    /// Count records matching filter + entity conditions.
    pub fn count_where(&self, filter: &SessionFilter) -> usize {
        self.filter_records(filter).len()
    }

    /// Count distinct values of an entity field across matching records.
    pub fn distinct_count(&self, field: &str, filter: &SessionFilter) -> usize {
        self.distinct_values(field, filter).len()
    }

    /// Collect distinct values of an entity field.
    pub fn distinct_values(&self, field: &str, filter: &SessionFilter) -> Vec<Value> {
        let mut seen = Vec::new();
        for record in self.filter_records(filter) {
            if let Some(val) = record.entities.get(field) {
                if !seen.contains(val) {
                    seen.push(val.clone());
                }
            }
        }
        seen
    }

    // ── Frequency & time (10d) ──────────────────────────────────

    /// Rate per minute scoped to a time window.
    pub fn rate_per_minute_windowed(&self, action_type: &str, within_min: u64) -> f64 {
        let now = Self::now_secs();
        let cutoff = now - (within_min as f64 * 60.0);
        let matching: Vec<&ActionRecord> = self
            .records
            .iter()
            .filter(|r| r.action_type == action_type && r.timestamp >= cutoff)
            .collect();
        if matching.is_empty() {
            return 0.0;
        }
        // Rate = count / window_minutes
        matching.len() as f64 / within_min as f64
    }

    /// How long the session has been active (minutes).
    pub fn duration_minutes(&self) -> f64 {
        if self.records.is_empty() {
            return 0.0;
        }
        let first = self.records.first().unwrap().timestamp;
        let last = self.records.last().unwrap().timestamp;
        (last - first) / 60.0
    }

    /// Detects silence followed by a burst of activity.
    ///
    /// Returns true if there was at least `idle_min` minutes of no activity
    /// followed by at least `burst_count` actions within `burst_window_min` minutes.
    pub fn idle_then_burst(
        &self,
        idle_min: u64,
        burst_count: usize,
        burst_window_min: u64,
    ) -> bool {
        if self.records.len() < burst_count {
            return false;
        }
        let idle_secs = idle_min as f64 * 60.0;
        let burst_secs = burst_window_min as f64 * 60.0;

        // Look for a gap >= idle_min between consecutive records
        for i in 1..self.records.len() {
            let gap = self.records[i].timestamp - self.records[i - 1].timestamp;
            if gap >= idle_secs {
                // Count actions within burst_window_min after the gap
                let burst_start = self.records[i].timestamp;
                let burst_end = burst_start + burst_secs;
                let count = self.records[i..]
                    .iter()
                    .filter(|r| r.timestamp <= burst_end)
                    .count();
                if count >= burst_count {
                    return true;
                }
            }
        }
        false
    }

    /// Detects accelerating action frequency over sliding windows.
    ///
    /// Splits matching records into `window_count` equal windows and checks
    /// whether each window has `factor` times more actions than the previous.
    pub fn accelerating(&self, action_type: &str, window_count: usize, factor: f64) -> bool {
        let matching: Vec<&ActionRecord> = self
            .records
            .iter()
            .filter(|r| r.action_type == action_type)
            .collect();
        if matching.len() < window_count * 2 {
            return false;
        }
        let first_ts = matching.first().unwrap().timestamp;
        let last_ts = matching.last().unwrap().timestamp;
        let span = last_ts - first_ts;
        if span < 1.0 {
            return false;
        }
        let window_size = span / window_count as f64;

        let mut prev_count = 0usize;
        for w in 0..window_count {
            let win_start = first_ts + w as f64 * window_size;
            let win_end = win_start + window_size;
            let count = matching
                .iter()
                .filter(|r| r.timestamp >= win_start && r.timestamp < win_end)
                .count();
            if w > 0 && prev_count > 0 && (count as f64) < (prev_count as f64 * factor) {
                return false;
            }
            prev_count = count;
        }
        // At least some acceleration must have been detected
        prev_count > 0
    }

    // ── Pattern & set operations (10e) ──────────────────────────

    /// Ordered or unordered subsequence detection.
    ///
    /// If `ordered`, checks that the pattern appears as an ordered subsequence
    /// in the last `within` actions. If unordered, checks that all pattern
    /// elements appear in the last `within` actions.
    pub fn sequence(&self, pattern: &[&str], within: usize, ordered: bool) -> bool {
        let recent_types: Vec<&str> = self
            .records
            .iter()
            .rev()
            .take(within)
            .map(|r| r.action_type.as_str())
            .collect();

        if ordered {
            // Check ordered subsequence (reversed because recent_types is newest-first)
            let reversed: Vec<&str> = recent_types.into_iter().rev().collect();
            let mut pattern_idx = 0;
            for at in &reversed {
                if pattern_idx < pattern.len() && *at == pattern[pattern_idx] {
                    pattern_idx += 1;
                }
            }
            pattern_idx == pattern.len()
        } else {
            // All pattern elements must appear
            pattern.iter().all(|p| recent_types.contains(p))
        }
    }

    /// Number of distinct risk flags observed in a time window.
    pub fn distinct_flags(&self, within_min: Option<u64>) -> usize {
        let now = Self::now_secs();
        let flags: HashSet<&str> = self
            .records
            .iter()
            .filter(|r| within_min.is_none_or(|mins| r.timestamp >= now - (mins as f64 * 60.0)))
            .flat_map(|r| r.flags.iter().map(|f| f.as_str()))
            .collect();
        flags.len()
    }

    /// Ratio of record counts matching two filters.
    pub fn ratio(&self, numerator: &SessionFilter, denominator: &SessionFilter) -> f64 {
        let denom = self.filter_records(denominator).len();
        if denom == 0 {
            return 0.0;
        }
        let numer = self.filter_records(numerator).len();
        numer as f64 / denom as f64
    }
}

/// Extract f64 from a JSON value.
fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_record(action_type: &str, tier: Tier, ts: f64) -> ActionRecord {
        ActionRecord {
            action_type: action_type.into(),
            tier,
            flags: vec![],
            timestamp: ts,
            entities: serde_json::Map::new(),
        }
    }

    fn make_record_with_entities(
        action_type: &str,
        tier: Tier,
        ts: f64,
        entities: Vec<(&str, Value)>,
    ) -> ActionRecord {
        let mut ents = serde_json::Map::new();
        for (k, v) in entities {
            ents.insert(k.into(), v);
        }
        ActionRecord {
            action_type: action_type.into(),
            tier,
            flags: vec![],
            timestamp: ts,
            entities: ents,
        }
    }

    fn make_record_with_flags(
        action_type: &str,
        tier: Tier,
        ts: f64,
        flags: Vec<&str>,
    ) -> ActionRecord {
        ActionRecord {
            action_type: action_type.into(),
            tier,
            flags: flags.into_iter().map(String::from).collect(),
            timestamp: ts,
            entities: serde_json::Map::new(),
        }
    }

    fn base_ts() -> f64 {
        // Use a fixed base timestamp for deterministic tests
        1_700_000_000.0
    }

    #[test]
    fn count_by_action_type() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record("payments.charge", Tier::Low, base_ts()));
        ctx.push(make_record("payments.charge", Tier::Low, base_ts() + 1.0));
        ctx.push(make_record("email.send", Tier::Low, base_ts() + 2.0));

        assert_eq!(ctx.count(Some("payments.charge"), None), 2);
        assert_eq!(ctx.count(Some("email.send"), None), 1);
        assert_eq!(ctx.count(None, None), 3);
    }

    #[test]
    fn count_by_flag() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record_with_flags(
            "payments.charge",
            Tier::Low,
            base_ts(),
            vec!["high_value"],
        ));
        ctx.push(make_record("payments.charge", Tier::Low, base_ts() + 1.0));

        assert_eq!(ctx.count(None, Some("high_value")), 1);
    }

    #[test]
    fn max_tier() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record("a", Tier::Low, base_ts()));
        ctx.push(make_record("b", Tier::High, base_ts() + 1.0));
        ctx.push(make_record("c", Tier::Medium, base_ts() + 2.0));

        assert_eq!(ctx.max_tier(), Tier::High);
    }

    #[test]
    fn max_tier_empty() {
        let ctx = SessionContext::new("test");
        assert_eq!(ctx.max_tier(), Tier::Minimal);
    }

    #[test]
    fn flag_sequence() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record_with_flags(
            "a",
            Tier::Low,
            base_ts(),
            vec!["EXPOSURE"],
        ));
        ctx.push(make_record_with_flags(
            "b",
            Tier::Low,
            base_ts() + 1.0,
            vec!["MUTATION"],
        ));
        ctx.push(make_record_with_flags(
            "c",
            Tier::Low,
            base_ts() + 2.0,
            vec!["FINANCIAL"],
        ));

        let flags = ctx.flag_sequence(2);
        // Most recent first: FINANCIAL, MUTATION
        assert_eq!(flags, vec!["FINANCIAL", "MUTATION"]);
    }

    #[test]
    fn rate_per_minute() {
        let mut ctx = SessionContext::new("test");
        // 3 charges over 2 minutes
        ctx.push(make_record("payments.charge", Tier::Low, base_ts()));
        ctx.push(make_record("payments.charge", Tier::Low, base_ts() + 60.0));
        ctx.push(make_record("payments.charge", Tier::Low, base_ts() + 120.0));

        let rate = ctx.rate_per_minute("payments.charge");
        assert!((rate - 1.5).abs() < 0.01); // 3 / 2min = 1.5
    }

    #[test]
    fn preceded_by() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record("files.read", Tier::Low, base_ts()));
        ctx.push(make_record("db.select", Tier::Low, base_ts() + 1.0));
        ctx.push(make_record("email.send", Tier::Low, base_ts() + 2.0));

        assert!(ctx.preceded_by(&["files.read"], 5));
        assert!(ctx.preceded_by(&["db.select"], 2));
        assert!(!ctx.preceded_by(&["iam.assign_role"], 5));
    }

    // ── Numeric aggregation tests ───────────────────────────────

    #[test]
    fn sum_entity_field() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record_with_entities(
            "payments.transfer",
            Tier::Medium,
            base_ts(),
            vec![("amount", json!(50000))],
        ));
        ctx.push(make_record_with_entities(
            "payments.transfer",
            Tier::Medium,
            base_ts() + 1.0,
            vec![("amount", json!(100000))],
        ));

        let filter = SessionFilter::new().with_action_type("payments.transfer");
        assert_eq!(ctx.sum("amount", &filter), 150000.0);
    }

    #[test]
    fn max_min_avg() {
        let mut ctx = SessionContext::new("test");
        for (i, amt) in [100, 500, 300].iter().enumerate() {
            ctx.push(make_record_with_entities(
                "payments.charge",
                Tier::Low,
                base_ts() + i as f64,
                vec![("amount", json!(amt))],
            ));
        }
        let filter = SessionFilter::new().with_action_type("payments.charge");
        assert_eq!(ctx.max_val("amount", &filter), Some(500.0));
        assert_eq!(ctx.min_val("amount", &filter), Some(100.0));
        assert_eq!(ctx.avg("amount", &filter), Some(300.0));
    }

    // ── Advanced counting tests ─────────────────────────────────

    #[test]
    fn distinct_count_recipients() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record_with_entities(
            "email.send",
            Tier::Low,
            base_ts(),
            vec![("recipient", json!("alice@a.com"))],
        ));
        ctx.push(make_record_with_entities(
            "email.send",
            Tier::Low,
            base_ts() + 1.0,
            vec![("recipient", json!("bob@b.com"))],
        ));
        ctx.push(make_record_with_entities(
            "email.send",
            Tier::Low,
            base_ts() + 2.0,
            vec![("recipient", json!("alice@a.com"))],
        ));

        let filter = SessionFilter::new().with_action_type("email.send");
        assert_eq!(ctx.distinct_count("recipient", &filter), 2);
    }

    #[test]
    fn count_where_with_entity_match() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record_with_entities(
            "email.send",
            Tier::Low,
            base_ts(),
            vec![("recipient_scope", json!("external"))],
        ));
        ctx.push(make_record_with_entities(
            "email.send",
            Tier::Low,
            base_ts() + 1.0,
            vec![("recipient_scope", json!("internal"))],
        ));
        ctx.push(make_record_with_entities(
            "email.send",
            Tier::Low,
            base_ts() + 2.0,
            vec![("recipient_scope", json!("external"))],
        ));

        let filter = SessionFilter::new()
            .with_action_type("email.send")
            .with_entity_match("recipient_scope", json!("external"));
        assert_eq!(ctx.count_where(&filter), 2);
    }

    // ── Temporal pattern tests ──────────────────────────────────

    #[test]
    fn duration_minutes() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record("a", Tier::Low, base_ts()));
        ctx.push(make_record("b", Tier::Low, base_ts() + 300.0)); // 5 min later
        assert!((ctx.duration_minutes() - 5.0).abs() < 0.01);
    }

    #[test]
    fn idle_then_burst_detected() {
        let mut ctx = SessionContext::new("test");
        // Action at t=0
        ctx.push(make_record("a", Tier::Low, base_ts()));
        // 10-minute idle gap
        // Then 3 actions within 1 minute
        ctx.push(make_record("a", Tier::Low, base_ts() + 600.0));
        ctx.push(make_record("a", Tier::Low, base_ts() + 610.0));
        ctx.push(make_record("a", Tier::Low, base_ts() + 620.0));

        assert!(ctx.idle_then_burst(5, 3, 1));
        assert!(!ctx.idle_then_burst(15, 3, 1)); // idle threshold too high
    }

    #[test]
    fn accelerating_detected() {
        let mut ctx = SessionContext::new("test");
        // Window 1 (0-30s): 1 action
        ctx.push(make_record("a", Tier::Low, base_ts()));
        // Window 2 (30-60s): 3 actions
        ctx.push(make_record("a", Tier::Low, base_ts() + 30.0));
        ctx.push(make_record("a", Tier::Low, base_ts() + 35.0));
        ctx.push(make_record("a", Tier::Low, base_ts() + 40.0));
        // Window 3 (60-90s): 9 actions
        for i in 0..9 {
            ctx.push(make_record("a", Tier::Low, base_ts() + 60.0 + i as f64));
        }

        assert!(ctx.accelerating("a", 3, 2.0));
    }

    // ── Set & sequence tests ────────────────────────────────────

    #[test]
    fn sequence_ordered() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record("files.read", Tier::Low, base_ts()));
        ctx.push(make_record("db.select", Tier::Low, base_ts() + 1.0));
        ctx.push(make_record("email.send", Tier::Low, base_ts() + 2.0));

        assert!(ctx.sequence(&["files.read", "email.send"], 5, true));
        assert!(!ctx.sequence(&["email.send", "files.read"], 5, true));
    }

    #[test]
    fn sequence_unordered() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record("email.send", Tier::Low, base_ts()));
        ctx.push(make_record("files.read", Tier::Low, base_ts() + 1.0));

        assert!(ctx.sequence(&["files.read", "email.send"], 5, false));
    }

    #[test]
    fn distinct_flags_count() {
        let mut ctx = SessionContext::new("test");
        ctx.push(make_record_with_flags(
            "a",
            Tier::Low,
            base_ts(),
            vec!["EXPOSURE", "MUTATION"],
        ));
        ctx.push(make_record_with_flags(
            "b",
            Tier::Low,
            base_ts() + 1.0,
            vec!["FINANCIAL", "MUTATION"],
        ));

        assert_eq!(ctx.distinct_flags(None), 3); // EXPOSURE, MUTATION, FINANCIAL
    }

    #[test]
    fn ratio_reads_to_writes() {
        let mut ctx = SessionContext::new("test");
        for i in 0..10 {
            ctx.push(make_record("files.read", Tier::Low, base_ts() + i as f64));
        }
        ctx.push(make_record("files.write", Tier::Low, base_ts() + 10.0));

        let reads = SessionFilter::new().with_action_type("files.read");
        let writes = SessionFilter::new().with_action_type("files.write");
        assert!((ctx.ratio(&reads, &writes) - 10.0).abs() < 0.01);
    }
}
