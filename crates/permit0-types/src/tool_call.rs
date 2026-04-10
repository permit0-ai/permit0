#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// A raw tool call as received from an AI agent or MCP surface.
/// This is the unprocessed input to the normalizer pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawToolCall {
    /// Tool name as reported by the agent surface (e.g. "http", "bash", "gmail_send").
    pub tool_name: String,
    /// Raw parameters — opaque JSON, structure depends on the surface tool.
    pub parameters: serde_json::Value,
    /// Optional metadata about the calling context.
    #[serde(default)]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_serde() {
        let tc = RawToolCall {
            tool_name: "http".into(),
            parameters: serde_json::json!({
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 5000, "currency": "usd"}
            }),
            metadata: serde_json::Map::new(),
        };
        let json = serde_json::to_string(&tc).unwrap();
        let back: RawToolCall = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tool_name, "http");
    }
}
