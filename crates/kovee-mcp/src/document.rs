//! The embedded C3a tools document — the contract. The bundle
//! (`mcp/kovee-mcp.tools.json`, D-RT-1-ratified) is embedded at build
//! time and parsed once at startup: tool names, ops, gating flags, and
//! input schemas all come from it, nothing is hand-copied. A document
//! this loader (or the schema interpreter) cannot fully enforce makes
//! the server refuse to start rather than serve a weaker contract.

use serde_json::Value;

use crate::validate;

/// The tools document, embedded verbatim at build time.
pub const DOCUMENT_JSON: &str = include_str!("../../../mcp/kovee-mcp.tools.json");

/// One tool row of the participant profile.
pub struct Tool {
    /// The MCP tool name (`kovee_<registry-op>`).
    pub name: String,
    /// The K0-frozen registry operation the tool dispatches to.
    pub op: String,
    /// `access: "gated"` (mutations plus the credential read) vs
    /// `access: "safe_to_allow"` (plain reads).
    pub gated: bool,
    /// The document description, verbatim — it carries the read-only vs
    /// gated marking the harness shows the operator.
    pub description: String,
    /// The closed input schema (op request args minus channel-derived
    /// fields), verbatim.
    pub input_schema: Value,
}

/// The parsed participant profile: the exact tool list, in document
/// order, plus the pinned KCP protocol version.
pub struct Document {
    pub protocol_version: String,
    pub tools: Vec<Tool>,
}

impl Document {
    /// Looks a tool up by name; absence means the tool does not exist
    /// (deny-by-absence).
    pub fn tool(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|tool| tool.name == name)
    }
}

/// Parses and cross-checks the embedded document.
pub fn load() -> Result<Document, String> {
    let root: Value =
        serde_json::from_str(DOCUMENT_JSON).map_err(|e| format!("tools document: {e}"))?;
    if root.get("document").and_then(Value::as_str) != Some("kovee-mcp.tools") {
        return Err("embedded file is not the kovee-mcp.tools document".to_owned());
    }
    let protocol_version = root
        .get("kcp_protocol_version")
        .and_then(Value::as_str)
        .ok_or("kcp_protocol_version missing")?
        .to_owned();
    if protocol_version != kovee_core::PROTOCOL_VERSION {
        return Err(format!(
            "document pins KCP {protocol_version} but this build speaks {}",
            kovee_core::PROTOCOL_VERSION
        ));
    }
    let profiles = root
        .get("profiles")
        .and_then(Value::as_object)
        .ok_or("profiles missing")?;
    if profiles.len() != 1 || !profiles.contains_key("participant") {
        return Err("expected exactly the participant profile".to_owned());
    }
    let rows = profiles
        .get("participant")
        .and_then(|p| p.get("tools"))
        .and_then(Value::as_array)
        .ok_or("participant.tools missing")?;
    let mut tools: Vec<Tool> = Vec::with_capacity(rows.len());
    for row in rows {
        let tool = parse_tool(row)?;
        if tools.iter().any(|t| t.name == tool.name) {
            return Err(format!("duplicate tool {}", tool.name));
        }
        tools.push(tool);
    }
    if tools.is_empty() {
        return Err("the participant profile lists no tools".to_owned());
    }
    Ok(Document {
        protocol_version,
        tools,
    })
}

fn parse_tool(row: &Value) -> Result<Tool, String> {
    let name = member_str(row, "name")?;
    let op = member_str(row, "op")?;
    let description = member_str(row, "description")?;
    let gated = match member_str(row, "access")?.as_str() {
        "gated" => true,
        "safe_to_allow" => false,
        other => return Err(format!("tool {name}: unknown access {other:?}")),
    };
    if name != format!("kovee_{op}") {
        return Err(format!("tool {name}: name does not derive from op {op:?}"));
    }
    // The op must be a registry operation the daemon dispatches:
    // read/mutation and envelope placement come from kovee-core's
    // registry-derived table, never from assumptions in this crate.
    if kovee_core::ops::op_spec(&op).is_none() {
        return Err(format!(
            "tool {name}: op {op:?} is not a K1 registry operation"
        ));
    }
    let input_schema = row
        .get("input_schema")
        .cloned()
        .ok_or_else(|| format!("tool {name}: input_schema missing"))?;
    validate::check_supported(&input_schema).map_err(|e| format!("tool {name}: {e}"))?;
    Ok(Tool {
        name,
        op,
        gated,
        description,
        input_schema,
    })
}

fn member_str(row: &Value, key: &str) -> Result<String, String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("tool row: {key} missing or not a string"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_document_loads_with_exactly_14_tools() {
        let doc = load().unwrap();
        assert_eq!(doc.protocol_version, "0.1");
        assert_eq!(doc.tools.len(), 14);
        // Gating marking lives in the document descriptions; the parsed
        // flag must agree with the text the harness will show.
        for tool in &doc.tools {
            assert_eq!(
                tool.gated,
                tool.description.contains("gated"),
                "{} marking drifted from its description",
                tool.name
            );
        }
        // The one recorded exception: a non-mutating read that stays
        // gated because its result carries a live credential (KG29).
        let credential = doc.tool("kovee_artifact_upload_credential").unwrap();
        assert!(credential.gated);
        assert_eq!(
            kovee_core::ops::op_spec(&credential.op).unwrap().kind,
            kovee_core::ops::OpKind::Read
        );
    }

    #[test]
    fn absent_tools_stay_absent() {
        let doc = load().unwrap();
        // Real daemon ops outside the C3a surface must not appear.
        for op in [
            "realm_show",
            "project_create",
            "space_create",
            "contribution_redact",
        ] {
            assert!(doc.tool(&format!("kovee_{op}")).is_none(), "{op}");
        }
    }
}
