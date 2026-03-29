use serde::{Deserialize, Serialize};

pub mod poc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VulnContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_positions: Option<Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poc {
    #[serde(rename = "type")]
    pub r#type: String,
    pub payload: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "file")]
    pub path: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    #[serde(default)]
    pub rank: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub location: Location,
    pub snippet: Option<String>,
    #[serde(default)]
    pub conditional: bool,
    #[serde(default)]
    pub guarded: bool,
    #[serde(default)]
    pub tainted: bool,
    #[serde(default)]
    pub implicit_risk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln_context: Option<VulnContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc: Option<Poc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_chain: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    JavaScript,
    C,
    Cpp,
}
