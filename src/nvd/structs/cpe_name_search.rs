use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NVDReponseCPEName {
    pub results_per_page: i64,
    pub start_index: i64,
    pub total_results: i64,
    pub format: String,
    pub version: String,
    pub timestamp: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub cve: Cve,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,
    pub source_identifier: String,
    pub published: String,
    pub last_modified: String,
    pub vuln_status: String,
    pub cve_tags: Vec<Value>,
    pub descriptions: Vec<Description>,
    pub metrics: Metrics,
    pub weaknesses: Vec<Weakness>,
    pub configurations: Vec<Configuration>,
    pub references: Vec<Reference>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub cvss_metric_v31: Vec<CvssMetricV31>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV31 {
    pub source: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub cvss_data: CvssData,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Weakness {
    pub source: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub description: Vec<Description2>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description2 {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub nodes: Vec<Node>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub operator: String,
    pub negate: bool,
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    pub version_end_excluding: Option<String>,
    pub match_criteria_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub url: String,
    pub source: String,
    pub tags: Option<Vec<String>>,
}
