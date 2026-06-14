use serde::Deserialize;
use serde::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct NVDResponseCriteriaID {
    pub results_per_page: i64,
    pub start_index: i64,
    pub total_results: i64,
    pub format: String,
    pub version: String,
    pub timestamp: String,
    pub products: Vec<Product>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Product {
    pub cpe: Cpe,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cpe {
    pub deprecated: bool,
    pub cpe_name: String,
    pub cpe_name_id: String,
    pub last_modified: String,
    pub created: String,
    pub titles: Vec<Title>,
    pub refs: Vec<Ref>,
    #[serde(default)]
    pub deprecated_by: Vec<DeprecatedBy>,
    #[serde(default)]
    pub deprecates: Vec<Deprecate>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Title {
    pub title: String,
    pub lang: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ref {
    #[serde(rename = "ref")]
    pub ref_field: String,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeprecatedBy {
    pub cpe_name: String,
    pub cpe_name_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deprecate {
    pub cpe_name: String,
    pub cpe_name_id: String,
}
