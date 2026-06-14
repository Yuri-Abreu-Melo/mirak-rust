use std::time::Duration;

use crate::nvd::structs::cpe_name_search::NVDReponseCPEName;

/// Hits the NVD api to get information about CPE and convert to JSON
pub async fn search_cves_by_cpe(cpe: &str, key: &str) -> NVDReponseCPEName {
    let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
    client
        .get(format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
        ))
        .header("apiKey", key)
        // .header("apiKey", "7b1f836b-858b-4e19-bfb7-6dcd92266782")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or_default()
}

// Hits the NVD api to get information about CPE list of a CVE and convert to JSON
// pub async fn search_cpes_by_criteria_id(criteria_id: &str, key: &str) -> NVDResponseCriteriaID {
//     let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
//     client
//         .get(format!(
//             "https://services.nvd.nist.gov/rest/json/cpes/2.0?matchCriteriaId={criteria_id}"
//         ))
//         .header("apiKey", key)
//         // .header("apiKey", "7b1f836b-858b-4e19-bfb7-6dcd92266782")
//         .send()
//         .await
//         .unwrap()
//         .json()
//         .await
//         .unwrap_or_default()
// }

pub async fn _search_cves_by_cpe_without_key(cpe: &str) -> NVDReponseCPEName {
    let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    client
        .get(format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or_default()
}

// pub async fn search_cpes_by_criteria_id_without_key(criteria_id: &str) -> NVDResponseCriteriaID {
//     let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
//     tokio::time::sleep(Duration::from_millis(500)).await;
//     client
//         .get(format!(
//             "https://services.nvd.nist.gov/rest/json/cpes/2.0?matchCriteriaId={criteria_id}"
//         ))
//         .send()
//         .await
//         .unwrap()
//         .json()
//         .await
//         .unwrap_or_default()
// }
