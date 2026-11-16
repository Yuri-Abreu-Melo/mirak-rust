use crate::nvd::structs::cpe_name_search::NVDReponseCPEName;
use std::time::Duration;

/// Hits the NVD api to get information about CPE and convert to JSON
pub async fn search_cves_by_cpe(cpe: &str, key: &str) -> NVDReponseCPEName {
    let client = reqwest::Client::builder().use_rustls_tls().build().unwrap();
    let page_size = 2_000;
    let mut start_index = 0;
    let mut combined = NVDReponseCPEName::default();

    loop {
        let mut retries = 0;
        let page_size_param = page_size.to_string();
        let start_index_param = start_index.to_string();
        let response = loop {
            tokio::time::sleep(Duration::from_millis(700)).await;
            let response = client
                .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
                .query(&[
                    ("cpeName", cpe),
                    ("resultsPerPage", page_size_param.as_str()),
                    ("startIndex", start_index_param.as_str()),
                ])
                .header("apiKey", key)
                .send()
                .await
                .expect("NVD CVE request failed");

            if matches!(
                response.status(),
                reqwest::StatusCode::TOO_MANY_REQUESTS
                    | reqwest::StatusCode::SERVICE_UNAVAILABLE
                    | reqwest::StatusCode::FORBIDDEN
            ) {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                if retries < 3 {
                    let delay = retry_after.unwrap_or(1_u64 << retries);
                    retries += 1;
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    continue;
                }
            }

            break response
                .error_for_status()
                .expect("NVD CVE request returned an error status");
        };
        let response = response
            .json::<NVDReponseCPEName>()
            .await
            .expect("NVD CVE response could not be parsed");
        let page_len = response.vulnerabilities.len();

        if start_index == 0 {
            combined = response;
        } else {
            combined.vulnerabilities.extend(response.vulnerabilities);
        }

        let received = combined.vulnerabilities.len() as i64;
        if received >= combined.total_results {
            break;
        }
        assert!(
            page_len > 0,
            "NVD pagination returned an empty page before completion"
        );
        start_index = received;
    }

    combined.results_per_page = combined.vulnerabilities.len() as i64;
    combined
}
