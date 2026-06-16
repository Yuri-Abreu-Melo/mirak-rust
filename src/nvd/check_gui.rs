use colored::*;
use regex::Regex;
use std::collections::HashMap;

use crate::nvd;
#[cfg(feature = "gui")]
use crate::nvd::check::CVEDataReport;

#[cfg(feature = "gui")]
use tokio::sync::mpsc;

fn looks_like_nvd_api_key(input: &str) -> bool {
    let re = Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
    .unwrap();
    re.is_match(input.trim())
}

fn matches_cpe(cpe_pattern: &str, cpe_to_check: &str) -> bool {
    let pattern_parts: Vec<&str> = cpe_pattern.split(':').collect();
    let check_parts: Vec<&str> = cpe_to_check.split(':').collect();

    if pattern_parts.len() != check_parts.len() {
        return false;
    }

    for (p, c) in pattern_parts.iter().zip(check_parts.iter()) {
        if *p != "*" && *c != "*" && *p != *c {
            return false;
        }
    }
    true
}

#[cfg(feature = "gui")]
pub async fn check_vulnerabilities_gui(
    cpes: Vec<String>,
    os_cpe: String,
    key: &str,
    sender: mpsc::UnboundedSender<String>,
) -> (HashMap<String, Vec<CVEDataReport>>, HashMap<String, i64>) {
    let mut all_vulnerabilities: HashMap<String, Vec<CVEDataReport>> = HashMap::new();
    let mut issues: HashMap<String, i64> = HashMap::new();

    let total_cpes = cpes.len();
    sender
        .send(format!(
            "🔍 Check for vulnerabilities for {} CPEs...\n",
            total_cpes
        ))
        .ok();

    for (index, cpe) in cpes.iter().enumerate() {
        let (vuln_map, issue_source, issues_qtd) =
            check_vulnerabilities_for_cpe_gui(os_cpe.as_str(), cpe.as_str(), key, sender.clone())
                .await;

        for (cve_id, cve_data_list) in vuln_map {
            all_vulnerabilities
                .entry(cve_id)
                .or_default()
                .extend(cve_data_list);
        }

        sender
            .send(format!(
                "📦 Progress: {}/{} CPEs checked\n",
                index + 1,
                total_cpes
            ))
            .ok();
        issues.entry(issue_source).or_insert(issues_qtd);
    }

    sender
        .send("✅ Vulnerabilities scan finished!\n".to_string())
        .ok();
    (all_vulnerabilities, issues)
}

#[cfg(feature = "gui")]
pub async fn check_gui(
    cpes: Vec<String>,
    key: String,
    sender: mpsc::UnboundedSender<String>,
) -> HashMap<String, Vec<CVEDataReport>> {
    let mut all_vulnerabilities: HashMap<String, Vec<CVEDataReport>> = HashMap::new();
    let mut final_issues: HashMap<String, i64> = HashMap::new();

    sender
        .send("🔑 Validanting NVD API KEY...\n".to_string())
        .ok();

    if looks_like_nvd_api_key(key.as_str()) {
        sender.send("🔍  Reading cpes.mirak \n".to_string()).ok();
        let os_cpe = cpes.first().unwrap().to_owned();
        let (vulnerabilities, issues) =
            check_vulnerabilities_gui(cpes, os_cpe.to_string(), &key, sender.clone()).await;

        for (cve_id, cve_data_list) in vulnerabilities {
            all_vulnerabilities
                .entry(cve_id)
                .or_default()
                .extend(cve_data_list);
        }

        for (k, v) in issues {
            if !k.is_empty() {
                *final_issues.entry(k.to_string()).or_insert(0) += v;
            }
        }
    } else {
        sender.send("⚠️Invalid NVD API KEY!\n".to_string()).ok();
    }

    let total: i64 = final_issues.values().sum();
    sender
        .send(format!(
            "\n{} {}\n",
            "Total CVEs found: ".bright_green(),
            total
        ))
        .ok();

    for (source, qtd) in final_issues {
        sender
            .send(format!(
                "{} {} {}\n",
                "Total CVEs found for: ".bright_green(),
                source,
                qtd
            ))
            .ok();
    }

    all_vulnerabilities
}

#[cfg(feature = "gui")]
async fn check_vulnerabilities_for_cpe_gui(
    _os_cpe: &str,
    cpe: &str,
    key: &str,
    sender: mpsc::UnboundedSender<String>,
) -> (HashMap<String, Vec<CVEDataReport>>, String, i64) {
    sender
        .send(format!("🔎 Searching NVD for CPE: {}\n", cpe))
        .ok();

    // Get the informations about the given CPE
    let result = nvd::search::search_cves_by_cpe(cpe, key).await;

    let mut vulnerabilities: HashMap<String, Vec<CVEDataReport>> = HashMap::new();
    let mut issue_source = String::from("");
    let mut issues_qtd = 0;

    let cpe_parts: Vec<&str> = cpe.split(':').collect();
    let vendor = cpe_parts.get(3).unwrap_or(&"unknown").to_string();
    let product_name = cpe_parts.get(4).unwrap_or(&"unknown").to_string();
    let version = cpe_parts.get(5).unwrap_or(&"unknown").to_string();

    if !result.vulnerabilities.is_empty() {
        issue_source.push_str(cpe_parts.get(4).unwrap_or(&"").to_owned());
        issues_qtd = result.total_results;

        sender
            .send(format!(
                "🐛 Found {} vulnerabilities for {}\n",
                result.total_results, product_name
            ))
            .ok();

        for cves in result.vulnerabilities.iter() {
            let mut cve_found = false;

            for config in &cves.cve.configurations {
                for node in &config.nodes {
                    if node.operator.eq("OR") {
                        if node
                            .cpe_match
                            .iter()
                            .any(|item| matches_cpe(cpe, item.criteria.as_str()))
                        {
                            let base_score = cves
                                .cve
                                .metrics
                                .cvss_metric_v31
                                .first()
                                .map(|m| m.cvss_data.base_score)
                                .unwrap_or(0.0);

                            let base_severity = cves
                                .cve
                                .metrics
                                .cvss_metric_v31
                                .first()
                                .map(|m| m.cvss_data.base_severity.clone())
                                .unwrap_or_else(|| "UNKNOWN".to_string());

                            let cve_data = CVEDataReport {
                                product: product_name.clone(),
                                vendor: vendor.clone(),
                                version: version.clone(),
                                base_score,
                                base_severity,
                                cve_id: cves.cve.id.clone(),
                                description: cves
                                    .cve
                                    .descriptions
                                    .first()
                                    .map(|d| d.value.clone())
                                    .unwrap_or_default(),
                            };

                            vulnerabilities
                                .entry(cves.cve.id.clone())
                                .or_default()
                                .push(cve_data);

                            cve_found = true;
                            break;
                        }
                    } else {
                        let mut related = true;
                        if node
                            .cpe_match
                            .iter()
                            .any(|item| matches_cpe(cpe, item.criteria.as_str()))
                        {
                            related = false;
                        }
                        if related {
                            let base_score = cves
                                .cve
                                .metrics
                                .cvss_metric_v31
                                .first()
                                .map(|m| m.cvss_data.base_score)
                                .unwrap_or(0.0);

                            let base_severity = cves
                                .cve
                                .metrics
                                .cvss_metric_v31
                                .first()
                                .map(|m| m.cvss_data.base_severity.clone())
                                .unwrap_or_else(|| "UNKNOWN".to_string());

                            let cve_data = CVEDataReport {
                                product: product_name.clone(),
                                vendor: vendor.clone(),
                                version: version.clone(),
                                base_score,
                                base_severity,
                                cve_id: cves.cve.id.clone(),
                                description: cves
                                    .cve
                                    .descriptions
                                    .first()
                                    .map(|d| d.value.clone())
                                    .unwrap_or_default(),
                            };

                            vulnerabilities
                                .entry(cves.cve.id.clone())
                                .or_default()
                                .push(cve_data);

                            cve_found = true;
                        }
                    }

                    if cve_found {
                        break;
                    }
                }
                if cve_found {
                    break;
                }
            }
        }

        sender
            .send(format!(
                "✅ Processed {} CVEs for {}\n",
                vulnerabilities.len(),
                product_name
            ))
            .ok();
    } else {
        sender
            .send(format!(
                "ℹ️ Zero vulnerabilities found for {}\n",
                product_name
            ))
            .ok();
    }

    (vulnerabilities, issue_source, issues_qtd)
}
