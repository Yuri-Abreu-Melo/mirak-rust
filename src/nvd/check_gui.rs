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
            "{}",
            format!("🔍 Check for vulnerabilities for {} CPEs...\n", total_cpes)
                .bright_blue()
                .bold()
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
                "{}",
                format!("📦 Progress: {}/{} CPEs checked\n", index + 1, total_cpes).bright_cyan()
            ))
            .ok();
        issues.entry(issue_source).or_insert(issues_qtd);
    }

    sender
        .send(format!(
            "{}\n",
            "✅ Vulnerabilities scan finished!".bright_green().bold()
        ))
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
        .send(format!(
            "{}\n",
            "🔑 Validating NVD API KEY...".bright_yellow().bold()
        ))
        .ok();

    if looks_like_nvd_api_key(key.as_str()) {
        sender
            .send(format!(
                "{}\n",
                "✅ NVD API KEY validated successfully!".bright_green()
            ))
            .ok();
        sender
            .send(format!("{}\n", "📖 Reading cpes.mirak...".bright_cyan()))
            .ok();

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
        sender
            .send(format!(
                "{}\n",
                "❌ Invalid NVD API KEY! Please check your key and try again."
                    .bright_red()
                    .bold()
            ))
            .ok();
        return all_vulnerabilities;
    }

    let total: i64 = final_issues.values().sum();

    // Envia o resumo formatado
    sender
        .send(format!(
            "\n{}\n",
            "═══════════════════════════════════════════".bright_magenta()
        ))
        .ok();
    sender
        .send(format!(
            "{} {}\n",
            "📊 SCAN SUMMARY".bright_magenta().bold(),
            "📊".bright_magenta()
        ))
        .ok();
    sender
        .send(format!(
            "{}\n",
            "═══════════════════════════════════════════".bright_magenta()
        ))
        .ok();

    sender
        .send(format!(
            "{} {}\n",
            "🔍 Total CVEs found:".bright_green().bold(),
            total.to_string().bright_yellow().bold()
        ))
        .ok();

    for (source, qtd) in final_issues {
        sender
            .send(format!(
                "{} {} {}\n",
                "📦".bright_cyan(),
                format!("{}:", source).bright_white(),
                qtd.to_string().bright_yellow()
            ))
            .ok();
    }

    sender
        .send(format!(
            "{}\n",
            "═══════════════════════════════════════════".bright_magenta()
        ))
        .ok();

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
        .send(format!(
            "{}\n",
            format!("🔎 Searching NVD for CPE: {}", cpe).bright_blue()
        ))
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
                "{} {} {}\n",
                "🐛 Found".bright_red(),
                result.total_results.to_string().bright_yellow().bold(),
                format!("vulnerabilities for {}", product_name).bright_white()
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
                "{} {} {}\n",
                "✅ Processed".bright_green(),
                vulnerabilities.len().to_string().bright_yellow().bold(),
                format!("CVEs for {}", product_name).bright_white()
            ))
            .ok();
    } else {
        sender
            .send(format!(
                "{} {}\n",
                "ℹ️".bright_cyan(),
                format!("Zero vulnerabilities found for {}", product_name).bright_white()
            ))
            .ok();
    }

    (vulnerabilities, issue_source, issues_qtd)
}
