use colored::*;
use regex::Regex;
use std::collections::HashMap;

use crate::nvd;
use crate::nvd::structs::cpe_name_search::{CpeMatch, Configuration, Node};
use version_compare::{Cmp, compare};

fn looks_like_nvd_api_key(input: &str) -> bool {
    let re = Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
    .unwrap();
    re.is_match(input.trim())
}

fn compare_versions(actual: &str, boundary: &str, accepts_equal: bool) -> bool {
    match compare(actual, boundary) {
        Ok(Cmp::Gt) => true,
        Ok(Cmp::Eq) => accepts_equal,
        _ => false,
    }
}

fn matches_cpe_match(cpe_to_check: &str, cpe_match: &CpeMatch) -> bool {
    let pattern_parts: Vec<&str> = cpe_match.criteria.split(':').collect();
    let check_parts: Vec<&str> = cpe_to_check.split(':').collect();

    if pattern_parts.len() != 13 || check_parts.len() != 13 {
        return false;
    }

    for (index, (pattern, actual)) in pattern_parts.iter().zip(check_parts.iter()).enumerate() {
        if index == 5 {
            continue;
        }
        if *pattern != "*" && *pattern != *actual {
            return false;
        }
    }

    let actual_version = check_parts[5];
    let pattern_version = pattern_parts[5];
    if pattern_version != "*" && pattern_version != actual_version {
        return false;
    }

    if let Some(start) = &cpe_match.version_start_including
        && !compare_versions(actual_version, start, true)
    {
        return false;
    }
    if let Some(start) = &cpe_match.version_start_excluding
        && !compare_versions(actual_version, start, false)
    {
        return false;
    }
    if let Some(end) = &cpe_match.version_end_including
        && !matches!(compare(actual_version, end), Ok(Cmp::Lt | Cmp::Eq))
    {
        return false;
    }
    if let Some(end) = &cpe_match.version_end_excluding
        && !compare_versions(end, actual_version, false)
    {
        return false;
    }

    true
}

fn evaluate_match_list(
    operator: &str,
    negate: bool,
    cpe_matches: &[CpeMatch],
    children: &[Node],
    inventory: &[String],
) -> bool {
    let mut results: Vec<bool> = cpe_matches
        .iter()
        .map(|criteria| {
            inventory
                .iter()
                .any(|cpe| matches_cpe_match(cpe, criteria))
        })
        .collect();
    results.extend(
        children
            .iter()
            .map(|child| evaluate_node(child, inventory)),
    );

    let matched = if operator.eq_ignore_ascii_case("AND") {
        !results.is_empty() && results.iter().all(|result| *result)
    } else {
        results.iter().any(|result| *result)
    };

    matched ^ negate
}

fn evaluate_node(node: &Node, inventory: &[String]) -> bool {
    evaluate_match_list(
        node.operator.as_str(),
        node.negate,
        &node.cpe_match,
        &node.children,
        inventory,
    )
}

fn evaluate_node_for_target(
    node: &Node,
    inventory: &[String],
    target_cpe: &str,
) -> (bool, bool) {
    let leaves: Vec<(bool, bool)> = node
        .cpe_match
        .iter()
        .map(|item| {
            let matched = inventory
                .iter()
                .any(|cpe| matches_cpe_match(cpe, item));
            let target_match = matched && item.vulnerable && matches_cpe_match(target_cpe, item);
            (matched, target_match)
        })
        .collect();
    let results: Vec<(bool, bool)> = leaves
        .into_iter()
        .chain(
            node.children
                .iter()
                .map(|child| evaluate_node_for_target(child, inventory, target_cpe)),
        )
        .collect();
    combine_results(
        node.operator.as_str(),
        node.negate,
        results.as_slice(),
    )
}

fn combine_results(operator: &str, negate: bool, results: &[(bool, bool)]) -> (bool, bool) {
    let matched = if operator.eq_ignore_ascii_case("AND") {
        !results.is_empty() && results.iter().all(|(matched, _)| *matched)
    } else {
        results.iter().any(|(matched, _)| *matched)
    };
    if negate {
        (!matched, false)
    } else {
        let target_matched = matched
            && results
                .iter()
                .any(|(matched, target_match)| *matched && *target_match);
        (matched, target_matched)
    }
}

pub fn should_report_vulnerability(
    cpe: &str,
    inventory: &[String],
    configuration: &Configuration,
) -> bool {
    let results: Vec<(bool, bool)> = configuration
        .nodes
        .iter()
        .map(|node| evaluate_node_for_target(node, inventory, cpe))
        .collect();
    let (matched, target_match) = combine_results(
        configuration.operator.as_str(),
        configuration.negate,
        results.as_slice(),
    );
    matched && target_match
}

pub fn should_report_vulnerability_for_node(node_operator: &str, cpe: &str, node: &Node) -> bool {
    evaluate_match_list(
        node_operator,
        node.negate,
        &node.cpe_match,
        &node.children,
        &[cpe.to_string()],
    )
}

/// This function receives an array with all installed apps and iterate through it searching for
/// CVEs base on the given CPE
pub async fn check_vulnerabilities(
    cpes: Vec<String>,
    os_cpe: String,
    key: &str,
) -> Result<(HashMap<String, Vec<CVEDataReport>>, HashMap<String, i64>), String> {
    let mut all_vulnerabilities: HashMap<String, Vec<CVEDataReport>> = HashMap::new();
    let mut issues: HashMap<String, i64> = HashMap::new();
    let total_cpes = cpes.len();

    println!(
        "{}",
        "[INFO] Starting NVD CPE lookups...".bright_blue().bold()
    );
    println!(
        "{} {} {}",
        "[INFO] CPEs queued for NVD lookup:".bright_cyan(),
        total_cpes.to_string().bright_yellow().bold(),
        "\n".to_string()
    );

    for (index, cpe) in cpes.iter().enumerate() {
        let (vuln_map, issue_source, issues_qtd) =
            check_vulnerabilities_for_cpe(os_cpe.as_str(), cpe.as_str(), key, &cpes).await?;

        // Mescla as vulnerabilidades encontradas
        for (cve_id, cve_data_list) in vuln_map {
            let existing_reports = all_vulnerabilities.entry(cve_id).or_default();
            for cve_data in cve_data_list {
                if !existing_reports.contains(&cve_data) {
                    existing_reports.push(cve_data);
                }
            }
        }

        // Show simple progress
        let progress = format!("[{:>3}/{}]", index + 1, total_cpes);
        print!(
            "\r{} {} ",
            progress.bright_cyan().bold(),
            "[INFO] Processing...".bright_blue()
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        issues.entry(issue_source).or_insert(issues_qtd);
    }

    println!(); // New line after progress

    println!(
        "\n{}",
        "[INFO] NVD CPE lookups completed; applicable matches are summarized below."
            .bright_blue()
    );
    Ok((all_vulnerabilities, issues))
}

// This function receives an array with all installed broke in small pieces and then fire the check
// for vulnerabilities with threads
pub async fn check(
    cpes: Vec<String>,
    key: String,
) -> Result<HashMap<String, Vec<CVEDataReport>>, String> {
    let mut all_vulnerabilities: HashMap<String, Vec<CVEDataReport>> = HashMap::new();
    let mut final_issues: HashMap<String, i64> = HashMap::new();

    println!(
        "{}",
        "[INFO] Checking NVD API key format...".bright_yellow().bold()
    );

    if looks_like_nvd_api_key(key.as_str()) && !cpes.is_empty() {
        println!(
            "{}",
            "[INFO] UUID format accepted; the NVD service will validate the key during the request."
                .bright_blue()
        );
        println!("{}", "[INFO] Reading cpes.mirak...".bright_cyan());
        let os_cpe = cpes.first().cloned().unwrap_or_default();
        let (vulnerabilities, issues) = check_vulnerabilities(cpes, os_cpe, &key).await?;

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
        println!(
            "{}",
            "[ERROR] Invalid NVD API KEY! Please check your key and try again."
                .bright_red()
                .bold()
        );
        return Err("Invalid NVD API key or empty validator CPE inventory.".to_string());
    }

    let total = all_vulnerabilities.len();

    println!(
        "\n{}",
        "═══════════════════════════════════════════".bright_magenta()
    );
    println!(
        "{}",
        "[INFO] SCAN SUMMARY".bright_magenta().bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════".bright_magenta()
    );

    println!(
        "{} {}",
        "[INFO] Applicable CVE matches after version/configuration filtering:"
            .bright_green()
            .bold(),
        total.to_string().bright_yellow().bold()
    );

    for (source, qtd) in final_issues {
        println!(
            "{} {} {}",
            "[INFO]".bright_cyan(),
            format!("{} candidate records before filtering:", source).bright_white(),
            qtd.to_string().bright_yellow()
        );
    }
    println!(
        "{}",
        "═══════════════════════════════════════════".bright_magenta()
    );

    Ok(all_vulnerabilities)
}

/// The function that inspect the returning of NVD api
async fn check_vulnerabilities_for_cpe(
    _os_cpe: &str,
    cpe: &str,
    key: &str,
    inventory: &[String],
) -> Result<(HashMap<String, Vec<CVEDataReport>>, String, i64), String> {
    // Get the informations about the given CPE
    let result = nvd::search::search_cves_by_cpe(cpe, key).await?;

    let mut vulnerabilities: HashMap<String, Vec<CVEDataReport>> = HashMap::new();
    let mut issue_source = String::from("");
    let mut issues_qtd = 0;

    // Extract vendor and product from the CPE
    let cpe_parts: Vec<&str> = cpe.split(':').collect();
    let vendor = cpe_parts.get(3).unwrap_or(&"unknown").to_string();
    let product_name = normalize_report_product(
        vendor.as_str(),
        cpe_parts.get(4).unwrap_or(&"unknown"),
    );
    let version = cpe_parts.get(5).unwrap_or(&"unknown").to_string();

    // More compact log to avoid clutter
    // println!("{}", format!("[INFO] Searching NVD for CPE: {}", cpe).bright_blue());

    if !result.vulnerabilities.is_empty() {
        issue_source.push_str(product_name.as_str());
        issues_qtd = result.total_results;

        // Show only if vulnerabilities are found
        println!(
            "\n  {} {} {}",
            "[INFO] NVD candidate records:".bright_cyan(),
            result.total_results.to_string().bright_yellow().bold(),
            format!("for {}", product_name).bright_white()
        );

        for cves in result.vulnerabilities.iter() {
            if cves.cve.vuln_status.eq_ignore_ascii_case("rejected") {
                continue;
            }
            let mut cve_found = false;

            for config in &cves.cve.configurations {
                if should_report_vulnerability(cpe, inventory, config) {
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
                if cve_found {
                    break;
                }
            }
        }

        println!(
            "  {} {} {}\n",
            "[INFO] Applicable configuration/version matches:".bright_blue(),
            vulnerabilities.len().to_string().bright_yellow().bold(),
            format!("for {}", product_name).bright_white()
        );
    }

    Ok((vulnerabilities, issue_source, issues_qtd))
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct CVEDataReport {
    pub product: String,
    pub vendor: String,
    pub version: String,
    pub base_score: f64,
    pub base_severity: String,
    pub cve_id: String,
    pub description: String,
}

fn normalize_report_product(vendor: &str, product: &str) -> String {
    if vendor == "nicmx" && matches!(product, "fort-validator" | "fort_validator") {
        "fort".to_string()
    } else {
        product.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvd::structs::cpe_name_search::{CpeMatch, Node};

    fn cpe_match(
        criteria: &str,
        vulnerable: bool,
        start_including: Option<&str>,
        start_excluding: Option<&str>,
        end_including: Option<&str>,
        end_excluding: Option<&str>,
    ) -> CpeMatch {
        CpeMatch {
            vulnerable,
            criteria: criteria.to_string(),
            version_start_including: start_including.map(str::to_string),
            version_start_excluding: start_excluding.map(str::to_string),
            version_end_including: end_including.map(str::to_string),
            version_end_excluding: end_excluding.map(str::to_string),
            match_criteria_id: "match-id".to_string(),
        }
    }

    fn node(operator: &str, negate: bool, cpe_match: Vec<CpeMatch>) -> Node {
        Node {
            operator: operator.to_string(),
            negate,
            cpe_match,
            children: Vec::new(),
        }
    }

    #[test]
    fn version_ranges_respect_inclusive_and_exclusive_bounds() {
        let cpe = "cpe:2.3:a:nicmx:fort-validator:1.6.2:*:*:*:*:*:*:*";
        let range = cpe_match(
            "cpe:2.3:a:nicmx:fort-validator:*:*:*:*:*:*:*:*",
            true,
            Some("1.6.0"),
            None,
            None,
            Some("1.6.3"),
        );

        assert!(matches_cpe_match(cpe, &range));
        assert!(!matches_cpe_match(
            "cpe:2.3:a:nicmx:fort-validator:1.6.3:*:*:*:*:*:*:*",
            &range
        ));
        assert!(!matches_cpe_match(
            "cpe:2.3:a:nicmx:fort-validator:1.5.9:*:*:*:*:*:*:*",
            &range
        ));

        let inclusive_end = cpe_match(
            "cpe:2.3:a:nicmx:fort-validator:*:*:*:*:*:*:*:*",
            true,
            None,
            None,
            Some("1.6.2"),
            None,
        );
        assert!(matches_cpe_match(cpe, &inclusive_end));

        let exclusive_start = cpe_match(
            "cpe:2.3:a:nicmx:fort-validator:*:*:*:*:*:*:*:*",
            true,
            None,
            Some("1.6.1"),
            None,
            None,
        );
        assert!(matches_cpe_match(cpe, &exclusive_start));
        assert!(!matches_cpe_match(
            "cpe:2.3:a:nicmx:fort-validator:1.6.1:*:*:*:*:*:*:*",
            &exclusive_start
        ));
    }

    #[test]
    fn fort_product_aliases_share_one_report_name() {
        assert_eq!(
            normalize_report_product("nicmx", "fort-validator"),
            "fort"
        );
        assert_eq!(
            normalize_report_product("nicmx", "fort_validator"),
            "fort"
        );
        assert_eq!(
            normalize_report_product("other", "fort_validator"),
            "fort_validator"
        );
    }

    #[test]
    fn and_nodes_require_all_installed_components_and_target_match() {
        let target = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*";
        let config = Configuration {
            operator: "OR".to_string(),
            negate: false,
            nodes: vec![node(
                "AND",
                false,
                vec![
                    cpe_match(
                        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                        true,
                        None,
                        None,
                        None,
                        Some("2.0"),
                    ),
                    cpe_match(
                        "cpe:2.3:o:vendor:os:1:*:*:*:*:*:*:*",
                        false,
                        None,
                        None,
                        None,
                        None,
                    ),
                ],
            )],
        };

        assert!(should_report_vulnerability(
            target,
            &[
                target.to_string(),
                "cpe:2.3:o:vendor:os:1:*:*:*:*:*:*:*".to_string(),
            ],
            &config
        ));
        assert!(!should_report_vulnerability(
            target,
            &[target.to_string()],
            &config
        ));
    }

    #[test]
    fn negated_nodes_and_nested_boolean_nodes_are_evaluated() {
        let target = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*";
        let config = Configuration {
            operator: "OR".to_string(),
            negate: false,
            nodes: vec![Node {
                operator: "AND".to_string(),
                negate: false,
                cpe_match: vec![cpe_match(
                    "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    true,
                    None,
                    None,
                    None,
                    None,
                )],
                children: vec![node(
                    "OR",
                    true,
                    vec![cpe_match(
                        "cpe:2.3:o:vendor:excluded_os:1:*:*:*:*:*:*:*",
                        false,
                        None,
                        None,
                        None,
                        None,
                    )],
                )],
            }],
        };

        assert!(should_report_vulnerability(
            target,
            &[target.to_string()],
            &config
        ));
        assert!(!should_report_vulnerability(
            target,
            &[
                target.to_string(),
                "cpe:2.3:o:vendor:excluded_os:1:*:*:*:*:*:*:*".to_string(),
            ],
            &config
        ));
    }

    #[test]
    fn nvd_configuration_deserializes_version_bounds_and_children() {
        let configuration: Configuration = serde_json::from_str(
            r#"{
                "operator": "AND",
                "negate": false,
                "nodes": [{
                    "operator": "OR",
                    "negate": false,
                    "cpeMatch": [{
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:nicmx:fort-validator:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "1.0",
                        "versionEndExcluding": "1.6.3",
                        "matchCriteriaId": "id"
                    }],
                    "children": []
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            configuration.nodes[0].cpe_match[0]
                .version_start_including
                .as_deref(),
            Some("1.0")
        );
        assert_eq!(
            configuration.nodes[0].cpe_match[0]
                .version_end_excluding
                .as_deref(),
            Some("1.6.3")
        );
    }
}
