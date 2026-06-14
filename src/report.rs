use colored::*;
use csv::Writer;
use std::{collections::HashMap, env};

use crate::nvd::check::CVEDataReport;

pub fn make_report(vulnerabilities: HashMap<String, Vec<CVEDataReport>>) {
    if vulnerabilities.is_empty() {
        println!(
            "{}", "[INFO] - Since no vulnerability was found in the installed apps no report will be generated".bright_green()
        );
    } else {
        println!(
            "{}",
            "[INFO] - Report of vulnerabilities generated".bright_green()
        );

        let mut wtr = Writer::from_path(env::home_dir().unwrap().join("mirak_report.csv")).unwrap();

        wtr.write_record([
            "cve_id",
            "product",
            "vendor",
            "version",
            "basescore",
            "baseseverity",
            "description",
        ])
        .unwrap();

        for (cve_id, cve_data_list) in &vulnerabilities {
            for cve_data in cve_data_list {
                wtr.write_record([
                    cve_id,
                    &cve_data.product,
                    &cve_data.vendor,
                    &cve_data.version,
                    &cve_data.base_score.to_string(),
                    &cve_data.base_severity,
                    &cve_data.description,
                ])
                .unwrap();
            }
        }

        wtr.flush().unwrap();
    }
}
