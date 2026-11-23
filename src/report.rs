use csv::Writer;
use std::env;
use std::path::PathBuf;

use crate::security_scan::SecurityFinding;

pub fn make_report(findings: &[SecurityFinding]) -> Result<Option<PathBuf>, String> {
    if findings.is_empty() {
        return Ok(None);
    }

    let home =
        env::home_dir().ok_or_else(|| "Could not determine the home directory.".to_string())?;
    let report_path = home.join("mirak_report.csv");
    let file = std::fs::File::create(&report_path)
        .map_err(|error| format!("Could not create {}: {error}", report_path.display()))?;
    let mut writer = Writer::from_writer(file);
    writer
        .write_record([
            "id",
            "source",
            "product",
            "version",
            "base_score",
            "severity",
            "status",
            "advisory_url",
            "evidence",
            "description",
        ])
        .map_err(|error| error.to_string())?;

    for finding in findings {
        writer
            .write_record([
                finding.id.as_str(),
                finding.source.as_str(),
                finding.product.as_str(),
                finding.version.as_str(),
                &finding.base_score.to_string(),
                finding.severity.as_str(),
                finding.status.as_str(),
                finding.advisory_url.as_str(),
                finding.evidence.as_str(),
                finding.description.as_str(),
            ])
            .map_err(|error| error.to_string())?;
    }
    writer
        .flush()
        .map_err(|error| format!("Could not write {}: {error}", report_path.display()))?;
    Ok(Some(report_path))
}
