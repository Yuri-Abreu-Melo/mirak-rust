use std::{fs, path::PathBuf};

use clap::Parser;
use colored::*;

mod cpe;
mod extractors;
mod nvd;
mod report;
mod routinator;
mod security_scan;

#[cfg(feature = "gui")]
mod gui;

#[derive(Parser)]
#[command(
    name = "MIRAK",
    version = "0.1.0",
    about = "Scans Routinator and Fort for known vulnerabilities",
    long_about = "Checks official Routinator and Fort security advisories, Rust dependency \
vulnerabilities, and optionally cross-checks NVD."
)]
struct Cli {
    /// Optional file containing the NVD API key
    #[arg(short = 'f', long, value_name = "FILE_PATH")]
    key_file: Option<PathBuf>,

    /// Collect local validator and dependency inventory without online checks
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["validate_from", "key_file"]
    )]
    extract_only: Option<PathBuf>,

    /// Validate an inventory snapshot created with --extract-only
    #[arg(long, value_name = "FILE", conflicts_with = "extract_only")]
    validate_from: Option<PathBuf>,

    #[cfg(feature = "gui")]
    /// Specify if it will run with the gui
    #[arg(short, long, conflicts_with_all = ["extract_only", "validate_from"])]
    gui: bool,
}

fn parse_args(cli: &Cli) -> Result<Option<String>, String> {
    if let Some(key_path) = &cli.key_file {
        #[cfg(target_os = "linux")]
        validate_key_file_permissions(key_path)?;

        let content = fs::read_to_string(key_path).map_err(|error| {
            format!(
                "Could not read NVD key file '{}': {error}",
                key_path.display()
            )
        })?;
        return Ok(Some(content.trim().to_string()));
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn validate_key_file_permissions(path: &PathBuf) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "Could not verify permissions for NVD key file '{}': {error}",
            path.display()
        )
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o400 == 0 || mode & 0o077 != 0 {
        return Err(format!(
            "NVD key file '{}' has permissions {:04o}; it must be readable by the owner only (for example, chmod 600).",
            path.display(),
            mode
        ));
    }
    Ok(())
}

async fn validate(cli: &Cli) -> Result<(), String> {
    if let Some(path) = &cli.extract_only {
        let (installation_count, warnings) = security_scan::export_snapshot(path)?;
        for warning in warnings {
            eprintln!("{} {}", "[WARN]".bright_yellow().bold(), warning);
        }
        println!(
            "[INFO] Extracted {installation_count} validator installation(s) to {}.",
            path.display()
        );
        println!("[INFO] No advisory, OSV, or NVD queries were performed in extraction mode.");
        return Ok(());
    }

    let nvd_key = parse_args(cli)?;

    println!(
        "\n{}",
        "═══════════════════════════════════════════".bright_magenta()
    );
    println!("{}", "🚀 MIRAK SECURITY SCANNER".bright_magenta().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════".bright_magenta()
    );

    // Inspect ports there are listening
    // let ports_result = extractors::network::list_open_ports();

    println!(
        "{}",
        "[INFO] Running CVE triage for Routinator, Fort, and identifiable dependencies...\n"
            .bright_blue()
            .bold()
    );

    let scan_result = if let Some(path) = &cli.validate_from {
        println!(
            "[INFO] Validating the extracted inventory from {}.",
            path.display()
        );
        security_scan::scan_from_snapshot(path, nvd_key.as_deref()).await?
    } else {
        // This pre-check is Routinator-specific; the CVE scan below also handles Fort.
        println!(
            "\n{}",
            "[INFO] Running Routinator configuration and permission pre-check..."
                .bright_blue()
                .bold()
        );
        println!(
            "{}",
            "[INFO] Checking Routinator config files; this is not a CVE validation."
                .bright_cyan()
        );
        routinator::validator::validate();
        println!(
            "{}",
            "[INFO] Routinator pre-check finished; review its messages above. CVE triage covers both Routinator and Fort.\n"
                .bright_blue()
        );
        security_scan::scan(nvd_key.as_deref()).await?
    };
    let warning_count = scan_result.warnings.len();
    for warning in &scan_result.warnings {
        eprintln!("{} {}", "[WARN]".bright_yellow().bold(), warning);
    }

    println!(
        "\n{}",
        format!(
            "[SUMMARY] {} possible match(es) for supported validators/dependencies.",
            scan_result.findings.len()
        )
            .bright_blue()
            .bold()
    );
    if !scan_result.findings.is_empty() {
        for finding in &scan_result.findings {
            println!(
                "[MATCH] {} | {} {} | {} | {}",
                finding.id, finding.product, finding.version, finding.severity, finding.source
            );
        }
    }

    match report::make_report(&scan_result.findings)? {
        Some(path) => println!("[INFO] CSV report written to {}.", path.display()),
        None => println!("[INFO] No CSV report was generated because there were no matches."),
    }
    if warning_count == 0 {
        println!("[INFO] Triage finished. Matches are not confirmation of exploitability.");
    } else {
        println!(
            "[INFO] Triage finished with {warning_count} warning(s); review them before interpreting coverage."
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    #[cfg(feature = "gui")]
    if gui::check_gui(&cli) {
        gui::gui();
    } else {
        if let Err(error) = validate(&cli).await {
            eprintln!("{} {}", "[ERROR]".bright_red().bold(), error);
            std::process::exit(1);
        }
    }

    #[cfg(not(feature = "gui"))]
    if let Err(error) = validate(&cli).await {
        eprintln!("{} {}", "[ERROR]".bright_red().bold(), error);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn nvd_api_key_is_only_accepted_from_a_file() {
        assert!(Cli::try_parse_from(["mirak", "--key", "not-a-real-key"]).is_err());
        assert!(Cli::try_parse_from(["mirak", "--key-file", "nvd-key.txt"]).is_ok());
    }

    #[test]
    fn inventory_modes_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["mirak", "--extract-only", "inventory.json"]).is_ok());
        assert!(Cli::try_parse_from(["mirak", "--validate-from", "inventory.json"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "mirak",
                "--extract-only",
                "inventory.json",
                "--validate-from",
                "inventory.json"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "mirak",
                "--extract-only",
                "inventory.json",
                "--key-file",
                "nvd-key.txt"
            ])
            .is_err()
        );
    }
}
