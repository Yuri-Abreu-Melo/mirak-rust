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

    #[cfg(feature = "gui")]
    /// Specify if it will run with the gui
    #[arg(short, long)]
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

    // Validating routinator config and file permissions
    println!(
        "\n{}",
        "[INFO] Validating Routinator configuration..."
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        "[INFO] Checking Routinator data validation process".bright_cyan()
    );

    routinator::validator::validate();
    println!(
        "{}",
        "[ OK ] Routinator data validation completed successfully\n".bright_green()
    );

    // Scan only the supported RPKI validators and their identifiable dependencies.
    println!(
        "{}",
        "[INFO] Scanning Routinator, Fort, and their dependencies...\n"
            .bright_blue()
            .bold()
    );

    let scan_result = security_scan::scan(nvd_key.as_deref()).await?;
    for warning in &scan_result.warnings {
        eprintln!("{} {}", "[WARN]".bright_yellow().bold(), warning);
    }

    println!(
        "\n{}",
        "[INFO] Processing vulnerability report..."
            .bright_blue()
            .bold()
    );

    report::make_report(&scan_result.findings)?;

    println!(
        "\n{}",
        "[ OK ] Scan completed successfully!".bright_green().bold()
    );
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
}
