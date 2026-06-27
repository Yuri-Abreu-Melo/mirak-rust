use std::{fs, path::PathBuf};

use clap::Parser;
use colored::*;

mod cpe;
mod extractors;
mod nvd;
mod report;
mod routinator;

#[cfg(feature = "gui")]
mod gui;

#[derive(Parser)]
#[command(
    name = "MIRAK",
    version = "0.1.0",
    about = "Scans system binaries for vulnerabilities using NVD and generates reports",
    long_about = "Scans system binaries for vulnerabilities using NVD and generates reports. \n
A command-line tool that analyzes installed system binaries, queries the NVD database for known \
vulnerabilities, and generates a structured security report."
)]
struct Cli {
    /// NVD API key provided directly via command line
    #[arg(short, long, value_name = "API_KEY")]
    key: Option<String>,

    /// Path to a file containing the NVD API key
    #[arg(short = 'f', long, value_name = "FILE_PATH")]
    key_file: Option<PathBuf>,

    #[cfg(feature = "gui")]
    /// Specify if it will run with the gui
    #[arg(short, long)]
    gui: bool,
}

fn parse_args(cli: &Cli) -> String {
    // Search NVD key on args
    if cli.key.is_none() && cli.key_file.is_none() {
        eprintln!(
            "{}",
            "[ERROR] Please provide a valid NVD key"
                .bright_red()
                .bold()
        );
        std::process::exit(1);
    }

    let mut nvd_key = String::from("");

    if let Some(key) = &cli.key {
        nvd_key = key.clone()
    }

    if let Some(key_path) = &cli.key_file {
        match fs::read_to_string(key_path) {
            Ok(content) => nvd_key = content.trim().to_string(),
            Err(err) => {
                eprintln!(
                    "{}",
                    format!(
                        "[ERROR] Could not read key file '{}': {}",
                        key_path.display(),
                        err
                    )
                    .bright_red()
                    .bold()
                );
                std::process::exit(1);
            }
        }
    }

    nvd_key
}

async fn validate(cli: &Cli) {
    let nvd_key = parse_args(cli);

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

    // Search for vulnerabilities in all installed apps
    println!(
        "{}",
        "[INFO] Scanning operating system binaries for vulnerabilities...\n"
            .bright_blue()
            .bold()
    );

    let nvd_result = nvd::check::check(cpe::builder::build_cpe(), nvd_key).await;

    println!(
        "\n{}",
        "[INFO] Processing vulnerability report...".bright_blue().bold()
    );

    report::make_report(nvd_result);

    println!(
        "\n{}",
        "[ OK ] Scan completed successfully!".bright_green().bold()
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    #[cfg(feature = "gui")]
    if gui::check_gui(&cli) {
        gui::gui();
    } else {
        validate(&cli).await;
    }

    #[cfg(not(feature = "gui"))]
    validate(&cli).await;
}
