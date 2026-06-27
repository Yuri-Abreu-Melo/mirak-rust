use std::{fs, path::PathBuf, process::Command};

use crate::{extractors, routinator::schema::Config};
use colored::*;

#[cfg(feature = "gui")]
pub fn validate_gui() -> String {
    let mut output = String::new();

    if Command::new("which")
        .arg("routinator")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let mut reports = String::new();
        match check_routinator_files() {
            Ok(result) => reports.push_str(&result),
            Err(err) => reports.push_str(&err),
        }
        reports.push_str(&validate_config());
        output.push_str(&reports);
    } else {
        output.push_str(&format!(
            "{}\n",
            "[ERROR] Routinator not installed".bright_red().bold()
        ));
    }

    output
}

pub fn validate() {
    if Command::new("which")
        .arg("routinator")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let mut reports = String::from("");
        match check_routinator_files() {
            Ok(result) => reports.push_str(result.as_str()),
            Err(err) => reports.push_str(err.as_str()),
        }
        reports.push_str(validate_config().as_str());
        println!("{reports}");
    } else {
        println!(
            "{}",
            "[ERROR] Routinator not installed. Please install it to continue."
                .bright_red()
                .bold()
        );
    }
}

/// This function simply reads the path and try to convert using the Config struct
/// so invalid fields (unexpected, wrong values or missing obrigatory) fires error
fn validate_config() -> String {
    let mut reports = String::from("");
    let home_dir = std::env::var("HOME").unwrap_or_default();
    let paths = vec![
        PathBuf::from("/etc/routinator/routinator.conf"),
        PathBuf::from(format!("{}/.routinator.conf", home_dir)),
    ];

    for path in paths {
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(file) => match toml::from_str::<Config>(&file) {
                    Ok(_) => reports.push_str(
                        format!(
                            "  [ OK ] Config file '{}' validated successfully\n",
                            path.display()
                        )
                        .bright_green()
                        .to_string()
                        .as_str(),
                    ),
                    Err(err) => reports.push_str(
                        format!(
                            "  [WARN] Invalid config file '{}': {}\n",
                            path.display(),
                            err.message().bright_red()
                        )
                        .bright_yellow()
                        .to_string()
                        .as_str(),
                    ),
                },
                Err(err) => reports.push_str(
                    format!(
                        "  [WARN] Could not open config file '{}': {}\n",
                        path.display(),
                        err.to_string().bright_red()
                    )
                    .bright_yellow()
                    .to_string()
                    .as_str(),
                ),
            }
        }
    }

    if reports.is_empty() {
        reports.push_str(
            "[WARN] Routinator config file not found in standard locations\n"
                .bright_yellow()
                .to_string()
                .as_str(),
        );
    }
    reports
}

/// This function check if the routinator config dir and config file exists
/// and check if the right permissions are setted
fn check_routinator_files() -> Result<String, String> {
    let home_dir = std::env::var("HOME").unwrap_or_default();
    let paths = vec![
        PathBuf::from("/etc/routinator/routinator.conf"),
        PathBuf::from(format!("{}/.routinator.conf", home_dir)),
    ];
    let access_modes = extractors::os::get_files_access_mode(paths);

    let mut result = String::from("[INFO] Checking Routinator configuration files:\n");

    for (path, mode) in access_modes {
        if mode.permission != 0o644 {
            return Err(format!(
                "  [WARN] File '{}' has incorrect permissions: {:o} (expected 644)\n",
                path.to_string().bright_white(),
                mode.permission
            )
            .bright_yellow()
            .to_string());
        } else {
            result.push_str(
                format!(
                    "  [ OK ] File '{}' has correct permissions: {:o}\n",
                    path.to_string().bright_white(),
                    mode.permission
                )
                .bright_green()
                .to_string()
                .as_str(),
            );
        }
    }

    Ok(result)
}
