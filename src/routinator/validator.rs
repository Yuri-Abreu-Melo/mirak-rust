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
        output.push_str("[ERROR] - Routinator not installed\n");
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
        println!("{}", "[ERROR] - Routinator not installed".red());
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
                    Ok(_) => reports.push_str(format!("{}", "[INFO] - Config validated".bright_green()).as_str()),
                    Err(err) => reports
                        .push_str(format!("{} {}", "[WARN] -Invalid config file: \n".bright_yellow(), err.message().red()).as_str()),
                },
                Err(err) => {
                    reports.push_str(format!("{} {err}", "[WARN] - Could not open config file: \n".bright_yellow()).as_str())
                }
            }
        }
    }
    if reports.is_empty() {
        reports.push_str(&"[WARN] - Routinator config file not found".bright_yellow().to_string());
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

    for (_, mode) in access_modes {
        if !mode.permission == 0o644 {
            return Err(format!(
                "{} {:o}", "[WARN] - Expected routinator.conf to have 644 as permission, got: \n".bright_yellow(),
                mode.permission
            ));
        }
    }

    Ok("[INFO] - Routinator config files permissions validated\n".bright_green().to_string())
}
