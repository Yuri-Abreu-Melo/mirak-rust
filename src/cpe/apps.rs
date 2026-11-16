use colored::*;
use regex::Regex;
use std::{env, fs, path::PathBuf, process::Command};

#[derive(Debug, Clone, Copy)]
pub enum PackageManager {
    Apt,
    Dnf,
    Apk,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub distributor: String,
    pub source_name: String,   // NEW: upstream source package name
    pub binary_path: Option<PathBuf>,
}

/// Clean some undesired characters
fn clean_cpe_carachters(text: &str) -> String {
    let regex = Regex::new(r"[^a-zA-Z0-9\-_/\.|]").unwrap();
    regex.replace_all(text, "").to_string()
}

pub fn find_routinator_by_cargo() -> (Vec<PackageInfo>, Vec<String>) {
    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    let mut cargo_homes = Vec::new();
    if let Some(cargo_home) = env::var_os("CARGO_HOME") {
        cargo_homes.push(PathBuf::from(cargo_home));
    }
    if let Some(home) = env::var_os("HOME") {
        cargo_homes.push(PathBuf::from(home).join(".cargo"));
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        cargo_homes.extend(passwd.lines().filter_map(|line| {
            let home = line.split(':').nth(5)?;
            (!home.is_empty() && home != "/nonexistent")
                .then(|| PathBuf::from(home).join(".cargo"))
        }));
    }

    let mut seen = Vec::new();
    for cargo_home in cargo_homes {
        if seen.contains(&cargo_home) || !cargo_home.join("bin/routinator").is_file() {
            continue;
        }
        seen.push(cargo_home.clone());

        match Command::new("cargo")
            .env("CARGO_HOME", &cargo_home)
            .args(["install", "--list"])
            .output()
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let version = stdout.lines().find_map(|line| {
                    line.strip_prefix("routinator v")
                        .and_then(|value| value.split_once(':').map(|(version, _)| version))
                });
                if let Some(version) = version {
                    packages.push(PackageInfo {
                        name: "routinator".to_string(),
                        version: version.to_string(),
                        distributor: "nlnetlabs".to_string(),
                        source_name: "routinator".to_string(),
                        binary_path: Some(cargo_home.join("bin/routinator")),
                    });
                } else {
                    warnings.push(format!(
                        "Could not determine the Cargo-installed Routinator version in {}.",
                        cargo_home.display()
                    ));
                }
            }
            Ok(output) => warnings.push(format!(
                "Could not query the Cargo installation in {}: {}",
                cargo_home.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => warnings.push(format!(
                "Could not query the Cargo installation in {}: {error}",
                cargo_home.display()
            )),
        }
    }
    (packages, warnings)
}

pub fn find_installed_apps(pkg_manager: PackageManager) -> Option<Vec<PackageInfo>> {
    println!(
        "{}",
        "[INFO] - Searching for system packages \n".bright_green()
    );
    let output = match pkg_manager {
        PackageManager::Apt => Command::new("dpkg-query")
            .args([
                "-W",
                // Added ${Source} to get upstream source package name
                "-f=${binary:Package}|${Maintainer}|${Version}|${Architecture}|${Source}\\n",
            ])
            .output()
            .ok()?,
        PackageManager::Dnf => Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                // Added %{SOURCERPM} to get the source RPM filename
                "%{NAME}|%{VENDOR}|%{VERSION}|%{ARCH}|%{SOURCERPM}\\n",
            ])
            .output()
            .ok()?,
        PackageManager::Apk => Command::new("apk").args(["info", "-v"]).output().ok()?,
    };

    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut packages: Vec<PackageInfo> = stdout
        .lines()
        .filter_map(|line| match pkg_manager {
            PackageManager::Apt | PackageManager::Dnf => {
                // Now line has 5 fields (or at least 5)
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() < 5 {
                    return None;
                }
                let name = clean_cpe_carachters(parts[0]);
                let version = clean_cpe_carachters(parts[2]);
                let source_raw = parts[4];

                let source_name = if source_raw.is_empty() {
                    name.clone()
                } else {
                    // For dpkg: Source may contain version like "openssl (1.0.2g-...)"
                    // For rpm: SOURCERPM is like "openssl-1.0.2g-1.fc24.src.rpm"
                    // Take only the first word/token before any space or dash-number
                    if matches!(pkg_manager, PackageManager::Apt) {
                        source_raw.split_whitespace().next().unwrap_or(&name).to_string()
                    } else {
                        // DNF: source is a filename, take part before first '-'
                        source_raw.split('-').next().unwrap_or(&name).to_string()
                    }
                };

                if name.contains("routinator") {
                    Some(PackageInfo {
                        name,
                        version,
                        distributor: "nlnetlabs".to_string(),
                        source_name: "routinator".to_string(),
                        binary_path: None,
                    })
                } else {
                    Some(PackageInfo {
                        name,
                        version,
                        distributor: parts[1]
                            .split_whitespace()
                            .next()
                            .unwrap_or("*")
                            .to_string(),
                        source_name,
                        binary_path: None,
                    })
                }
            }
            PackageManager::Apk => {
                let parts: Vec<&str> = line.rsplitn(2, '-').collect();
                if parts.len() < 2 {
                    return None;
                }
                let name_version = parts[1];
                let name_parts: Vec<&str> = name_version.splitn(2, '-').collect();
                if name_parts.len() < 2 {
                    return None;
                }
                let pkg_name = clean_cpe_carachters(name_parts[0]);
                let pkg_version = clean_cpe_carachters(name_parts[1]);
                // APK doesn't expose source directly; use pkg_name as source (often correct)
                if pkg_name.contains("routinator") {
                    Some(PackageInfo {
                        name: pkg_name,
                        version: pkg_version,
                        distributor: "nlnetlabs".to_string(),
                        source_name: "routinator".to_string(),
                        binary_path: None,
                    })
                } else {
                    Some(PackageInfo {
                        name: pkg_name.clone(),
                        version: pkg_version,
                        distributor: "alpine".to_string(),
                        source_name: pkg_name,
                        binary_path: None,
                    })
                }
            }
        })
        .collect();

    Some(packages)
}

impl PackageManager {
    pub fn detect_package_manager() -> Option<Self> {
        let candidates = [
            ("apt", PackageManager::Apt),
            ("dnf", PackageManager::Dnf),
            ("apk", PackageManager::Apk),
        ];
        for (cmd, manager) in candidates {
            if Command::new("which")
                .arg(cmd)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return Some(manager);
            }
        }
        None
    }
}

/// Remove distribution release suffix (everything after first '-' followed by digit)
pub fn normalize_version(version: &str) -> String {
    let version = version
        .split_once(':')
        .map_or(version, |(_, upstream_version)| upstream_version);
    if let Some(pos) = version.find('-') {
        version[..pos].to_string()
    } else {
        version.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_version;

    #[test]
    fn normalize_version_removes_package_epoch_and_release_suffix() {
        assert_eq!(normalize_version("1:0.15.3-1ubuntu1"), "0.15.3");
    }
}
