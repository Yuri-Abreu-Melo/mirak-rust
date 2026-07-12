use colored::*;
use regex::Regex;
use std::process::Command;

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
}

/// Clean some undesired characters
fn clean_cpe_carachters(text: &str) -> String {
    let regex = Regex::new(r"[^a-zA-Z0-9\-_/\.|]").unwrap();
    regex.replace_all(text, "").to_string()
}

fn find_routinator_by_cargo(packages: &mut Vec<PackageInfo>) {
    if let Ok(output) = Command::new("cargo").args(["install", "--list"]).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.starts_with("routinator v")) {
            if let Some((name, version)) = line.split_once(' ') {
                packages.push(PackageInfo {
                    name: name.to_string(),
                    version: version
                        .trim_start_matches('v')
                        .trim_end_matches(':')
                        .to_string(),
                    distributor: "nlnetlabs".to_string(),
                    source_name: "routinator".to_string(), // hardcoded for this tool
                });
            }
        }
    }
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
                    })
                } else {
                    Some(PackageInfo {
                        name: pkg_name.clone(),
                        version: pkg_version,
                        distributor: "alpine".to_string(),
                        source_name: pkg_name,
                    })
                }
            }
        })
        .collect();

    find_routinator_by_cargo(&mut packages);
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

/// Remove common distro prefixes/suffixes that are not part of upstream name
pub fn normalize_package_name(raw: &str) -> String {
    let mut name = raw.to_lowercase();
    for prefix in &["python3-", "python-", "ruby-", "perl-", "php-", "lua-"] {
        if let Some(stripped) = name.strip_prefix(prefix) {
            name = stripped.to_string();
            break;
        }
    }
    for suffix in &["-dev", "-doc", "-common", "-data", "-bin"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            name = stripped.to_string();
            break;
        }
    }
    name
}

/// Remove distribution release suffix (everything after first '-' followed by digit)
pub fn normalize_version(version: &str) -> String {
    if let Some(pos) = version.find('-') {
        version[..pos].to_string()
    } else {
        version.to_string()
    }
}