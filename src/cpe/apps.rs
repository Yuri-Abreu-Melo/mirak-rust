use regex::Regex;
use std::process::Command;
use colored::*;

#[derive(Debug)]
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
}

/// Clean some undesired carachters
fn clean_cpe_carachters(text: &str) -> String {
    let regex = Regex::new(r"[^a-zA-Z0-9\-_/\.|]").unwrap();
    regex.replace_all(text, "").to_string()
}

fn find_routinator_by_cargo(packages: &mut Vec<PackageInfo>) {
    if let Ok(output) = Command::new("cargo").args(["install", "--list"]).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let routinator_version = stdout.lines().find(|line| line.starts_with("routinator v"));
        if let Some(routinator_installed) = routinator_version {
            let (name, version) = routinator_installed.split_once(" ").unwrap();
            packages.push(PackageInfo {
                name: name.to_string(),
                version: version
                    .trim_start_matches("v")
                    .trim_end_matches(":")
                    .to_string(),
                distributor: "nlnetlabs".to_string(),
            });
        }
    }
}

pub fn find_installed_apps(pkg_manager: PackageManager) -> Option<Vec<PackageInfo>> {
    println!("{}", "[INFO] - Searching for system packages \n".bright_green());
    let output = match pkg_manager {
        PackageManager::Apt => Command::new("dpkg-query")
            .args([
                "-W",
                "-f=${binary:Package}|${Maintainer}|${Version}|${Architecture}\\n",
            ])
            .output()
            .ok()?,
        PackageManager::Dnf => Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}|%{VENDOR}|%{VERSION}|%{ARCH}\\n",
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
                let parts: Vec<&str> = line.splitn(3, '|').collect();
                if parts.len() < 3 {
                    return None;
                }
                if clean_cpe_carachters(parts[0]).contains("routinator") {
                    Some(PackageInfo {
                        name: clean_cpe_carachters(parts[0]),
                        version: clean_cpe_carachters(parts[2]),
                        distributor: "nlnetlabs".to_string(),
                    })
                } else {
                    Some(PackageInfo {
                        name: clean_cpe_carachters(parts[0]),
                        version: clean_cpe_carachters(parts[2]),
                        distributor: parts[1]
                            .split_whitespace()
                            .next()
                            .unwrap_or("*")
                            .to_string(),
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
                if clean_cpe_carachters(name_parts[0]).contains("routinator") {
                    Some(PackageInfo {
                        name: clean_cpe_carachters(name_parts[0]),
                        version: clean_cpe_carachters(name_parts[1]),
                        distributor: "nlnetlabs".to_string(),
                    })
                } else {
                    Some(PackageInfo {
                        name: clean_cpe_carachters(name_parts[0]),
                        version: clean_cpe_carachters(name_parts[1]),
                        distributor: "alpine".to_string(),
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
