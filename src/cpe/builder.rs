use crate::{
    cpe::apps::{PackageManager, find_installed_apps, normalize_package_name, normalize_version},
    extractors::os,
};

use colored::*;
use std::collections::HashMap;

fn write_cpes_to_file(cpes: &[String], filename: &str) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(filename)?;

    for cpe in cpes {
        writeln!(file, "{}", cpe)?;
    }

    Ok(())
}

fn get_cpe_mapping() -> HashMap<&'static str, (&'static str, &'static str)> {
    HashMap::from([
        ("openssl", ("openssl", "openssl")),
        ("libssl", ("openssl", "openssl")),
        ("apache2", ("apache", "http_server")),
        ("httpd", ("apache", "http_server")),
        ("nginx", ("nginx", "nginx")),
        ("python-requests", ("python-requests", "requests")),
        ("requests", ("python-requests", "requests")),
        ("linux-libc-dev", ("linux", "linux_kernel")),
        ("glibc", ("gnu", "glibc")),
        ("libc6", ("gnu", "glibc")),
        ("bash", ("gnu", "bash")),
        ("zlib1g", ("zlib", "zlib")),
        ("expat", ("libexpat", "expat")),
    ])
}

/// Build CPEs for installed applications and OS
pub fn build_cpe() -> Vec<String> {
    println!("\n{}", "═══════════════════════════════════════════".bright_magenta());
    println!("{}", "[INFO] BUILDING CPEs FOR SYSTEM SCAN".bright_magenta().bold());
    println!("{}", "═══════════════════════════════════════════".bright_magenta());

    println!("{}", "[INFO] Detecting package manager...".bright_blue());
    let pkg_manager = PackageManager::detect_package_manager();
    
    assert!(
        pkg_manager.is_some(), 
        "{}", 
        "[ERROR] This version of MIRAK only works on systems using DNF, APT, or APK package managers"
            .bright_red()
            .bold()
    );
    
    let manager_name = match pkg_manager.unwrap() {
        PackageManager::Dnf => "DNF",
        PackageManager::Apt => "APT",
        PackageManager::Apk => "APK",
    };
    println!(
        "{} {}",
        "[ OK ] Package manager detected:".bright_green(),
        manager_name.bright_yellow().bold()
    );

    println!("{}", "[INFO] Fetching installed packages...".bright_blue());
    let packages = find_installed_apps(pkg_manager.unwrap());
    
    assert!(
        packages.is_some(),
        "{}",
        "[ERROR] No packages found to scan. Please ensure packages are installed."
            .bright_red()
            .bold()
    );

    let package_count = packages.as_ref().unwrap().len();
    println!(
        "{} {} {}",
        "[ OK ] Found".bright_green(),
        package_count.to_string().bright_yellow().bold(),
        "installed packages".bright_green()
    );

    println!("{}", "[INFO] Detecting OS information...".bright_blue());
    let mut cpes: Vec<String> = Vec::new();
    let os_release = os::extract_os_release_info();
    
    // Create the OS CPE
    let os_id = os_release.get("ID").unwrap();
    let os_version = os_release.get("VERSION_ID").unwrap();
    
    println!(
        "{} {} {}",
        "[ OK ] OS detected:".bright_green(),
        os_id.bright_cyan(),
        format!("(version {})", os_version).bright_white()
    );

    if os_id.to_lowercase().eq("ubuntu") {
        cpes.push(format!(
            "cpe:2.3:o:canonical:{}:{}:*:*:*:*:*:*:*",
            os_id.to_owned() + "_linux",
            os_version,
        ));
    } else {
        cpes.push(format!(
            "cpe:2.3:o:fedoraproject:{}:{}:*:*:*:*:*:*:*",
            os_id,
            os_version,
        ));
    }

    println!("{}", "[INFO] Generating CPEs for packages...".bright_blue());
    let mut cpe_count = 0;
    let mapping = get_cpe_mapping();

    for package in packages.unwrap() {
        // --- ROUTINATOR / NLNETLABS especial ---
        // If the package was explicitly marked as routinator by the collector,
        // we already have the correct vendor and product.
        if package.distributor == "nlnetlabs" || package.name.contains("routinator") {
            let version = normalize_version(&package.version);
            cpes.push(format!(
                "cpe:2.3:a:nlnetlabs:routinator:{}:*:*:*:*:*:*:*",
                version
            ));
            cpe_count += 1;
            continue;
        }

        // --- General application CPE generation ---
        // Prefer source_name (normalized), else name normalized
        let raw_name = if !package.source_name.is_empty() {
            &package.source_name
        } else {
            &package.name
        };
        let normalized_name = normalize_package_name(raw_name);
        let version = normalize_version(&package.version);

        // Lookup mapping or fallback to normalized name as vendor and product
        let (vendor, product) = if let Some(&(v, p)) = mapping.get(normalized_name.as_str()) {
            (v, p)
        } else {
            (normalized_name.as_str(), normalized_name.as_str())
        };

        cpes.push(format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            vendor, product, version
        ));
        cpe_count += 1;
        
        // Show progress every 100 CPEs
        if cpe_count % 100 == 0 {
            print!("\r  [INFO] Progress: {} CPEs generated", cpe_count.to_string().bright_yellow());
        }
    }
    
    if cpe_count > 100 {
        println!();
    }
    
    println!(
        "{} {} {}",
        "[ OK ] Generated".bright_green(),
        cpe_count.to_string().bright_yellow().bold(),
        "CPEs".bright_green()
    );

    println!("{}", "[INFO] Saving CPEs to file...".bright_blue());
    match write_cpes_to_file(&cpes, "cpes.mirak") {
        Ok(_) => {
            println!(
                "{} {}",
                "[ OK ] CPEs saved successfully to".bright_green(),
                "cpes.mirak".bright_white().bold()
            );
        }
        Err(err) => {
            eprintln!(
                "{} {}",
                "[WARN] Could not save CPEs to file:".bright_yellow(),
                err.to_string().bright_red()
            );
        }
    }

    println!(
        "\n{}",
        "[ OK ] CPE build completed successfully!".bright_green().bold()
    );
    println!("{}\n", "═══════════════════════════════════════════".bright_magenta());

    cpes
}

#[cfg(feature = "gui")]
pub fn build_cpe_gui() -> Vec<String> {
    let pkg_manager = PackageManager::detect_package_manager();
    if pkg_manager.is_none() {
        panic!(
            "{}", 
            "[ERROR] This version of MIRAK only works on systems using DNF, APT, or APK package managers"
                .bright_red()
                .bold()
        );
    }
    
    let packages = find_installed_apps(pkg_manager.unwrap());
    let mut cpes: Vec<String> = Vec::new();
    let os_release = os::extract_os_release_info();
    
    // OS CPE
    if os_release.get("ID").unwrap().to_lowercase().eq("ubuntu") {
        cpes.push(format!(
            "cpe:2.3:o:canonical:{}:{}:*:*:*:*:*:*:*",
            os_release.get("ID").unwrap().as_str().to_owned() + "_linux",
            os_release.get("VERSION_ID").unwrap(),
        ));
    } else {
        cpes.push(format!(
            "cpe:2.3:o:fedoraproject:{}:{}:*:*:*:*:*:*:*",
            os_release.get("ID").unwrap(),
            os_release.get("VERSION_ID").unwrap(),
        ));
    }
    
    let mapping = get_cpe_mapping();
    for package in packages.unwrap() {
        // Routinator special treatment
        if package.distributor == "nlnetlabs" || package.name.contains("routinator") {
            let version = normalize_version(&package.version);
            cpes.push(format!(
                "cpe:2.3:a:nlnetlabs:routinator:{}:*:*:*:*:*:*:*",
                version
            ));
            continue;
        }

        let raw_name = if !package.source_name.is_empty() {
            &package.source_name
        } else {
            &package.name
        };
        let normalized_name = normalize_package_name(raw_name);
        let version = normalize_version(&package.version);

        let (vendor, product) = if let Some(&(v, p)) = mapping.get(normalized_name.as_str()) {
            (v, p)
        } else {
            (normalized_name.as_str(), normalized_name.as_str())
        };

        cpes.push(format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            vendor, product, version
        ));
    }
    
    let _ = write_cpes_to_file(&cpes, "cpes.mirak");
    cpes
}