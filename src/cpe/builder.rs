use crate::{
    cpe::apps::{PackageManager, find_installed_apps},
    extractors::os,
};

use colored::*;

fn write_cpes_to_file(cpes: &[String], filename: &str) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(filename)?;

    for cpe in cpes {
        writeln!(file, "{}", cpe)?;
    }

    Ok(())
}

/// Create the cpes for apps instaled and the OS
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
    
    // Create the OS cpe
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
    for package in packages.unwrap() {
        cpes.push(format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            package.distributor, package.name, package.version
        ));
        cpe_count += 1;
        
        // Mostrar progresso a cada 100 CPEs gerados
        if cpe_count % 100 == 0 {
            print!("\r  [INFO] Progress: {} CPEs generated", cpe_count.to_string().bright_yellow());
        }
    }
    
    if cpe_count > 100 {
        println!(); // Nova linha após o progresso
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
    
    // Create the OS cpe
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
    
    for package in packages.unwrap() {
        cpes.push(format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            package.distributor, package.name, package.version
        ));
    }
    
    // Salvar CPEs em arquivo (silenciosamente na GUI)
    let _ = write_cpes_to_file(&cpes, "cpes.mirak");
    
    cpes
}
