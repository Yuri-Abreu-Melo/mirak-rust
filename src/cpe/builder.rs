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
    let pkg_manager = PackageManager::detect_package_manager();
    assert!(
        pkg_manager.is_some(), "{}",
        "[ERROR] - This version of mirak only works in OS where DNF or APT or APK package managers are used".red()
    );
    let packages = find_installed_apps(pkg_manager.unwrap());
    assert!(
        packages.is_some(),
        "{}",
        "[ERROR] - If there are no packages installed, then there is nothing to be checked".red()
    );
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
    write_cpes_to_file(&cpes, "cpes.mirak").unwrap();
    println!("[INFO] - Saving the CPES on cpes.mirak",);
    cpes
}

#[cfg(feature = "gui")]
pub fn build_cpe_gui() -> Vec<String> {
    let pkg_manager = PackageManager::detect_package_manager();
    if pkg_manager.is_none() {
        panic!(
            "{}", "[ERROR] - This version of mirak only works in OS where DNF or APT or APK package managers are used".red()
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
    // text_buffer.insert(
    //     &mut text_buffer.end_iter(),
    //     "✅ Salvando os CPES no arquivo cpes.mirak \n",
    // );
    write_cpes_to_file(&cpes, "cpes.mirak").unwrap();
    cpes
}
