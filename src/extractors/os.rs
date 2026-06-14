use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
use users::{get_group_by_gid, get_user_by_uid};

#[allow(dead_code)]
pub struct ModeInfo {
    pub permission: u32,
    pub dir: bool,
    pub owner: String,
    pub gowner: String,
}

/// Read os-release file and return a HashMap with it content
pub fn extract_os_release_info() -> HashMap<String, String> {
    let os_release_file = fs::File::open("/etc/os-release");
    let mut os_release_info: HashMap<String, String> = HashMap::new();
    match os_release_file {
        Ok(file) => {
            let buffer = BufReader::new(file);
            for (idx, line) in buffer.lines().enumerate() {
                match line {
                    Ok(content) => {
                        if content.trim().is_empty() || content.starts_with("#") {
                            continue;
                        }
                        if let Some((key, value)) = content.split_once("=") {
                            // Remove " from value
                            let clean_value = value.trim_matches('"');
                            os_release_info.insert(key.to_string(), clean_value.to_string());
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to read line {idx} of os-release file, {err:?}");
                    }
                }
            }
        }
        Err(err) => eprintln!("Error while trying to open os-release file, {err:?}"),
    }
    os_release_info
}

// Read lsb-release file and return a HashMap with it content
// pub fn extract_lsb_release_info() -> HashMap<String, String> {
//     let lsb_release_file = fs::File::open("/etc/lsb-release");
//     let mut lsb_release_info: HashMap<String, String> = HashMap::new();
//     if let Ok(file) = lsb_release_file {
//         let buffer = BufReader::new(file);
//         for (idx, line) in buffer.lines().enumerate() {
//             match line {
//                 Ok(content) => {
//                     if content.trim().is_empty() || content.starts_with("#") {
//                         continue;
//                     }
//                     if let Some((key, value)) = content.split_once("=") {
//                         // Remove " from value
//                         let clean_value = value.trim_matches('"');
//                         lsb_release_info.insert(key.to_string(), clean_value.to_string());
//                     }
//                 }
//                 Err(err) => {
//                     eprintln!("Failed to read line {idx} of lsb-release file, {err:?}");
//                 }
//             }
//         }
//     }
//     lsb_release_info
// }

// Read issue file and return it contents
// pub fn extract_issue_info() -> String {
//     let issue_file = fs::read_to_string("/etc/issue");
//     match issue_file {
//         Ok(content) => content,
//         Err(err) => format!("Error while trying to open issue file, {err:?}").to_string(),
//     }
// }

/// Receive an array of paths and return a HashMap with the path as key and the mode  access e.g.:
/// 755 as value
pub fn get_files_access_mode(files: Vec<PathBuf>) -> HashMap<String, ModeInfo> {
    let mut files_modes: HashMap<String, ModeInfo> = HashMap::new();
    for file in files {
        if let Ok(metadata) = file.metadata() {
            files_modes.insert(
                file.to_string_lossy().to_string(),
                ModeInfo {
                    // The & 0o777 bitmask ensure to get only the bit of permissions
                    permission: metadata.permissions().mode() & 0o777,
                    dir: file.is_dir(),
                    owner: get_user_by_uid(metadata.uid())
                        .unwrap()
                        .name()
                        .to_string_lossy()
                        .to_string(),
                    gowner: get_group_by_gid(metadata.gid())
                        .unwrap()
                        .name()
                        .to_string_lossy()
                        .to_string(),
                },
            );
        }
    }
    files_modes
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_extract_os_release_info() {
        let os_release = extract_os_release_info();
        assert!(os_release.contains_key("NAME"));
    }

    // #[test]
    // fn test_extract_lsb_release_info() {
    //     let lsb_release = extract_lsb_release_info();
    //     assert!(lsb_release.contains_key("DISTRIB_ID"));
    // }

    // #[test]
    // fn test_extract_issue_info() {
    //     let issue_info = extract_issue_info();
    //     assert!(!issue_info.is_empty())
    // }

    #[test]
    fn test_get_file_access_mode() {
        let test_paths = vec![PathBuf::from("/etc/passwd"), PathBuf::from("/etc")];
        let files_modes = get_files_access_mode(test_paths);
        assert!(files_modes.contains_key("/etc"));
        assert!(files_modes.contains_key("/etc/passwd"));
        // The linux mode permissions are stored in octal base
        // In order to compare these values in octal base the 0o is needed to prefix the raw value
        assert_eq!(files_modes.get("/etc/passwd").unwrap().permission, 0o644);
        assert_eq!(files_modes.get("/etc").unwrap().permission, 0o755);
        assert!(!files_modes.get("/etc/passwd").unwrap().dir);
        assert!(files_modes.get("/etc").unwrap().dir);
        assert_eq!(files_modes.get("/etc").unwrap().owner, "root");
        assert_eq!(files_modes.get("/etc/passwd").unwrap().owner, "root");
        assert_eq!(files_modes.get("/etc").unwrap().gowner, "root");
        assert_eq!(files_modes.get("/etc/passwd").unwrap().gowner, "root");
    }
}
