use crate::cpe::apps::{PackageInfo, normalize_version};

fn get_validator_cpes(package: &PackageInfo) -> Option<Vec<String>> {
    let version = normalize_version(&package.version);

    if package.distributor == "nlnetlabs" || package.name.contains("routinator") {
        return Some(vec![format!(
            "cpe:2.3:a:nlnetlabs:routinator:{}:*:*:*:*:*:*:*",
            version
        )]);
    }

    let is_fort_validator = [&package.name, &package.source_name].iter().any(|name| {
        let normalized_name = name.to_ascii_lowercase().replace('_', "-");
        matches!(normalized_name.as_str(), "fort" | "fort-validator")
    });

    is_fort_validator.then(|| {
        ["fort-validator", "fort_validator"]
            .into_iter()
            .map(|product| format!("cpe:2.3:a:nicmx:{}:{}:*:*:*:*:*:*:*", product, version))
            .collect()
    })
}

pub fn validator_cpes(package: &PackageInfo) -> Vec<String> {
    get_validator_cpes(package).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::get_validator_cpes;
    use crate::cpe::apps::PackageInfo;

    #[test]
    fn fort_validator_generates_both_nvd_product_variants() {
        let package = PackageInfo {
            name: "fort".to_string(),
            version: "1.6.6-1".to_string(),
            distributor: "NICMx".to_string(),
            source_name: "fort_validator".to_string(),
        };

        assert_eq!(
            get_validator_cpes(&package).unwrap(),
            vec![
                "cpe:2.3:a:nicmx:fort-validator:1.6.6:*:*:*:*:*:*:*".to_string(),
                "cpe:2.3:a:nicmx:fort_validator:1.6.6:*:*:*:*:*:*:*".to_string(),
            ]
        );
    }

    #[test]
    fn fort_validator_detection_is_case_and_separator_insensitive() {
        for name in ["Fort", "FORT-VALIDATOR", "Fort_Validator"] {
            let package = PackageInfo {
                name: name.to_string(),
                version: "1.6.6".to_string(),
                distributor: "unknown".to_string(),
                source_name: String::new(),
            };

            assert!(get_validator_cpes(&package).is_some(), "{name}");
        }
    }

    #[test]
    fn routinator_keeps_its_existing_cpe() {
        let package = PackageInfo {
            name: "routinator".to_string(),
            version: "0.15.2".to_string(),
            distributor: "nlnetlabs".to_string(),
            source_name: "routinator".to_string(),
        };

        assert_eq!(
            get_validator_cpes(&package).unwrap(),
            vec!["cpe:2.3:a:nlnetlabs:routinator:0.15.2:*:*:*:*:*:*:*".to_string()]
        );
    }
}
