use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use version_compare::{Cmp, compare};

use crate::{
    cpe::{
        apps::{
            PackageInfo, PackageManager, find_installed_apps, find_routinator_by_cargo,
            normalize_version,
        },
        builder::validator_cpes,
    },
    nvd,
};

const ROUTINATOR_ADVISORIES_URL: &str =
    "https://www.nlnetlabs.nl/projects/routinator/security-advisories/";
const FORT_ADVISORIES_URL: &str = "https://nicmx.github.io/FORT-validator/CVE.html";
const OSV_QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const SCAN_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityFinding {
    pub id: String,
    pub source: String,
    pub product: String,
    pub version: String,
    pub base_score: f64,
    pub severity: String,
    pub status: String,
    pub advisory_url: String,
    pub evidence: String,
    pub description: String,
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub findings: Vec<SecurityFinding>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
struct ValidatorInstall {
    product: String,
    version: String,
    binary: Option<PathBuf>,
    package: PackageInfo,
    deployment: String,
    version_source: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanSnapshot {
    schema_version: u32,
    installations: Vec<InstallationSnapshot>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstallationSnapshot {
    product: String,
    version: String,
    package: PackageSnapshot,
    deployment: String,
    version_source: String,
    #[serde(default)]
    dependencies: Option<Vec<CrateDependency>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PackageSnapshot {
    name: String,
    version: String,
    distributor: String,
    source_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionRange {
    minimum: Option<String>,
    maximum: Option<String>,
    exact: Option<String>,
    wildcard_prefix: Option<String>,
}

#[derive(Debug, Clone)]
struct Advisory {
    id: String,
    product: String,
    summary: String,
    description: String,
    fixed_version: Option<String>,
    remediation: String,
    condition: Option<String>,
    url: String,
    ranges: Vec<VersionRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct CrateDependency {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<Option<OsvPackageResult>>,
}

#[derive(Debug, Deserialize)]
struct OsvPackageResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

pub async fn scan(nvd_key: Option<&str>) -> Result<ScanResult, String> {
    validate_snapshot(collect_snapshot()?, nvd_key).await
}

pub fn export_snapshot(path: &Path) -> Result<(usize, Vec<String>), String> {
    let snapshot = collect_snapshot()?;
    let installation_count = snapshot.installations.len();
    let warnings = snapshot.warnings.clone();
    let contents = serde_json::to_vec_pretty(&snapshot)
        .map_err(|error| format!("Could not serialize scan snapshot: {error}"))?;
    fs::write(path, contents)
        .map_err(|error| format!("Could not write scan snapshot {}: {error}", path.display()))?;
    Ok((installation_count, warnings))
}

pub async fn scan_from_snapshot(
    path: &Path,
    nvd_key: Option<&str>,
) -> Result<ScanResult, String> {
    let contents = fs::read(path)
        .map_err(|error| format!("Could not read scan snapshot {}: {error}", path.display()))?;
    let snapshot = serde_json::from_slice(&contents)
        .map_err(|error| format!("Invalid scan snapshot {}: {error}", path.display()))?;
    validate_snapshot(snapshot, nvd_key).await
}

fn collect_snapshot() -> Result<ScanSnapshot, String> {
    let (installs, mut warnings) = find_validator_installs()?;
    let mut installations = Vec::with_capacity(installs.len());

    for install in installs {
        let dependencies = match dependency_inventory(&install) {
            Ok(Some(packages)) => Some(packages),
            Ok(None) => {
                warnings.push(format!(
                    "Could not determine Rust dependencies for {} {}: no matching Cargo.lock or cargo-auditable metadata was found.",
                    install.product, install.version
                ));
                None
            }
            Err(error) => {
                warnings.push(format!(
                    "Could not read Rust dependency inventory for {}: {error}",
                    install.product
                ));
                None
            }
        };

        installations.push(InstallationSnapshot {
            product: install.product,
            version: install.version,
            package: PackageSnapshot {
                name: install.package.name,
                version: install.package.version,
                distributor: install.package.distributor,
                source_name: install.package.source_name,
            },
            deployment: install.deployment,
            version_source: install.version_source,
            dependencies,
        });
    }

    Ok(ScanSnapshot {
        schema_version: SCAN_SNAPSHOT_SCHEMA_VERSION,
        installations,
        warnings,
    })
}

impl InstallationSnapshot {
    fn to_install(&self) -> ValidatorInstall {
        ValidatorInstall {
            product: self.product.clone(),
            version: self.version.clone(),
            binary: None,
            package: PackageInfo {
                name: self.package.name.clone(),
                version: self.package.version.clone(),
                distributor: self.package.distributor.clone(),
                source_name: self.package.source_name.clone(),
                binary_path: None,
            },
            deployment: self.deployment.clone(),
            version_source: self.version_source.clone(),
        }
    }
}

async fn validate_snapshot(
    snapshot: ScanSnapshot,
    nvd_key: Option<&str>,
) -> Result<ScanResult, String> {
    if snapshot.schema_version != SCAN_SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "Unsupported scan snapshot schema version {}; expected {}.",
            snapshot.schema_version, SCAN_SNAPSHOT_SCHEMA_VERSION
        ));
    }
    if snapshot.installations.is_empty() {
        return Err("The scan snapshot contains no supported validator installations.".to_string());
    }
    if snapshot
        .installations
        .iter()
        .any(|install| !matches!(install.product.as_str(), "routinator" | "fort"))
    {
        return Err("The scan snapshot contains an unsupported validator product.".to_string());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Could not create HTTP client: {error}"))?;
    let installs = snapshot
        .installations
        .iter()
        .map(InstallationSnapshot::to_install)
        .collect::<Vec<_>>();
    for install in &installs {
        println!(
            "[INFO] Detected {} {} at {} (version source: {}).",
            install.product, install.version, install.deployment, install.version_source
        );
    }
    let mut result = ScanResult {
        warnings: snapshot.warnings.clone(),
        ..ScanResult::default()
    };
    let mut findings = Vec::new();

    println!("[INFO] Fetching official Routinator and Fort advisories...");
    let mut advisories = fetch_routinator_advisories(&client).await?;
    advisories.extend(fetch_fort_advisories(&client).await?);

    for install in &installs {
        for advisory in advisories
            .iter()
            .filter(|advisory| advisory.product == install.product)
        {
            if !advisory
                .ranges
                .iter()
                .any(|range| range.matches(&install.version))
            {
                continue;
            }

            let condition = advisory
                .condition
                .as_deref()
                .map(|value| format!(" Advisory condition: {value}"))
                .unwrap_or_default();
            let remediation = if advisory.remediation.is_empty() {
                advisory
                    .fixed_version
                    .as_deref()
                    .map(|version| format!(" Vendor fix: {version}."))
                    .unwrap_or_default()
            } else {
                format!(" Vendor remediation: {}", advisory.remediation)
            };
            findings.push(SecurityFinding {
                id: advisory.id.clone(),
                source: "Vendor advisory".to_string(),
                product: install.product.clone(),
                version: install.version.clone(),
                base_score: 0.0,
                severity: "UNKNOWN".to_string(),
                status: "Affected-version match; exploitability not confirmed.".to_string(),
                advisory_url: advisory.url.clone(),
                evidence: format!(
                    "{}{}{} Detected at {} (version source: {}).",
                    advisory.summary,
                    remediation,
                    condition,
                    install.deployment,
                    install.version_source
                ),
                description: advisory.description.clone(),
            });
        }
    }

    let dependencies = snapshot
        .installations
        .iter()
        .filter_map(|installation| {
            installation.dependencies.as_ref().map(|packages| {
                (installation.product.clone(), packages.clone())
            })
        })
        .collect::<Vec<_>>();
    for (product, packages) in dependencies {
        match query_osv(&client, &product, &packages).await {
            Ok(osv_findings) => findings.extend(osv_findings),
            Err(error) => result.warnings.push(format!(
                "Could not check {product} dependencies with OSV: {error}"
            )),
        }
    }

    if let Some(key) = nvd_key.filter(|key| !key.trim().is_empty()) {
        let cpes = installs
            .iter()
            .flat_map(|install| validator_cpes(&install.package))
            .collect::<Vec<_>>();
        if !cpes.is_empty() {
            let key_regex = Regex::new(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            )
            .map_err(|error| error.to_string())?;
            if !key_regex.is_match(key.trim()) {
                result.warnings.push(
                    "NVD cross-check skipped because the provided API key is not a valid UUID."
                        .to_string(),
                );
            } else {
                println!("[INFO] Cross-checking Routinator and Fort with NVD...");
                match nvd::check::check(cpes, key.to_string()).await {
                    Ok(nvd_findings) => {
                        findings.extend(nvd_findings.into_values().flatten().map(|finding| {
                            let deployments = installs
                                .iter()
                                .filter(|install| {
                                    products_match(&install.product, &finding.product)
                                        && install.version == finding.version
                                })
                                .map(|install| {
                                    format!(
                                        "{} (version source: {})",
                                        install.deployment, install.version_source
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join("; ");
                            let evidence = if deployments.is_empty() {
                                finding.vendor
                            } else {
                                format!("{} Detected at {deployments}.", finding.vendor)
                            };
                            SecurityFinding {
                                id: finding.cve_id,
                                source: "NVD".to_string(),
                                product: finding.product,
                                version: finding.version,
                                base_score: finding.base_score,
                                severity: finding.base_severity,
                                status:
                                    "NVD configuration/version match; exploitability not confirmed."
                                        .to_string(),
                                advisory_url: String::new(),
                                evidence,
                                description: finding.description,
                            }
                        }));
                    }
                    Err(error) => result
                        .warnings
                        .push(format!("NVD cross-check failed: {error}")),
                }
            }
        }
    } else {
        result
            .warnings
            .push("NVD cross-check skipped because no API key was provided.".to_string());
    }

    result.findings = merge_findings(findings);
    Ok(result)
}

fn find_validator_installs() -> Result<(Vec<ValidatorInstall>, Vec<String>), String> {
    let mut warnings = Vec::new();
    let mut packages = match PackageManager::detect_package_manager() {
        Some(package_manager) => match find_installed_apps(package_manager) {
            Some(packages) => packages,
            None => {
                warnings.push("Could not read the host package inventory.".to_string());
                Vec::new()
            }
        },
        None => {
            warnings.push(
                "No supported host package manager (APT, DNF, or APK) was detected.".to_string(),
            );
            Vec::new()
        }
    };
    let (cargo_packages, cargo_warnings) = find_routinator_by_cargo();
    packages.extend(cargo_packages);
    warnings.extend(cargo_warnings);
    let mut installs = Vec::new();
    let mut seen = HashSet::new();
    for package in packages {
        let normalized_name = package.name.to_ascii_lowercase().replace('_', "-");
        let normalized_source = package.source_name.to_ascii_lowercase().replace('_', "-");
        let product = if package.distributor.eq_ignore_ascii_case("nlnetlabs")
            || normalized_name.contains("routinator")
            || normalized_source == "routinator"
        {
            "routinator"
        } else if matches!(normalized_name.as_str(), "fort" | "fort-validator")
            || matches!(normalized_source.as_str(), "fort" | "fort-validator")
        {
            "fort"
        } else {
            continue;
        };

        let version = normalize_version(&package.version);
        let executable_names = if product == "routinator" {
            &["routinator"][..]
        } else {
            &["fort", "fort-validator"][..]
        };
        let binary = package
            .binary_path
            .clone()
            .or_else(|| find_executable(executable_names));
        let install_path = binary
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| "host package inventory".to_string());
        if !seen.insert((product.to_string(), version.clone(), install_path)) {
            continue;
        }
        let deployment = binary
            .as_ref()
            .map(|path| format!("host binary {}", path.display()))
            .unwrap_or_else(|| "host package inventory".to_string());
        installs.push(ValidatorInstall {
            product: product.to_string(),
            version,
            binary,
            package,
            deployment,
            version_source: "host package inventory".to_string(),
        });
    }

    match find_fort_binary_install() {
        Ok(Some(install)) => {
            println!(
                "[INFO] Fort executable probe found {} reporting version {}.",
                install
                    .binary
                    .as_deref()
                    .map_or_else(|| "<unknown>".to_string(), |path| path.display().to_string()),
                install.version
            );
            merge_fort_binary_install(&mut installs, install);
        }
        Ok(None) => println!(
            "[INFO] Fort executable probe found no fort or fort-validator in PATH or standard install locations."
        ),
        Err(warning) => warnings.push(warning),
    }

    let (container_installs, container_warnings) = find_container_installs();
    installs.extend(container_installs);
    warnings.extend(container_warnings);

    if installs.is_empty() {
        let details = if warnings.is_empty() {
            String::new()
        } else {
            format!(" {}", warnings.join(" "))
        };
        return Err(format!(
            "No Routinator or Fort installation was detected.{details}"
        ));
    }
    Ok((installs, warnings))
}

fn merge_fort_binary_install(
    installs: &mut Vec<ValidatorInstall>,
    binary_install: ValidatorInstall,
) {
    let binary_path = binary_install.binary.clone();
    let mut matched_package = false;
    for install in installs.iter_mut().filter(|install| {
        install.product == "fort" && install.binary == binary_path
    }) {
        install.version = binary_install.version.clone();
        install.package.version = binary_install.package.version.clone();
        install.version_source = binary_install.version_source.clone();
        matched_package = true;
    }

    if !matched_package {
        installs.push(binary_install);
    }
}

fn find_fort_binary_install() -> Result<Option<ValidatorInstall>, String> {
    let standard_binary = Path::new("/usr/local/bin/fort");
    let binary = standard_binary
        .is_file()
        .then(|| standard_binary.to_path_buf())
        .or_else(|| find_executable(&["fort", "fort-validator"]));
    let Some(binary) = binary else {
        return Ok(None);
    };
    let output = Command::new(&binary)
        .arg("-V")
        .output()
        .map_err(|error| {
            format!(
                "Could not determine Fort version from {}: {error}",
                binary.display()
            )
        })?;
    let version_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let Some(version) = parse_fort_version(&version_output) else {
        return Err(format!(
            "Could not parse Fort version reported by {} (exit status: {}). Output: {}",
            binary.display(),
            output.status,
            version_output.trim()
        ));
    };

    Ok(Some(ValidatorInstall {
        product: "fort".to_string(),
        version: version.clone(),
        binary: Some(binary.clone()),
        package: PackageInfo {
            name: "fort".to_string(),
            version,
            distributor: "nicmx".to_string(),
            source_name: "fort".to_string(),
            binary_path: Some(binary.clone()),
        },
        deployment: format!("host binary {}", binary.display()),
        version_source: "fort -V".to_string(),
    }))
}

fn parse_fort_version(output: &str) -> Option<String> {
    let version_regex =
        Regex::new(r"(?im)^\s*fort\s+([0-9]+(?:\.[0-9]+)+(?:[.-][0-9A-Za-z.-]+)?)").ok()?;
    version_regex
        .captures(output)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().to_string())
}

fn products_match(left: &str, right: &str) -> bool {
    let normalize = |product: &str| {
        let normalized = product
            .to_ascii_lowercase()
            .replace('-', "")
            .replace('_', "");
        if normalized.contains("routinator") {
            "routinator"
        } else if normalized.contains("fort") {
            "fort"
        } else {
            ""
        }
    };
    normalize(left) == normalize(right) && !normalize(left).is_empty()
}

fn find_executable(names: &[&str]) -> Option<PathBuf> {
    let mut directories = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    directories.extend([
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/local/sbin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/sbin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/opt/routinator/bin"),
    ]);
    if let Ok(entries) = fs::read_dir("/opt") {
        directories.extend(entries.flatten().filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|file_type| file_type.is_dir())
                .map(|_| entry.path().join("bin"))
        }));
    }
    if let Some(cargo_home) = env::var_os("CARGO_HOME") {
        directories.push(PathBuf::from(cargo_home).join("bin"));
    }
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        directories.extend(passwd.lines().filter_map(|line| {
            let home = line.split(':').nth(5)?;
            (!home.is_empty() && home != "/nonexistent")
                .then(|| PathBuf::from(home).join(".cargo/bin"))
        }));
    }

    directories.dedup();
    directories.into_iter().find_map(|directory| {
        names
            .iter()
            .map(|name| directory.join(name))
            .find(|path| path.is_file())
    })
}

fn find_container_installs() -> (Vec<ValidatorInstall>, Vec<String>) {
    let mut installs = Vec::new();
    let mut warnings = Vec::new();

    for engine in ["docker", "podman"] {
        let image_list = match Command::new(engine)
            .args(["image", "ls", "--no-trunc", "--quiet"])
            .output()
        {
            Ok(output) if output.status.success() => output,
            Ok(output) => {
                warnings.push(format!(
                    "Could not list local {engine} images: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                warnings.push(format!("Could not query {engine} images: {error}"));
                continue;
            }
        };

        let (running_containers, running_warning) = running_container_names(engine);
        if let Some(warning) = running_warning {
            warnings.push(warning);
        }
        let image_list_text = String::from_utf8_lossy(&image_list.stdout);
        let image_ids = image_list_text
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect::<HashSet<_>>();
        for image_id in image_ids {
            let inspect = match Command::new(engine)
                .args(["image", "inspect", image_id])
                .output()
            {
                Ok(output) if output.status.success() => output,
                Ok(output) => {
                    warnings.push(format!(
                        "Could not inspect {engine} image {image_id}: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                    continue;
                }
                Err(error) => {
                    warnings.push(format!("Could not inspect {engine} image {image_id}: {error}"));
                    continue;
                }
            };
            let Ok(value) = serde_json::from_slice::<Value>(&inspect.stdout) else {
                warnings.push(format!(
                    "Could not parse metadata for {engine} image {image_id}."
                ));
                continue;
            };
            let image = value
                .as_array()
                .and_then(|images| images.first())
                .unwrap_or(&value);
            match validator_install_from_image(engine, image, &running_containers) {
                Ok(Some(install)) => installs.push(install),
                Ok(None) => {}
                Err(warning) => warnings.push(warning),
            }
        }
    }

    (installs, warnings)
}

fn running_container_names(engine: &str) -> (HashMap<String, Vec<String>>, Option<String>) {
    let output = match Command::new(engine)
        .args(["ps", "--format", "{{.Image}}|{{.Names}}"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return (
                HashMap::new(),
                Some(format!(
                    "Could not list running {engine} containers: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
            );
        }
        Err(error) => {
            return (
                HashMap::new(),
                Some(format!("Could not list running {engine} containers: {error}")),
            );
        }
    };

    let output_text = String::from_utf8_lossy(&output.stdout);
    let mut containers = HashMap::<String, Vec<String>>::new();
    for line in output_text.lines() {
        let Some((image, name)) = line.split_once('|') else {
            continue;
        };
        containers
            .entry(image.to_string())
            .or_default()
            .push(name.to_string());
    }
    (containers, None)
}

fn validator_install_from_image(
    engine: &str,
    image: &Value,
    running_containers: &HashMap<String, Vec<String>>,
) -> Result<Option<ValidatorInstall>, String> {
    let Some(config) = image.get("Config") else {
        return Ok(None);
    };
    let labels = config.get("Labels").and_then(Value::as_object);
    let references = image
        .get("RepoTags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|reference| !reference.ends_with(":<none>"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let command = ["Entrypoint", "Cmd"]
        .into_iter()
        .filter_map(|field| config.get(field).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let label_text = [
        "org.opencontainers.image.title",
        "org.opencontainers.image.ref.name",
        "org.label-schema.name",
        "name",
    ]
    .into_iter()
    .filter_map(|key| labels.and_then(|labels| labels.get(key)))
    .filter_map(Value::as_str)
    .collect::<Vec<_>>()
    .join(" ");
    let identity = format!("{} {command} {label_text}", references.join(" "));
    let normalized = identity.to_ascii_lowercase();
    let command_names = command
        .split_whitespace()
        .filter_map(|argument| Path::new(argument).file_name())
        .filter_map(|name| name.to_str())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let product = if contains_product_token(&normalized, "routinator")
        || command_names
            .iter()
            .any(|name| name.as_str() == "routinator")
    {
        "routinator"
    } else if contains_product_token(&normalized, "fort")
        || contains_product_token(&normalized, "fortvalidator")
        || command_names
            .iter()
            .any(|name| matches!(name.as_str(), "fort" | "fort-validator"))
    {
        "fort"
    } else {
        return Ok(None);
    };

    let labeled_version = labels
        .and_then(|labels| labels.get("org.opencontainers.image.version"))
        .and_then(Value::as_str)
        .and_then(parse_image_version);
    let version_source = if labeled_version.is_some() {
        "OCI image version label"
    } else {
        "image tag"
    };
    let tagged_version = references.iter().find_map(|reference| {
        reference
            .rsplit_once(':')
            .and_then(|(_, tag)| parse_image_version(tag))
    });
    let version = labeled_version.or(tagged_version).ok_or_else(|| {
        format!(
            "Could not determine the version of {engine} image {} from its OCI label or tag.",
            references.join(", ")
        )
    })?;
    let image_id = image
        .get("Id")
        .and_then(Value::as_str)
        .unwrap_or("unknown image id");
    let reference_text = if references.is_empty() {
        image_id.to_string()
    } else {
        references.join(", ")
    };
    let running_names = running_containers
        .get(image_id)
        .into_iter()
        .flatten()
        .chain(
            references
                .iter()
                .filter_map(|reference| running_containers.get(reference))
                .flatten(),
        )
        .cloned()
        .collect::<Vec<_>>();
    let deployment = if running_names.is_empty() {
        format!("{engine} image {reference_text}")
    } else {
        format!(
            "{engine} image {reference_text} (running containers: {})",
            running_names.join(", ")
        )
    };
    let (name, distributor) = if product == "routinator" {
        ("routinator", "nlnetlabs")
    } else {
        ("fort-validator", "nicmx")
    };
    let package = PackageInfo {
        name: name.to_string(),
        version: version.clone(),
        distributor: distributor.to_string(),
        source_name: name.to_string(),
        binary_path: None,
    };

    Ok(Some(ValidatorInstall {
        product: product.to_string(),
        version,
        binary: None,
        package,
        deployment,
        version_source: version_source.to_string(),
    }))
}

fn contains_product_token(identity: &str, product: &str) -> bool {
    identity
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| token == product)
}

fn parse_image_version(value: &str) -> Option<String> {
    let regex = Regex::new(r"(?i)^v?(\d+\.\d+(?:\.\d+)?(?:[-+][0-9a-z.-]+)?)$").ok()?;
    regex
        .captures(value.trim())
        .and_then(|captures| captures.get(1))
        .map(|version| version.as_str().to_string())
}

fn find_lockfile(binary: &Path, product: &str, version: &str) -> Option<PathBuf> {
    let mut directory = binary.parent()?;
    for _ in 0..6 {
        let lockfile = directory.join("Cargo.lock");
        if lockfile.is_file() && lockfile_matches_product(&lockfile, product, version) {
            return Some(lockfile);
        }
        directory = directory.parent()?;
    }
    None
}

fn lockfile_matches_product(path: &Path, product: &str, version: &str) -> bool {
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(lockfile) = contents.parse::<toml::Value>() else {
        return false;
    };
    lockfile
        .get("package")
        .and_then(toml::Value::as_array)
        .is_some_and(|packages| {
            packages.iter().any(|package| {
                package.get("source").is_none()
                    && package
                        .get("name")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|name| package_matches_product(name, product))
                    && package
                        .get("version")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|package_version| {
                            compare(package_version, version) == Ok(Cmp::Eq)
                        })
            })
        })
}

fn package_matches_product(name: &str, product: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    match product {
        "routinator" => normalized == "routinator",
        "fort" => matches!(normalized.as_str(), "fort" | "fort-validator"),
        _ => false,
    }
}

fn dependency_inventory(
    install: &ValidatorInstall,
) -> Result<Option<Vec<CrateDependency>>, String> {
    if let Some(binary) = &install.binary {
        let auditable_result = auditable_dependencies(binary, &install.product, &install.version);
        match auditable_result {
            Ok(Some(dependencies)) => return Ok(Some(dependencies)),
            Ok(None) => {}
            Err(error) => {
                if let Some(lockfile) = find_lockfile(binary, &install.product, &install.version) {
                    return dependencies_from_lockfile(&lockfile).map(Some);
                }
                return Err(error);
            }
        }
        if let Some(lockfile) = find_lockfile(binary, &install.product, &install.version) {
            return dependencies_from_lockfile(&lockfile).map(Some);
        }
    }
    Ok(None)
}

fn auditable_dependencies(
    binary: &Path,
    product: &str,
    version: &str,
) -> Result<Option<Vec<CrateDependency>>, String> {
    let json = match auditable_info::json_from_file(binary, auditable_info::Limits::default()) {
        Ok(json) => json,
        Err(_) => return Ok(None),
    };
    let value: Value =
        serde_json::from_str(&json).map_err(|error| format!("invalid embedded SBOM: {error}"))?;
    let Some(packages) = value.get("packages").and_then(Value::as_array) else {
        return Err("embedded SBOM has no package list".to_string());
    };
    let has_validator_root = packages.iter().any(|package| {
        package.get("root").and_then(Value::as_bool) == Some(true)
            && package
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| package_matches_product(name, product))
            && package
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|package_version| compare(package_version, version) == Ok(Cmp::Eq))
    });
    if !has_validator_root {
        return Ok(None);
    }
    Ok(Some(
        packages
            .iter()
            .filter(|package| is_registry_source(package.get("source")))
            .filter_map(|package| {
                Some(CrateDependency {
                    name: package.get("name")?.as_str()?.to_string(),
                    version: package.get("version")?.as_str()?.to_string(),
                })
            })
            .collect(),
    ))
}

fn is_registry_source(source: Option<&Value>) -> bool {
    match source {
        Some(Value::String(source)) => matches!(source.as_str(), "CratesIo" | "Registry"),
        Some(Value::Object(source)) => source.contains_key("Registry"),
        _ => false,
    }
}

fn dependencies_from_lockfile(path: &Path) -> Result<Vec<CrateDependency>, String> {
    let contents =
        fs::read_to_string(path).map_err(|error| format!("could not read Cargo.lock: {error}"))?;
    let lockfile: toml::Value = contents
        .parse()
        .map_err(|error| format!("could not parse Cargo.lock: {error}"))?;
    let packages = lockfile
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "Cargo.lock has no package list".to_string())?;

    Ok(packages
        .iter()
        .filter(|package| {
            package
                .get("source")
                .and_then(toml::Value::as_str)
                .is_some_and(|source| {
                    source.starts_with("registry+") || source.starts_with("sparse+")
                })
        })
        .filter_map(|package| {
            Some(CrateDependency {
                name: package.get("name")?.as_str()?.to_string(),
                version: package.get("version")?.as_str()?.to_string(),
            })
        })
        .collect())
}

async fn query_osv(
    client: &reqwest::Client,
    product: &str,
    packages: &[CrateDependency],
) -> Result<Vec<SecurityFinding>, String> {
    let mut findings = Vec::new();
    for batch in packages.chunks(1000) {
        if batch.is_empty() {
            continue;
        }
        let request = json!({
            "queries": batch.iter().map(|dependency| json!({
                "package": {
                    "name": dependency.name.as_str(),
                    "ecosystem": "crates.io"
                },
                "version": dependency.version.as_str()
            })).collect::<Vec<_>>()
        });
        let response = client
            .post(OSV_QUERY_BATCH_URL)
            .json(&request)
            .send()
            .await
            .map_err(|error| format!("OSV dependency query failed: {error}"))?
            .error_for_status()
            .map_err(|error| format!("OSV dependency query returned an error: {error}"))?
            .json::<OsvBatchResponse>()
            .await
            .map_err(|error| format!("Could not parse OSV response: {error}"))?;

        if response.results.len() != batch.len() {
            return Err(
                "OSV returned a result count that does not match the query batch.".to_string(),
            );
        }
        for (dependency, package_result) in batch.iter().zip(response.results) {
            let Some(package_result) = package_result else {
                continue;
            };
            for vulnerability in package_result.vulns {
                let osv_id = vulnerability.id.clone();
                let id = vulnerability
                    .aliases
                    .iter()
                    .find(|alias| alias.starts_with("CVE-"))
                    .cloned()
                    .unwrap_or_else(|| osv_id.clone());
                let description = vulnerability
                    .details
                    .or(vulnerability.summary)
                    .unwrap_or_else(|| {
                        "OSV reported this dependency version as affected.".to_string()
                    });
                findings.push(SecurityFinding {
                    id,
                    source: format!("OSV ({osv_id})"),
                    product: format!("{product} dependency: {}", dependency.name),
                    version: dependency.version.clone(),
                    base_score: 0.0,
                    severity: "UNKNOWN".to_string(),
                    status:
                        "Affected dependency version reported by OSV; exploitability not confirmed."
                            .to_string(),
                    advisory_url: format!("https://osv.dev/vulnerability/{}", vulnerability.id),
                    evidence: format!("pkg:cargo/{}@{}", dependency.name, dependency.version),
                    description,
                });
            }
        }
    }
    Ok(findings)
}

async fn fetch_routinator_advisories(client: &reqwest::Client) -> Result<Vec<Advisory>, String> {
    let html = fetch_text(
        client,
        ROUTINATOR_ADVISORIES_URL,
        "Routinator advisory index",
    )
    .await?;
    let link_regex = Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*["']([^"']+\.txt)["'][^>]*>(.*?)</a>"#)
        .map_err(|error| error.to_string())?;
    let id_regex = Regex::new(r"CVE-\d{4}-\d+").map_err(|error| error.to_string())?;
    let mut advisories = Vec::new();

    for link in link_regex.captures_iter(&html) {
        let href = link.get(1).map(|value| value.as_str()).unwrap_or_default();
        let Some(id) = id_regex.find(href).map(|value| value.as_str()) else {
            continue;
        };
        let url = reqwest::Url::parse(ROUTINATOR_ADVISORIES_URL)
            .and_then(|base| base.join(href))
            .map_err(|error| format!("Invalid Routinator advisory URL: {error}"))?
            .to_string();
        let text = fetch_text(client, &url, id).await?;
        if let Some(advisory) = parse_routinator_advisory(id, &url, &text)? {
            advisories.push(advisory);
        }
    }
    Ok(advisories)
}

async fn fetch_fort_advisories(client: &reqwest::Client) -> Result<Vec<Advisory>, String> {
    let html = fetch_text(client, FORT_ADVISORIES_URL, "Fort advisory page").await?;
    let advisories = parse_fort_advisories(&html)?;
    println!(
        "[INFO] Parsed {} Fort advisories with affected-version ranges.",
        advisories.len()
    );
    Ok(advisories)
}

fn parse_fort_advisories(html: &str) -> Result<Vec<Advisory>, String> {
    let heading_regex = Regex::new(r"(?is)<h[1-6]\b[^>]*>\s*(CVE-\d{4}-\d+)\s*</h[1-6]>")
        .map_err(|error| error.to_string())?;
    let headings = heading_regex
        .captures_iter(&html)
        .filter_map(|capture| {
            let full = capture.get(0)?;
            let id = capture.get(1)?.as_str().to_string();
            Some((full.start(), full.end(), id))
        })
        .collect::<Vec<_>>();
    let mut advisories = Vec::new();

    for (index, (_, body_start, id)) in headings.iter().enumerate() {
        let body_end = headings
            .get(index + 1)
            .map(|heading| heading.0)
            .unwrap_or(html.len());
        let section = html.get(*body_start..body_end).unwrap_or_default();
        let plain_text = html_to_text(section)?;
        if let Some(advisory) = parse_fort_advisory(&id, FORT_ADVISORIES_URL, &plain_text)? {
            advisories.push(advisory);
        }
    }
    Ok(advisories)
}

async fn fetch_text(
    client: &reqwest::Client,
    url: &str,
    description: &str,
) -> Result<String, String> {
    client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("Could not fetch {description}: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Could not fetch {description}: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Could not read {description}: {error}"))
}

fn parse_routinator_advisory(id: &str, url: &str, text: &str) -> Result<Option<Advisory>, String> {
    let affected = section_between(text, "== Affected products", "==");
    let ranges = parse_routinator_ranges(affected)?;
    if ranges.is_empty() {
        return Ok(None);
    }
    let summary = section_between(text, "== Summary", "==").trim().to_string();
    let description = section_between(text, "== Description", "==")
        .trim()
        .to_string();
    let solution = section_between(text, "== Solution", "==");
    let fix_regex =
        Regex::new(r"(?i)Install\s+Routinator\s+([0-9]+(?:\.[0-9]+)+)\s+or\s+(?:later|newer)")
            .map_err(|error| error.to_string())?;
    let fixed_version = fix_regex
        .captures(solution)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().to_string());

    Ok(Some(Advisory {
        id: id.to_string(),
        product: "routinator".to_string(),
        summary,
        description,
        fixed_version,
        remediation: solution.trim().to_string(),
        condition: extract_condition(text),
        url: url.to_string(),
        ranges,
    }))
}

fn section_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let Some(start_index) = text.find(start) else {
        return "";
    };
    let content_start = start_index + start.len();
    let content = &text[content_start..];
    match content.find(end) {
        Some(end_index) => &content[..end_index],
        None => content,
    }
}

fn parse_routinator_ranges(section: &str) -> Result<Vec<VersionRange>, String> {
    let mut ranges = Vec::new();
    let bounded = Regex::new(
        r"(?i)Routinator\s+([0-9]+(?:\.[0-9]+)+)\s+up to and including\s+([0-9]+(?:\.[0-9]+)+)",
    )
    .map_err(|error| error.to_string())?;
    for capture in bounded.captures_iter(section) {
        ranges.push(VersionRange {
            minimum: capture.get(1).map(|value| value.as_str().to_string()),
            maximum: capture.get(2).map(|value| value.as_str().to_string()),
            exact: None,
            wildcard_prefix: None,
        });
    }

    let upper_bound = Regex::new(r"(?i)Routinator\s+up to and including\s+([0-9]+(?:\.[0-9]+)+)")
        .map_err(|error| error.to_string())?;
    for capture in upper_bound.captures_iter(section) {
        ranges.push(VersionRange {
            minimum: None,
            maximum: capture.get(1).map(|value| value.as_str().to_string()),
            exact: None,
            wildcard_prefix: None,
        });
    }

    let wildcard =
        Regex::new(r"(?i)Routinator\s+([0-9]+\.[0-9]+)\.\*").map_err(|error| error.to_string())?;
    for capture in wildcard.captures_iter(section) {
        ranges.push(VersionRange {
            minimum: None,
            maximum: None,
            exact: None,
            wildcard_prefix: capture.get(1).map(|value| format!("{}.", value.as_str())),
        });
    }
    Ok(ranges)
}

fn parse_fort_advisory(id: &str, url: &str, text: &str) -> Result<Option<Advisory>, String> {
    let patch_index = text
        .to_ascii_lowercase()
        .find("patch")
        .unwrap_or(text.len());
    let affected_text = &text[..patch_index];
    let ranges = parse_fort_ranges(affected_text)?;
    if ranges.is_empty() {
        return Ok(None);
    }
    let summary = affected_text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .to_string();
    let fix_regex = Regex::new(r"(?i)(?:released in Fort|Fort release)\s+([0-9]+(?:\.[0-9]+)+)")
        .map_err(|error| error.to_string())?;
    let fixed_version = fix_regex
        .captures(text)
        .filter(|capture| {
            let prefix = &text[..capture
                .get(0)
                .map(|value| value.start())
                .unwrap_or_default()];
            !prefix.to_ascii_lowercase().contains("scheduled")
        })
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().to_string());

    Ok(Some(Advisory {
        id: id.to_string(),
        product: "fort".to_string(),
        summary,
        description: text.trim().to_string(),
        fixed_version,
        remediation: text[patch_index..].trim().to_string(),
        condition: extract_condition(text),
        url: url.to_string(),
        ranges,
    }))
}

fn parse_fort_ranges(text: &str) -> Result<Vec<VersionRange>, String> {
    let mut ranges = Vec::new();
    let through = Regex::new(r"(?i)\bFort\s+([0-9]+(?:\.[0-9]+)+)\s*-\s*[.,;]")
        .map_err(|error| error.to_string())?;
    for capture in through.captures_iter(text) {
        ranges.push(VersionRange {
            minimum: None,
            maximum: capture.get(1).map(|value| value.as_str().to_string()),
            exact: None,
            wildcard_prefix: None,
        });
    }

    let exact =
        Regex::new(r"(?i)\bFort\s+([0-9]+(?:\.[0-9]+)+(?:\s*(?:,|and)\s*[0-9]+(?:\.[0-9]+)+)*)")
            .map_err(|error| error.to_string())?;
    for capture in exact.captures_iter(text) {
        let matched_end = capture.get(0).map(|value| value.end()).unwrap_or_default();
        if text[matched_end..].trim_start().starts_with('-') {
            continue;
        }
        let versions = capture
            .get(1)
            .map(|value| value.as_str())
            .unwrap_or_default();
        let split = Regex::new(r"(?i)\s*(?:,|and)\s*").map_err(|error| error.to_string())?;
        for version in split
            .split(versions)
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            ranges.push(VersionRange {
                minimum: None,
                maximum: None,
                exact: Some(version.to_string()),
                wildcard_prefix: None,
            });
        }
    }
    Ok(ranges)
}

fn html_to_text(html: &str) -> Result<String, String> {
    let tags = Regex::new(r"(?s)<[^>]*>").map_err(|error| error.to_string())?;
    let without_tags = tags.replace_all(html, " ");
    let text = without_tags
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    let whitespace = Regex::new(r"\s+").map_err(|error| error.to_string())?;
    Ok(whitespace.replace_all(&text, " ").trim().to_string())
}

fn extract_condition(text: &str) -> Option<String> {
    let mut sentence_start = 0;
    let mut sentences = Vec::new();
    let characters = text.char_indices().collect::<Vec<_>>();
    for (index, (position, character)) in characters.iter().enumerate() {
        let version_dot = *character == '.'
            && index > 0
            && index + 1 < characters.len()
            && characters[index - 1].1.is_ascii_digit()
            && characters[index + 1].1.is_ascii_digit();
        if (*character == '.' && !version_dot) || *character == '\n' {
            sentences.push(&text[sentence_start..*position]);
            sentence_start = position + character.len_utf8();
        }
    }
    sentences.push(&text[sentence_start..]);
    sentences
        .into_iter()
        .map(str::trim)
        .find(|sentence| {
            let sentence = sentence.to_ascii_lowercase();
            sentence.contains("only affects")
                || sentence.contains("disabled by default")
                || sentence.contains("compiled with")
                || sentence.contains("only when")
                || sentence.contains("if enabled")
        })
        .map(str::to_string)
}

impl VersionRange {
    fn matches(&self, version: &str) -> bool {
        if let Some(exact) = &self.exact {
            return compare(version, exact) == Ok(Cmp::Eq);
        }
        if let Some(prefix) = &self.wildcard_prefix {
            return version.starts_with(prefix);
        }
        if let Some(minimum) = &self.minimum
            && !matches!(compare(version, minimum), Ok(Cmp::Gt | Cmp::Eq))
        {
            return false;
        }
        if let Some(maximum) = &self.maximum
            && !matches!(compare(version, maximum), Ok(Cmp::Lt | Cmp::Eq))
        {
            return false;
        }
        self.minimum.is_some() || self.maximum.is_some()
    }
}

fn merge_findings(findings: Vec<SecurityFinding>) -> Vec<SecurityFinding> {
    let mut merged = HashMap::<(String, String, String), SecurityFinding>::new();
    for finding in findings {
        let key = (
            finding.id.clone(),
            finding.product.clone(),
            finding.version.clone(),
        );
        if let Some(existing) = merged.get_mut(&key) {
            if !existing
                .source
                .split("; ")
                .any(|source| source == finding.source)
            {
                existing.source.push_str("; ");
                existing.source.push_str(&finding.source);
            }
            if existing.advisory_url.is_empty() && !finding.advisory_url.is_empty() {
                existing.advisory_url = finding.advisory_url;
            }
            if existing.description.is_empty() {
                existing.description = finding.description;
            }
            if existing.evidence.is_empty() {
                existing.evidence = finding.evidence;
            } else if !finding.evidence.is_empty() && !existing.evidence.contains(&finding.evidence)
            {
                existing.evidence.push_str("; ");
                existing.evidence.push_str(&finding.evidence);
            }
        } else {
            merged.insert(key, finding);
        }
    }
    let mut findings = merged.into_values().collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        (&left.id, &left.product, &left.version, &left.source).cmp(&(
            &right.id,
            &right.product,
            &right.version,
            &right.source,
        ))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fort_version_reported_by_binary() {
        assert_eq!(
            parse_fort_version("fort 1.6.2\n"),
            Some("1.6.2".to_string())
        );
        assert_eq!(
            parse_fort_version("fort 1.7.0.experimental\n"),
            Some("1.7.0.experimental".to_string())
        );
        assert_eq!(parse_fort_version("not a version"), None);
    }

    #[test]
    fn fort_binary_version_overrides_stale_package_version() {
        let fort_binary = PathBuf::from("/usr/local/bin/fort");
        let mut installs = vec![ValidatorInstall {
            product: "fort".to_string(),
            version: "1.7.0.experimental".to_string(),
            binary: Some(fort_binary.clone()),
            package: PackageInfo {
                name: "fort".to_string(),
                version: "1.7.0.experimental".to_string(),
                distributor: "nicmx".to_string(),
                source_name: "fort".to_string(),
                binary_path: None,
            },
            deployment: format!("host binary {}", fort_binary.display()),
            version_source: "host package inventory".to_string(),
        }];
        let detected_binary_install = ValidatorInstall {
            product: "fort".to_string(),
            version: "1.6.2".to_string(),
            binary: Some(fort_binary.clone()),
            package: PackageInfo {
                name: "fort".to_string(),
                version: "1.6.2".to_string(),
                distributor: "nicmx".to_string(),
                source_name: "fort".to_string(),
                binary_path: Some(fort_binary),
            },
            deployment: "host binary /usr/local/bin/fort".to_string(),
            version_source: "fort -V".to_string(),
        };

        merge_fort_binary_install(&mut installs, detected_binary_install);

        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].version, "1.6.2");
        assert_eq!(installs[0].package.version, "1.6.2");
        assert_eq!(installs[0].version_source, "fort -V");
    }

    #[test]
    fn routinator_advisory_uses_link_id_and_matches_fixed_version_boundary() {
        let advisory = parse_routinator_advisory(
            "CVE-2023-39916",
            "https://example.test/CVE-2023-39916.txt",
            "The CVE number is CVE-2023-39915.\n\n== Summary\nIssue\n\n== Affected products\nRoutinator 0.9.0 up to and including 0.12.1.\nRoutinator 0.14.*.\n\n== Description\nOnly affects users that enabled the feature.\n\n== Solution\nInstall Routinator 0.12.2 or later, skipping the 0.14.* releases.",
        )
        .unwrap()
        .unwrap();

        assert_eq!(advisory.id, "CVE-2023-39916");
        assert_eq!(advisory.fixed_version.as_deref(), Some("0.12.2"));
        assert!(
            advisory
                .remediation
                .contains("skipping the 0.14.* releases")
        );
        assert!(advisory.ranges.iter().any(|range| range.matches("0.12.1")));
        assert!(!advisory.ranges.iter().any(|range| range.matches("0.12.2")));
        assert!(advisory.ranges.iter().any(|range| range.matches("0.14.9")));
        assert!(!advisory.ranges.iter().any(|range| range.matches("0.13.0")));
    }

    #[test]
    fn routinator_open_upper_range_and_fort_fixed_versions_are_matched() {
        let routinator_ranges =
            parse_routinator_ranges("Routinator up to and including 0.15.1.").unwrap();
        assert!(routinator_ranges[0].matches("0.15.1"));
        assert!(!routinator_ranges[0].matches("0.15.2"));

        let fort_ranges = parse_fort_ranges("Malformed certificate crashes Fort 1.6.2-.").unwrap();
        assert_eq!(fort_ranges.len(), 1);
        assert!(fort_ranges[0].matches("1.6.2"));
        assert!(!fort_ranges[0].matches("1.6.3"));

        let exact_fort_ranges = parse_fort_ranges("Manifest crashes Fort 1.6.3, 1.6.4.").unwrap();
        assert!(exact_fort_ranges.iter().any(|range| range.matches("1.6.3")));
        assert!(exact_fort_ranges.iter().any(|range| range.matches("1.6.4")));
        assert!(!exact_fort_ranges.iter().any(|range| range.matches("1.6.5")));
    }

    #[test]
    fn fort_scheduled_fix_is_not_mistaken_for_an_affected_range() {
        let advisory = parse_fort_advisory(
            "CVE-2024-56170",
            "https://example.test/CVE.html",
            "Fort 1.6.5-. Manifest metadata is not compared.\n\nPatch\nScheduled for Fort release 2.0.0.",
        )
        .unwrap();
        assert_eq!(advisory.unwrap().fixed_version, None);
    }

    #[test]
    fn fort_condition_and_fix_are_preserved_as_advisory_evidence() {
        let advisory = parse_fort_advisory(
            "CVE-2024-45238",
            "https://example.test/CVE.html",
            "Certificate parsing crashes Fort 1.6.2-. This only affects builds compiled with OpenSSL < 3.\nPatch\nCommit released in Fort 1.6.3.",
        )
        .unwrap()
        .unwrap();
        assert_eq!(advisory.fixed_version.as_deref(), Some("1.6.3"));
        assert!(
            advisory
                .condition
                .as_deref()
                .unwrap()
                .contains("only affects")
        );
        assert!(
            advisory
                .condition
                .as_deref()
                .unwrap()
                .contains("OpenSSL < 3")
        );
        assert!(advisory.ranges.iter().any(|range| range.matches("1.6.2")));
        assert!(!advisory.ranges.iter().any(|range| range.matches("1.6.3")));
    }

    #[test]
    fn fort_html_advisory_sections_match_version_1_6_2() {
        let html = r#"
            <h2 id="cve-2024-45238">CVE-2024-45238</h2>
            <p>Certificate parsing crashes Fort 1.6.2-, when compiled with OpenSSL &lt; 3.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.3.</td></tr></table>
            <h2 id="cve-2024-45237">CVE-2024-45237</h2>
            <p>Key Usage handling crashes Fort 1.6.2-.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.3.</td></tr></table>
            <h2 id="cve-2024-45235">CVE-2024-45235</h2>
            <p>Authority Key Identifier handling crashes Fort 1.6.2-.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.3.</td></tr></table>
            <h2 id="cve-2024-45236">CVE-2024-45236</h2>
            <p>Empty signedAttrs crashes Fort 1.6.2-.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.3.</td></tr></table>
            <h2 id="cve-2024-45239">CVE-2024-45239</h2>
            <p>Null eContent crashes Fort 1.6.2-.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.3.</td></tr></table>
            <h2 id="cve-2024-45234">CVE-2024-45234</h2>
            <p>Non-canonical signedAttrs crashes Fort 1.6.2-.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.3.</td></tr></table>
            <h2 id="cve-2024-56375">CVE-2024-56375</h2>
            <p>Empty fileList crashes Fort 1.6.3, 1.6.4.</p>
            <table><tr><td>Patch</td><td>Released in Fort 1.6.5.</td></tr></table>
        "#;

        let advisories = parse_fort_advisories(html).unwrap();
        let matched = advisories
            .iter()
            .filter(|advisory| {
                advisory
                    .ranges
                    .iter()
                    .any(|range| range.matches("1.6.2"))
            })
            .map(|advisory| advisory.id.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(matched.len(), 6);
        assert!(matched.contains("CVE-2024-45238"));
        assert!(matched.contains("CVE-2024-45237"));
        assert!(matched.contains("CVE-2024-45235"));
        assert!(matched.contains("CVE-2024-45236"));
        assert!(matched.contains("CVE-2024-45239"));
        assert!(matched.contains("CVE-2024-45234"));
        assert!(!matched.contains("CVE-2024-56375"));
    }

    #[test]
    fn registry_source_detection_ignores_git_dependencies() {
        assert!(is_registry_source(Some(&json!("CratesIo"))));
        assert!(is_registry_source(Some(&json!("Registry"))));
        assert!(!is_registry_source(Some(&json!("Git"))));
        assert!(!is_registry_source(Some(&json!({"Other": "git"}))));
    }

    #[test]
    fn scan_snapshot_preserves_package_and_dependency_inventory() {
        let snapshot = ScanSnapshot {
            schema_version: SCAN_SNAPSHOT_SCHEMA_VERSION,
            installations: vec![InstallationSnapshot {
                product: "routinator".to_string(),
                version: "0.15.2".to_string(),
                package: PackageSnapshot {
                    name: "routinator".to_string(),
                    version: "0.15.2-1".to_string(),
                    distributor: "nlnetlabs".to_string(),
                    source_name: "routinator".to_string(),
                },
                deployment: "host package inventory".to_string(),
                version_source: "host package inventory".to_string(),
                dependencies: Some(vec![CrateDependency {
                    name: "serde".to_string(),
                    version: "1.0.219".to_string(),
                }]),
            }],
            warnings: vec!["inventory warning".to_string()],
        };
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let decoded: ScanSnapshot = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.schema_version, SCAN_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(decoded.installations[0].product, "routinator");
        assert_eq!(decoded.installations[0].package.version, "0.15.2-1");
        assert_eq!(
            decoded.installations[0].dependencies.as_ref().unwrap()[0].name,
            "serde"
        );
        assert_eq!(decoded.warnings, vec!["inventory warning".to_string()]);
    }

    #[tokio::test]
    async fn scan_snapshot_rejects_unsupported_schema_before_network_access() {
        let snapshot = ScanSnapshot {
            schema_version: SCAN_SNAPSHOT_SCHEMA_VERSION + 1,
            installations: Vec::new(),
            warnings: Vec::new(),
        };

        let error = validate_snapshot(snapshot, None).await.unwrap_err();

        assert!(error.contains("Unsupported scan snapshot schema version"));
    }
}
