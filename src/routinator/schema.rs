use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
/// This struct is defined to have the mandatory fields and type validation
/// when the toml lib converts the file based on that struct it will automatically check the fields
pub struct Config {
    pub repository_dir: PathBuf,
    pub no_rir_tals: Option<bool>,
    pub tals: Option<Vec<String>>,
    pub extra_tals_dir: Option<PathBuf>,
    pub exceptions: Option<Vec<PathBuf>>,
    pub strict: Option<bool>,
    pub stale: Option<StalePolicy>,
    pub allow_dubious_hosts: Option<bool>,
    pub disable_rsync: Option<bool>,
    pub rsync_command: Option<String>,
    pub rsync_args: Option<Vec<String>>,
    pub rsync_count: Option<u32>,
    pub validation_threads: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub history_size: Option<u32>,
    pub rtr_listen: Vec<SocketAddr>,
    pub http_listen: Vec<SocketAddr>,
    pub log_level: Option<LogLevel>,
    pub log: Option<LogOutput>,
    pub syslog_facility: Option<String>,
    pub log_file: Option<PathBuf>,
    pub pid_file: Option<PathBuf>,
    pub working_dir: Option<PathBuf>,
    pub chroot: Option<PathBuf>,
    pub tal_labels: Option<Vec<String>>,
    pub tal_dir: Option<PathBuf>,
}

// The Enum controls which values can be setted

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StalePolicy {
    Reject,
    Warn,
    Accept,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    Stderr,
    Syslog,
    File,
    Default,
}
