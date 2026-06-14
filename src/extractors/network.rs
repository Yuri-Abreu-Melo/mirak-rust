use std::process::Command;
use std::str;

#[allow(dead_code)]
struct PortInfo {
    pid: u32,
    command: String,
    user: String,
    port: String,
}

#[allow(dead_code)]
pub fn list_open_ports() -> String {
    let ports = extract_ports();
    let mut reports = String::from("");
    if !ports.is_empty() {
        reports
            .push_str("The following ports are open, ensure that anything running on it is safe\n");
        ports.iter().for_each(|port| {
            reports.push_str(
                format!(
                    "The program {} is running on port {} by the user {} with the pid {}\n",
                    port.command, port.port, port.user, port.pid
                )
                .as_str(),
            );
        });
    } else {
        reports.push_str("There is no listening ports\n");
    }
    reports
}

/// This function uses lsof to get the port there are listening in the OS
/// spotting the pid, command and the user reponsible for the port
#[allow(dead_code)]
fn extract_ports() -> Vec<PortInfo> {
    let output = Command::new("sudo")
        .args(["lsof", "-i", "-P", "-n"])
        .output()
        .expect("Failed to execute lsof");
    let stdout = str::from_utf8(&output.stdout).expect("Output is not UTF-8");
    let mut results: Vec<PortInfo> = Vec::new();
    for line in stdout.lines().skip(1) {
        // Skip non LISTEN ports
        if !line.contains("(LISTEN)") {
            continue;
        }
        // Split the line into whitespace-separated parts and collect them into a vector
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Skip this line if it doesn't have at least 9 parts, since we expect certain columns to be present
        if parts.len() < 9 {
            continue;
        }

        // The first column is the command name (e.g., "sshd", "nginx")
        let command = parts[0].to_string();

        // The second column is the PID, parsed as a u32 integer; if parsing fails, use 0 as a fallback
        let pid = parts[1].parse::<u32>().unwrap_or(0);

        // The third column is the user who owns the process
        let user = parts[2].to_string();

        // The 9th column (index 8) contain the IP:port
        let name_field = parts[8];

        let port = name_field.rsplit(':').next().unwrap_or("").to_string();

        results.push(PortInfo {
            pid,
            command,
            user,
            port,
        });
    }
    results
}
