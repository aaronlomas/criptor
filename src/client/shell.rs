//! # Shell Query Interface
//!
//! Note: The engine does not recognize terminals or UIs. It only returns `Vec<String>`.

use crate::client::CriptorClient;
use crate::crypto;
use crate::security;
use crate::storage::AUDIT_LOG_MAX_ROWS;
use crate::telemetry::{self, AnalysisTool, SystemSnapshot};

/// Width of the panels rendered by the shell.
const PANEL_WIDTH: usize = 60;

/// Number of processes listed by the `sysinfo` command in each ranking.
const PROCESS_RANKING_SIZE: usize = 8;

/// Builds a panel header padded to [`PANEL_WIDTH`] characters.
fn panel_header(title: &str) -> String {
    let prefix = format!("── {} ", title);
    let fill = PANEL_WIDTH.saturating_sub(prefix.chars().count());
    format!("{}{}", prefix, "─".repeat(fill))
}

/// Builds a panel footer spanning [`PANEL_WIDTH`] characters.
fn panel_footer() -> String {
    "─".repeat(PANEL_WIDTH)
}

/// Runs `task` on the blocking thread pool when a Tokio runtime is available,
/// falling back to a synchronous execution otherwise.
async fn run_blocking<T, F>(task: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle
            .spawn_blocking(task)
            .await
            .map_err(|e| format!("worker thread terminated: {}", e)),
        Err(_) => Ok(task()),
    }
}

/// Renders the debugger verdict.
///
/// The evidence is moved to its own line so the panel keeps a constant width
/// regardless of how long the platform specific detail is.
fn render_debugger_verdict() -> Vec<String> {
    match security::debugger_evidence() {
        Some(evidence) => vec![
            "  Debugger          : ATTACHED".to_string(),
            format!("  Evidence          : {}", evidence.describe()),
        ],
        None => vec!["  Debugger          : not attached".to_string()],
    }
}

/// Renders the compact runtime block appended to the `status` command.
fn render_runtime_status(snapshot: &SystemSnapshot) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "  CPU               : {:.1}% ({} cores)",
        snapshot.cpu_usage_percent, snapshot.cpu_cores
    ));
    lines.push(format!(
        "  Memory            : {} / {} ({:.0}%)",
        telemetry::format_bytes(snapshot.used_memory),
        telemetry::format_bytes(snapshot.total_memory),
        snapshot.memory_usage_percent()
    ));
    lines.push(format!("  Processes         : {}", snapshot.process_count));
    lines.push(format!(
        "  Uptime            : {}",
        telemetry::format_duration(snapshot.uptime_seconds)
    ));

    lines.extend(render_debugger_verdict());

    lines
}

/// Renders the process ranking table used by the `sysinfo` command.
fn render_process_table(title: &str, processes: &[&telemetry::ProcessSample]) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(panel_header(title));
    lines.push(format!(
        "  {:<8} {:>7} {:>10}  {}",
        "PID", "CPU %", "MEM", "NAME"
    ));

    if processes.is_empty() {
        lines.push("  (no data available)".to_string());
    } else {
        for process in processes {
            lines.push(format!(
                "  {:<8} {:>7.2} {:>10}  {}",
                process.pid.as_u32(),
                process.cpu_percent,
                telemetry::format_bytes(process.memory_bytes),
                process.name
            ));
        }
    }

    lines.push(panel_footer());
    lines
}

/// Renders the analysis tools detected in the process table.
fn render_analysis_tools(tools: &[AnalysisTool]) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(panel_header("Analysis Tools"));
    if tools.is_empty() {
        lines.push("  None detected.".to_string());
    } else {
        for tool in tools {
            lines.push(format!(
                "  {:<8} {:<24} {}",
                tool.pid.as_u32(),
                tool.name,
                tool.category.label()
            ));
        }
        lines.push(format!("  {} process(es) flagged.", tools.len()));
    }
    lines.push(panel_footer());
    lines
}

/// Renders the full telemetry report of the `sysinfo` command.
fn render_sysinfo(snapshot: SystemSnapshot) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(panel_header("System Telemetry"));
    lines.push(format!(
        "  CPU               : {:.1}% ({} cores)",
        snapshot.cpu_usage_percent, snapshot.cpu_cores
    ));
    lines.push(format!(
        "  Memory            : {} / {} ({:.0}%)",
        telemetry::format_bytes(snapshot.used_memory),
        telemetry::format_bytes(snapshot.total_memory),
        snapshot.memory_usage_percent()
    ));
    lines.push(format!(
        "  Available         : {}",
        telemetry::format_bytes(snapshot.available_memory)
    ));
    lines.push(format!(
        "  Swap              : {} / {}",
        telemetry::format_bytes(snapshot.swap_used),
        telemetry::format_bytes(snapshot.swap_total)
    ));
    lines.push(format!(
        "  Uptime            : {}",
        telemetry::format_duration(snapshot.uptime_seconds)
    ));
    lines.push(format!("  Processes         : {}", snapshot.process_count));
    lines.push(panel_footer());

    lines.extend(render_process_table(
        "Top Processes (CPU)",
        &snapshot.top_by_cpu(PROCESS_RANKING_SIZE),
    ));
    lines.extend(render_process_table(
        "Top Processes (Memory)",
        &snapshot.top_by_memory(PROCESS_RANKING_SIZE),
    ));
    lines.extend(render_analysis_tools(&snapshot.analysis_tools));

    lines.push(panel_header("Security Verdict"));
    lines.extend(render_debugger_verdict());
    lines.push(format!(
        "  Analysis tools    : {} detected",
        snapshot.analysis_tools.len()
    ));
    lines.push("  Note              : heuristic only, not a security boundary.".to_string());
    lines.push(panel_footer());

    lines
}

impl CriptorClient {
    /// Processes a plain text command and returns response lines.
    /// This method is the only entry point for the shell interface.
    pub async fn query_shell(&self, input: &str) -> Vec<String> {
        let parts: Vec<&str> = input.trim().splitn(2, ' ').collect();
        let command = parts[0].to_lowercase();
        let args = parts.get(1).copied().unwrap_or("").trim();

        match command.as_str() {
            "help" => vec![
                "┌─ Criptor CLI ─────────────────────────────────────────────┐".into(),
                "│  crypto       Show active cryptographic parameters        │".into(),
                "│  status       Show vault lock state and session info      │".into(),
                "│  sysinfo      Show CPU, memory and process telemetry      │".into(),
                "│  audit        Show last 10 audit log entries              │".into(),
                "│  audit -n <N> Show last N audit log entries               │".into(),
                "│  audit -rm    Clear all audit log entries                 │".into(),
                "│  clear        Clear terminal output                       │".into(),
                "│  help         Show this help message                      │".into(),
                "└───────────────────────────────────────────────────────────┘".into(),
            ],

            "crypto" => vec![
                "Cryptographic Parameters".into(),
                "  KDF Algorithm    : Argon2id (RFC 9106)".to_string(),
                format!(
                    "  Memory Cost (m)  : {} KiB  ({} MiB)",
                    crypto::ARGON2_M_COST,
                    crypto::ARGON2_M_COST / 1024
                ),
                format!("  Time Cost   (t)  : {} iterations", crypto::ARGON2_T_COST),
                format!("  Parallelism (p)  : {} lanes", crypto::ARGON2_P_COST),
                "  Output Length    : 32 bytes (256-bit key)".to_string(),
                "".into(),
                "  AEAD Cipher      : ChaCha20-Poly1305 (RFC 8439)".to_string(),
                format!(
                    "  Nonce Length     : {} bytes (96-bit random)",
                    crypto::NONCE_LEN
                ),
                format!(
                    "  Auth Tag Length  : {} bytes (128-bit MAC)",
                    crypto::TAG_LEN
                ),
                "  Key Length       : 32 bytes (256-bit)".to_string(),
                "#".into(), //We use '#' to mark the end of the output for each command.
            ],

            "status" => {
                let locked = self.is_locked();
                let session_ok = *self
                    .session_verified
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let vault_state = if locked { "LOCKED" } else { "UNLOCKED" };
                let session_state = if session_ok {
                    "VERIFIED"
                } else if !locked {
                    "PENDING_TOTP"
                } else {
                    "N/A"
                };

                let mut lines = vec![
                    panel_header("Criptor Status"),
                    format!("  Criptor State     : {}", vault_state),
                    format!("  Session           : {}", session_state),
                    format!("  DB Path           : {}", self.db_path.display()),
                ];

                // The runtime block requires a live system sample, which is
                // taken on a blocking worker to avoid stalling the runtime.
                match run_blocking(telemetry::snapshot).await {
                    Ok(snapshot) => lines.extend(render_runtime_status(&snapshot)),
                    Err(e) => lines.push(format!("  Runtime          : unavailable ({})", e)),
                }

                lines.push(panel_footer());
                lines
            }

            "sysinfo" | "sys" => match run_blocking(telemetry::snapshot).await {
                Ok(snapshot) => render_sysinfo(snapshot),
                Err(e) => vec![format!("sysinfo: error: {}", e)],
            },

            "audit" => {
                match args {
                    "-rm" => match self.clear_audit_logs().await {
                        Ok(()) => vec![
                            "Audit Log".into(),
                            "  All audit log entries have been removed.".into(),
                            format!("  Retention cap: {} rows (automatic).", AUDIT_LOG_MAX_ROWS),
                            "#".into(),
                        ],
                        Err(e) => vec![format!("audit -rm: error: {}", e)],
                    },

                    flag if flag.starts_with("-n ") => {
                        let n_str = flag.trim_start_matches("-n ").trim();
                        match n_str.parse::<i64>() {
                            Ok(n) if n > 0 => self.shell_show_audit_logs(n).await,
                            _ => vec![
                            format!("audit -n: invalid argument '{}' — expected a positive integer.", n_str),
                            "  Usage: audit -n <N>".into(),
                        ],
                    }
                    }

                    "" => self.shell_show_audit_logs(10).await,

                    unknown => vec![
                        format!("audit: unknown flag '{}'", unknown),
                        "  Usage: audit | audit -n <N> | audit -rm".into(),
                    ],
                }
            }

            "" => vec![],

            unknown => vec![
                format!("criptor: command not found: '{}'", unknown),
                "  Type 'help' to see available commands.".into(),
            ],
        }
    }

    /// Renders the last `limit` audit log entries as terminal output lines.
    async fn shell_show_audit_logs(&self, limit: i64) -> Vec<String> {
        match self.get_audit_logs(limit).await {
            Ok(logs) => {
                let mut output = vec![format!("Audit Log (last {})", limit)];
                if logs.is_empty() {
                    output.push("  No audit log entries found.".into());
                } else {
                    for log in logs {
                        let meta = log.metadata.unwrap_or_else(|| "N/A".into());
                        output.push(format!("  [{}] {} — {}", log.created_at, log.action, meta));
                    }
                }
                output.push(format!("  Retention cap: {} rows.", AUDIT_LOG_MAX_ROWS));
                output.push("#".into());
                output
            }
            Err(e) => vec![format!("audit: error fetching entries: {}", e)],
        }
    }
}
