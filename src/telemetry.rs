//! # System Telemetry
//!
//! On-demand introspection of the host system (CPU, memory and the process
//! table) used by the shell `status` and `sysinfo` commands.
//!
//! Design constraints:
//!
//! - **Nothing runs in the background.** Every sample is taken synchronously
//!   when the command is invoked and dropped right after.
//! - **Nothing leaves the device.** The collected data is only rendered as
//!   terminal lines; it is never persisted, audited nor transmitted.
//! - **Heuristics are labelled as such.** The analysis-tool detection is a
//!   name-based heuristic, not a security boundary: it can be bypassed by
//!   renaming an executable and it never blocks any operation.

use std::time::Duration;

use sysinfo::{
    CpuRefreshKind, MemoryRefreshKind, Pid, Process, ProcessRefreshKind, RefreshKind, System,
    UpdateKind,
};

/// Interval between the two refreshes used to compute CPU usage.
///
/// `sysinfo` reports CPU and per-process usage as the delta between two
/// consecutive refreshes, so a second sample is mandatory for the percentages
/// to carry any meaning.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

/// Executables considered reverse-engineering, debugging or traffic capture
/// tools.
///
/// The comparison is performed against the exact executable name
/// (case-insensitive) to keep false positives as low as possible.
const ANALYSIS_TOOLS: &[(&str, ToolCategory)] = &[
    // Debuggers
    ("gdb", ToolCategory::Debugger),
    ("gdbserver", ToolCategory::Debugger),
    ("lldb", ToolCategory::Debugger),
    ("lldb-server", ToolCategory::Debugger),
    ("x64dbg", ToolCategory::Debugger),
    ("x32dbg", ToolCategory::Debugger),
    ("windbg", ToolCategory::Debugger),
    ("windbgx", ToolCategory::Debugger),
    ("ollydbg", ToolCategory::Debugger),
    // Reverse engineering
    ("ida", ToolCategory::ReverseEngineering),
    ("ida64", ToolCategory::ReverseEngineering),
    ("idat", ToolCategory::ReverseEngineering),
    ("idat64", ToolCategory::ReverseEngineering),
    ("ghidra", ToolCategory::ReverseEngineering),
    ("radare2", ToolCategory::ReverseEngineering),
    ("r2", ToolCategory::ReverseEngineering),
    ("rizin", ToolCategory::ReverseEngineering),
    ("cutter", ToolCategory::ReverseEngineering),
    ("binaryninja", ToolCategory::ReverseEngineering),
    ("apktool", ToolCategory::ReverseEngineering),
    ("jadx", ToolCategory::ReverseEngineering),
    ("dnspy", ToolCategory::ReverseEngineering),
    // Instrumentation
    ("frida", ToolCategory::Instrumentation),
    ("frida-server", ToolCategory::Instrumentation),
    ("strace", ToolCategory::Instrumentation),
    ("ltrace", ToolCategory::Instrumentation),
    // Traffic capture / interception
    ("wireshark", ToolCategory::NetworkCapture),
    ("tshark", ToolCategory::NetworkCapture),
    ("tcpdump", ToolCategory::NetworkCapture),
    ("dumpcap", ToolCategory::NetworkCapture),
    ("mitmproxy", ToolCategory::NetworkCapture),
    ("burpsuite", ToolCategory::NetworkCapture),
];

/// Family an analysis tool belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCategory {
    Debugger,
    ReverseEngineering,
    Instrumentation,
    NetworkCapture,
}

impl ToolCategory {
    /// Human readable label rendered in the terminal.
    pub fn label(&self) -> &'static str {
        match self {
            ToolCategory::Debugger => "debugger",
            ToolCategory::ReverseEngineering => "reverse-engineering",
            ToolCategory::Instrumentation => "instrumentation",
            ToolCategory::NetworkCapture => "traffic capture",
        }
    }
}

/// A single entry of the process table.
#[derive(Debug, Clone)]
pub struct ProcessSample {
    pub pid: Pid,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

/// A running process whose executable name matches a known analysis tool.
#[derive(Debug, Clone)]
pub struct AnalysisTool {
    pub pid: Pid,
    pub name: String,
    pub category: ToolCategory,
}

/// Aggregated snapshot of the host system.
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    /// Average CPU usage across all cores, in percent.
    pub cpu_usage_percent: f32,
    pub cpu_cores: usize,
    pub total_memory: u64,
    pub used_memory: u64,
    pub available_memory: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub uptime_seconds: u64,
    pub process_count: usize,
    /// Every sampled process, sorted by CPU usage (descending).
    pub processes: Vec<ProcessSample>,
    /// Processes flagged as analysis tools.
    pub analysis_tools: Vec<AnalysisTool>,
}

impl SystemSnapshot {
    /// The `limit` processes consuming the most CPU time.
    pub fn top_by_cpu(&self, limit: usize) -> Vec<&ProcessSample> {
        self.processes.iter().take(limit).collect()
    }

    /// The `limit` processes holding the most resident memory.
    pub fn top_by_memory(&self, limit: usize) -> Vec<&ProcessSample> {
        let mut sorted: Vec<&ProcessSample> = self.processes.iter().collect();
        sorted.sort_by_key(|process| std::cmp::Reverse(process.memory_bytes));
        sorted.truncate(limit);
        sorted
    }

    /// Percentage of the total physical memory currently in use.
    pub fn memory_usage_percent(&self) -> f32 {
        if self.total_memory == 0 {
            return 0.0;
        }
        (self.used_memory as f64 / self.total_memory as f64 * 100.0) as f32
    }
}

/// Captures a full snapshot of the host system.
///
/// The call blocks for roughly [`SAMPLE_INTERVAL`] plus the time needed to
/// walk the process table. It is meant to be executed on a blocking worker
/// thread, never on an async runtime worker.
pub fn snapshot() -> SystemSnapshot {
    let refresh_kind = RefreshKind::nothing()
        .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
        .with_memory(MemoryRefreshKind::everything())
        .with_processes(
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet),
        );

    let mut system = System::new_with_specifics(refresh_kind);

    // First sample: establishes the baseline for the usage deltas.
    std::thread::sleep(SAMPLE_INTERVAL);

    // Second sample: now CPU and per-process usage are meaningful.
    system.refresh_specifics(refresh_kind);

    let cpu_usage_percent = average_cpu_usage(&system);

    let processes: Vec<ProcessSample> = system
        .processes()
        .values()
        .map(|process| ProcessSample {
            pid: process.pid(),
            name: process_label(process),
            cpu_percent: process.cpu_usage().max(0.0),
            memory_bytes: process.memory(),
        })
        .collect();

    let analysis_tools = detect_analysis_tools(&processes, system.processes());

    let mut sorted = processes;
    sorted.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.memory_bytes.cmp(&a.memory_bytes))
    });

    SystemSnapshot {
        cpu_usage_percent,
        cpu_cores: system.cpus().len(),
        total_memory: system.total_memory(),
        used_memory: system.used_memory(),
        available_memory: system.available_memory(),
        swap_total: system.total_swap(),
        swap_used: system.used_swap(),
        uptime_seconds: System::uptime(),
        process_count: sorted.len(),
        processes: sorted,
        analysis_tools,
    }
}

/// Computes the average CPU usage across every core.
fn average_cpu_usage(system: &System) -> f32 {
    let cpus = system.cpus();
    if cpus.is_empty() {
        return 0.0;
    }
    let total: f32 = cpus.iter().map(|cpu| cpu.cpu_usage()).sum();
    total / cpus.len() as f32
}

/// Resolves the display name of a process.
///
/// The executable path is preferred because the process name reported by the
/// kernel is truncated on some platforms; the plain name is used as fallback.
fn process_label(process: &Process) -> String {
    if let Some(exe) = process.exe() {
        if let Some(file_name) = exe.file_name() {
            return file_name.to_string_lossy().to_string();
        }
    }
    process.name().to_string_lossy().to_string()
}

/// Returns the category of `name` when it matches a known analysis tool.
///
/// The comparison is exact and case-insensitive on purpose: a substring match
/// would flag unrelated executables.
pub fn classify_tool(name: &str) -> Option<ToolCategory> {
    ANALYSIS_TOOLS
        .iter()
        .find(|(tool, _)| tool.eq_ignore_ascii_case(name))
        .map(|(_, category)| *category)
}

/// Flags the processes whose executable name matches a known analysis tool.
fn detect_analysis_tools(
    samples: &[ProcessSample],
    raw_processes: &std::collections::HashMap<Pid, Process>,
) -> Vec<AnalysisTool> {
    let mut hits = Vec::new();

    for sample in samples {
        let mut matched = classify_tool(&sample.name);

        // The executable path may be unavailable (permission denied on
        // foreign processes), fall back to the raw process name.
        if matched.is_none() {
            if let Some(process) = raw_processes.get(&sample.pid) {
                matched = classify_tool(&process.name().to_string_lossy());
            }
        }

        if let Some(category) = matched {
            hits.push(AnalysisTool {
                pid: sample.pid,
                name: sample.name.clone(),
                category,
            });
        }
    }

    hits
}

/// Formats a byte count using binary units (KiB, MiB, GiB).
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;

    if value >= KIB * KIB * KIB {
        format!("{:.2} GiB", value / (KIB * KIB * KIB))
    } else if value >= KIB * KIB {
        format!("{:.2} MiB", value / (KIB * KIB))
    } else if value >= KIB {
        format!("{:.2} KiB", value / KIB)
    } else {
        format!("{} B", bytes)
    }
}

/// Formats a duration expressed in seconds as a compact `Xd HHh MMm` string.
pub fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    if days > 0 {
        format!("{}d {:02}h {:02}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {:02}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes_with_binary_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.00 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn formats_durations_compactly() {
        assert_eq!(format_duration(45), "0m");
        assert_eq!(format_duration(3_661), "1h 01m");
        assert_eq!(format_duration(90_061), "1d 01h 01m");
    }

    #[test]
    fn classifies_analysis_tools_by_exact_name() {
        assert_eq!(classify_tool("gdb"), Some(ToolCategory::Debugger));
        assert_eq!(classify_tool("GDB"), Some(ToolCategory::Debugger));
        assert_eq!(classify_tool("frida"), Some(ToolCategory::Instrumentation));
        assert_eq!(
            classify_tool("wireshark"),
            Some(ToolCategory::NetworkCapture)
        );

        // Partial names must never match, otherwise unrelated executables
        // would be reported as analysis tools.
        assert_eq!(classify_tool("mygdb"), None);
        assert_eq!(classify_tool("gdb-helper"), None);
        assert_eq!(classify_tool("firefox"), None);
        assert_eq!(classify_tool(""), None);
    }

    #[test]
    fn snapshot_reports_a_consistent_system_state() {
        let snapshot = snapshot();

        assert!(snapshot.process_count > 0);
        assert!(!snapshot.processes.is_empty());
        assert!(snapshot.cpu_cores > 0);
        assert!(snapshot.total_memory > 0);
        assert!(snapshot.memory_usage_percent() >= 0.0);
        assert!(snapshot.memory_usage_percent() <= 100.0);
    }

    #[test]
    fn top_lists_are_bounded_and_sorted() {
        let snapshot = snapshot();

        let by_cpu = snapshot.top_by_cpu(3);
        assert!(by_cpu.len() <= 3);
        assert!(by_cpu.len() <= snapshot.processes.len());

        let by_memory = snapshot.top_by_memory(3);
        assert!(by_memory.len() <= 3);
        for window in by_memory.windows(2) {
            assert!(window[0].memory_bytes >= window[1].memory_bytes);
        }
    }
}
