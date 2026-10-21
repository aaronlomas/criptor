#[cfg(target_os = "linux")]
use std::env;

/// Evidence that the current process is attached to a debugger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebuggerEvidence {
    /// Linux: `TracerPid` from `/proc/self/status` points at the tracer.
    LinuxTracerPid(u32),
    /// Windows: `IsDebuggerPresent()` reported an attached debugger.
    WindowsDebuggerPresent,
    /// macOS: the `P_TRACED` flag is set on the current process.
    MacOsProcessTraced,
}

impl DebuggerEvidence {
    /// Human readable summary of the detection.
    pub fn describe(&self) -> String {
        match self {
            DebuggerEvidence::LinuxTracerPid(pid) => {
                format!("Linux tracer attached (TracerPid={})", pid)
            }
            DebuggerEvidence::WindowsDebuggerPresent => {
                "Windows debugger detected (IsDebuggerPresent)".to_string()
            }
            DebuggerEvidence::MacOsProcessTraced => {
                "macOS process traced (P_TRACED flag set)".to_string()
            }
        }
    }
}

/// Detects whether the current process is being traced by a debugger.
///
/// Unlike a process-name scan — which only lists well known debugging tools
/// running elsewhere — this check inspects the *current* process, so it
/// reports the real attachment state of Criptor itself.
pub fn debugger_evidence() -> Option<DebuggerEvidence> {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return None;
        };

        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                let tracer_pid = rest.trim().parse::<u32>().unwrap_or(0);
                return if tracer_pid > 0 {
                    Some(DebuggerEvidence::LinuxTracerPid(tracer_pid))
                } else {
                    None
                };
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
            if IsDebuggerPresent() != 0 {
                return Some(DebuggerEvidence::WindowsDebuggerPresent);
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    {
        // `KERN_PROC` returns a `kinfo_proc` structure whose first member is
        // `proc_bsdinfo`, and `proc_bsdinfo.p_flags` is its first `u32`.
        // Reading the leading bytes therefore exposes the process flags.
        const P_TRACED: u32 = 0x0000_0800;
        const BUFFER_SIZE: usize = 1024;

        let mut buffer = [0u8; BUFFER_SIZE];
        let mut size = buffer.len() as libc::size_t;

        let pid = unsafe { libc::getpid() };
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];

        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buffer.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };

        if result != 0 || size < std::mem::size_of::<u32>() {
            return None;
        }

        let flags = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        if flags & P_TRACED != 0 {
            return Some(DebuggerEvidence::MacOsProcessTraced);
        }

        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        None
    }
}

/// Checks if the current session is a remote connection.
/// Returns `true` if a remote session is detected (e.g. SSH, RDP, etc.).
pub fn environment_check() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            // GetSystemMetrics(SM_REMOTESESSION)
            // SM_REMOTESESSION = 0x1000
            use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};
            if GetSystemMetrics(SM_REMOTESESSION) != 0 {
                return true;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // 1. Check common SSH/Remote environment variables
        let remote_vars = ["SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "REMOTEHOST"];
        for var in remote_vars.iter() {
            if env::var(var).is_ok() {
                return true;
            }
        }

        // 2. Check systemd-logind via dlsym to avoid hard dependency on libsystemd.so
        unsafe {
            let handle = libc::dlopen(c"libsystemd.so.0".as_ptr() as *const _, libc::RTLD_LAZY);
            if !handle.is_null() {
                let func = libc::dlsym(handle, c"sd_session_is_remote".as_ptr() as *const _);
                if !func.is_null() {
                    let sd_session_is_remote: extern "C" fn(*const libc::c_char) -> libc::c_int =
                        std::mem::transmute(func);
                    // Pass NULL to check the current session
                    let result = sd_session_is_remote(std::ptr::null());
                    libc::dlclose(handle);
                    if result > 0 {
                        return true;
                    }
                } else {
                    libc::dlclose(handle);
                }
            }
        }

        // 3. Detect remote desktop software processes (AnyDesk, TeamViewer, VNC, etc.)
        if let Ok(entries) = std::fs::read_dir("/proc") {
            let remote_procs = [
                "anydesk",
                "teamviewer",
                "rustdesk",
                "xrdp",
                "vnc",
                "remmina",
            ];
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let file_name = entry.file_name();
                        let file_name_str = file_name.to_string_lossy();
                        if file_name_str.chars().all(|c| c.is_ascii_digit()) {
                            let mut comm_path = entry.path();
                            comm_path.push("comm");
                            if let Ok(comm) = std::fs::read_to_string(comm_path) {
                                let comm_lower = comm.trim().to_lowercase();
                                for rp in &remote_procs {
                                    if comm_lower.contains(rp) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    false
}
