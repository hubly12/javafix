//! OS specifics: where to look, console setup, language, elevation, running Java processes, log folder.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn home() -> Option<PathBuf> {
    if cfg!(windows) { env_path("USERPROFILE") } else { env_path("HOME") }
}

/// Hidden folders in the user's home (.jdks, .gradle, .lunarclient, .sdkman, .jabba, ...).
fn dot_dirs(home: &PathBuf) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(home)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with('.') && n != ".Trash"
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// Folders scanned by default. Documents/Desktop/Downloads are left out on purpose (macOS privacy prompts).
pub fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let home = home();
    if cfg!(windows) {
        for name in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA", "APPDATA"] {
            roots.extend(env_path(name));
        }
        if let Some(h) = &home {
            roots.push(h.join("curseforge"));
        }
    } else if cfg!(target_os = "macos") {
        roots.extend(["/Library/Java/JavaVirtualMachines", "/Library/Internet Plug-Ins", "/Applications", "/opt/homebrew", "/usr/local/Cellar"].map(PathBuf::from));
        if let Some(h) = &home {
            roots.push(h.join("Library/Java/JavaVirtualMachines"));
            roots.push(h.join("Library/Application Support"));
            roots.push(h.join("Applications"));
        }
    } else {
        roots.extend(["/usr/lib/jvm", "/opt"].map(PathBuf::from));
    }
    if let Some(h) = &home {
        roots.extend(dot_dirs(h));
    }
    roots.extend(env_path("JAVA_HOME"));
    let mut unique: Vec<PathBuf> = Vec::new();
    for r in roots {
        if r.is_dir() && !unique.contains(&r) {
            unique.push(r);
        }
    }
    unique
}

#[cfg(windows)]
mod win {
    type Handle = *mut core::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
        fn GetUserDefaultUILanguage() -> u16;
    }
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    pub fn enable_ansi() -> bool {
        // SAFETY: plain Win32 calls on the process's own stdout handle.
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode = 0u32;
            GetConsoleMode(h, &mut mode) != 0 && SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        }
    }

    pub fn ui_is_korean() -> bool {
        // SAFETY: no arguments, returns a LANGID.
        unsafe { GetUserDefaultUILanguage() & 0x3ff == 0x12 }
    }
}

/// Turns on ANSI colours. Returns false when the output is not a console that supports them.
pub fn enable_ansi() -> bool {
    #[cfg(windows)]
    {
        win::enable_ansi()
    }
    #[cfg(not(windows))]
    {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal()
    }
}

pub fn system_is_korean() -> bool {
    for name in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = env::var(name) {
            if !v.is_empty() {
                return v.to_ascii_lowercase().starts_with("ko");
            }
        }
    }
    #[cfg(windows)]
    {
        win::ui_is_korean()
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).split(',').next().unwrap_or("").contains("ko"))
            .unwrap_or(false)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        false
    }
}

/// Number of running Java processes (Minecraft, launchers, IDEs). Best effort; 0 when unknown.
pub fn running_java() -> usize {
    if cfg!(windows) {
        Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| {
                        let l = l.to_ascii_lowercase();
                        l.starts_with("\"java.exe\"") || l.starts_with("\"javaw.exe\"")
                    })
                    .count()
            })
            .unwrap_or(0)
    } else {
        Command::new("ps")
            .args(["-axo", "comm="])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.trim().rsplit('/').next() == Some("java")).count())
            .unwrap_or(0)
    }
}

/// Starts this program again with administrator/root rights.
/// Windows: a new window via the UAC prompt (returns at once). macOS/Linux: `sudo` in this terminal (waits).
pub fn relaunch_elevated(args: &[String]) -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    if cfg!(windows) {
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let list: Vec<String> = args.iter().map(|a| quote(&format!("\"{a}\""))).collect();
        let script = format!(
            "Start-Process -FilePath {} -ArgumentList {} -Verb RunAs",
            quote(&exe.to_string_lossy()),
            if list.is_empty() { "@()".to_string() } else { list.join(",") }
        );
        let status = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]).status().map_err(|e| e.to_string())?;
        if status.success() { Ok(()) } else { Err("UAC".into()) }
    } else {
        let status = Command::new("sudo").arg(exe).args(args).status().map_err(|e| e.to_string())?;
        if status.success() { Ok(()) } else { Err(format!("sudo: {status}")) }
    }
}

/// `JAVAFIX_LOG_DIR` overrides the place (used by the tests).
pub fn log_dir() -> Option<PathBuf> {
    if let Some(dir) = env_path("JAVAFIX_LOG_DIR") {
        Some(dir)
    } else if cfg!(windows) {
        env_path("LOCALAPPDATA").map(|p| p.join("JavaFix"))
    } else if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library/Logs/JavaFix"))
    } else {
        home().map(|h| h.join(".local/state/javafix"))
    }
}
