//! Finding Java runtimes (by their lib/security/blocked.certs) and reading their state. Read-only.

use crate::fingerprints::{BACKUP_SUFFIX, FINGERPRINTS, HEADER};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// All 16 certificates are blocked.
    Protected,
    /// Some are missing and the file can be patched.
    Vulnerable,
    /// Some are missing, but the runtime lives inside a signed macOS .app; the app must be updated instead.
    AppBundle,
    /// The file does not look like a SHA-256 block list; left alone.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Runtime {
    pub home: PathBuf,
    pub file: PathBuf,
    pub version: String,
    pub state: State,
    pub missing: Vec<&'static str>,
    pub writable: bool,
    pub has_backup: bool,
}

/// Large folders that never contain a Java runtime worth patching.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", ".rustup", ".cargo", ".npm", ".nuget", ".Trash", "$Recycle.Bin", "WindowsApps"];

pub fn backup_path(file: &Path) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

/// Fingerprints from the list that the given block list does not contain yet.
pub fn missing(content: &str) -> Vec<&'static str> {
    let have: HashSet<String> = content.lines().map(|l| l.trim().to_ascii_uppercase()).collect();
    FINGERPRINTS.iter().copied().filter(|f| !have.contains(*f)).collect()
}

pub fn in_app_bundle(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase().ends_with(".app"))
}

fn is_block_list(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if name != "blocked.certs" && name != "blacklisted.certs" {
        return false;
    }
    let security = path.parent();
    let lib = security.and_then(Path::parent);
    security.and_then(Path::file_name).is_some_and(|n| n == "security") && lib.and_then(Path::file_name).is_some_and(|n| n == "lib")
}

fn read_version(home: &Path) -> String {
    // JDK 9+ and JREs keep `release` in the home; a JDK 8 home found via jre/lib has it one level up.
    for dir in [Some(home), home.parent()].into_iter().flatten() {
        if let Ok(text) = fs::read_to_string(dir.join("release")) {
            for key in ["JAVA_RUNTIME_VERSION=", "JAVA_VERSION="] {
                if let Some(line) = text.lines().find(|l| l.starts_with(key)) {
                    return line[key.len()..].trim().trim_matches('"').to_string();
                }
            }
        }
    }
    "?".to_string()
}

/// Reads one block list. `None` when the path is not a block list or cannot be read.
pub fn inspect(file: &Path) -> Option<Runtime> {
    if !is_block_list(file) {
        return None;
    }
    let home = file.parent()?.parent()?.parent()?.to_path_buf();
    let bytes = fs::read(file).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let first = text.lines().next().unwrap_or("").trim_start_matches('\u{feff}').trim();
    let (state, missing) = if first != HEADER {
        (State::Unknown, Vec::new())
    } else {
        let m = missing(&text);
        if m.is_empty() {
            (State::Protected, m)
        } else if cfg!(target_os = "macos") && in_app_bundle(file) {
            (State::AppBundle, m)
        } else {
            (State::Vulnerable, m)
        }
    };
    Some(Runtime {
        version: read_version(&home),
        home,
        file: file.to_path_buf(),
        state,
        missing,
        // Opening for append changes nothing; it only tells whether we may write without elevation.
        writable: fs::OpenOptions::new().append(true).open(file).is_ok(),
        has_backup: backup_path(file).is_file(),
    })
}

/// Walks every root (without following directory links) and returns each runtime once.
pub fn find(roots: &[PathBuf], mut on_root: impl FnMut(&Path)) -> Vec<Runtime> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for root in roots {
        on_root(root);
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let Ok(kind) = entry.file_type() else { continue };
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if kind.is_dir() {
                    if !SKIP_DIRS.contains(&name.as_ref()) {
                        stack.push(entry.path());
                    }
                    continue;
                }
                if name != "blocked.certs" && name != "blacklisted.certs" {
                    continue;
                }
                let path = entry.path();
                // Debian-style JDKs link lib/security/blocked.certs to /etc; follow file links only.
                if kind.is_symlink() && !path.is_file() {
                    continue;
                }
                let key = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                if !seen.insert(key) {
                    continue;
                }
                if let Some(rt) = inspect(&path) {
                    out.push(rt);
                }
            }
        }
    }
    out.sort_by(|a, b| a.home.cmp(&b.home));
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fresh empty directory under the system temp folder.
    pub fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("javafix-{}-{}-{}", tag, std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Creates `<root>/<name>/lib/security/blocked.certs` with the given body and a release file.
    pub fn fake_jdk(root: &Path, name: &str, body: &str) -> PathBuf {
        let sec = root.join(name).join("lib").join("security");
        fs::create_dir_all(&sec).unwrap();
        fs::write(root.join(name).join("release"), "JAVA_VERSION=\"21.0.3\"\nJAVA_RUNTIME_VERSION=\"21.0.3+9\"\n").unwrap();
        let file = sec.join("blocked.certs");
        fs::write(&file, body).unwrap();
        file
    }

    #[test]
    fn missing_ignores_case_whitespace_and_crlf() {
        let mut body = format!("{HEADER}\r\n");
        for f in &FINGERPRINTS[..10] {
            body.push_str(&format!("  {}\r\n", f.to_ascii_lowercase()));
        }
        assert_eq!(missing(&body), FINGERPRINTS[10..].to_vec());
        assert_eq!(missing(&format!("{HEADER}\n{}", FINGERPRINTS.join("\n"))).len(), 0);
    }

    #[test]
    fn states_versions_and_dedup() {
        let root = temp_dir("scan");
        fake_jdk(&root, "open", &format!("{HEADER}\nAAAA\n"));
        fake_jdk(&root, "done", &format!("{HEADER}\n{}\n", FINGERPRINTS.join("\n")));
        fake_jdk(&root, "odd", "something else\n");
        fs::create_dir_all(root.join("node_modules/x/lib/security")).unwrap();
        fs::write(root.join("node_modules/x/lib/security/blocked.certs"), HEADER).unwrap();
        fs::write(root.join("open/blocked.certs"), HEADER).unwrap(); // not under lib/security

        let found = find(&[root.clone(), root.join("open")], |_| {});
        let names: Vec<_> = found.iter().map(|r| (r.home.file_name().unwrap().to_string_lossy().into_owned(), r.state)).collect();
        assert_eq!(
            names,
            vec![("done".into(), State::Protected), ("odd".into(), State::Unknown), ("open".into(), State::Vulnerable)]
        );
        let open = &found[2];
        assert_eq!(open.version, "21.0.3+9");
        assert_eq!(open.missing.len(), 16);
        assert!(open.writable);
        assert!(!open.has_backup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn app_bundle_detection() {
        assert!(in_app_bundle(Path::new("/Applications/IntelliJ IDEA.app/Contents/jbr/Contents/Home/lib/security/blocked.certs")));
        assert!(!in_app_bundle(Path::new("/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home/lib/security/blocked.certs")));
    }
}
