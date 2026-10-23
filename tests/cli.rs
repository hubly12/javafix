//! Drives the real binary with typed answers against fake Java runtimes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const HEADER: &str = "Algorithm=SHA-256";
const ONE: &str = "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("javafix-cli-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fake_jdk(root: &Path, name: &str, body: &str) -> PathBuf {
    let sec = root.join(name).join("lib").join("security");
    fs::create_dir_all(&sec).unwrap();
    fs::write(root.join(name).join("release"), "JAVA_RUNTIME_VERSION=\"21.0.3+9\"\n").unwrap();
    let file = sec.join("blocked.certs");
    fs::write(&file, body).unwrap();
    file
}

fn run(root: &Path, extra: &[&str], input: &str) -> (i32, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_javafix"))
        .args(["--lang", "en", "--scan-root"])
        .arg(root.join("jdks"))
        .args(extra)
        .env("JAVAFIX_LOG_DIR", root.join("logs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

fn backup(file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.bak-cve-2026-91403", file.display()))
}

#[test]
fn nothing_happens_without_consent() {
    let root = temp_dir("decline");
    let file = fake_jdk(&root.join("jdks"), "a", &format!("{HEADER}\n"));
    for input in ["3\n\n", "1\nn\n\n", "1\ny\nno\n\n", "", "1\nY"] {
        let (_, out) = run(&root, &[], input);
        assert_eq!(fs::read_to_string(&file).unwrap(), format!("{HEADER}\n"), "input {input:?}\n{out}");
        assert!(!backup(&file).exists());
    }
    let (_, out) = run(&root, &[], "1\nn\n\n");
    assert!(out.contains("Not scanning"), "{out}");
    assert!(!out.contains("searching:"), "scan must not start before consent\n{out}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn check_fix_and_restore_round_trip() {
    let root = temp_dir("flow");
    let jdks = root.join("jdks");
    let open = fake_jdk(&jdks, "open", &format!("{HEADER}\nAAAA\n"));
    let done = fake_jdk(&jdks, "done", &format!("{HEADER}\n{ONE}\n"));
    let locked = fake_jdk(&jdks, "locked", &format!("{HEADER}\n"));
    let odd = fake_jdk(&jdks, "odd", "not a block list\n");
    let mut perms = fs::metadata(&locked).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&locked, perms).unwrap();
    // `done` has one of 16; give it all so it counts as protected.
    let all = include_str!("../src/fingerprints.rs")
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"').map(|s| s[..64].to_string()))
        .collect::<Vec<_>>();
    assert_eq!(all.len(), 16);
    fs::write(&done, format!("{HEADER}\n{}\n", all.join("\n"))).unwrap();

    let (code, out) = run(&root, &["--check"], "");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("4 runtimes — 1 protected, 2 vulnerable, 0 need an app update, 1 unknown"), "{out}");
    assert!(out.contains("(needs administrator)"), "{out}");

    // scan yes, fix yes, elevation no
    let (_, out) = run(&root, &[], "1\ny\ny\nn\n\n");
    assert!(out.contains("1 fixed, 0 failed"), "{out}");
    let fixed = fs::read_to_string(&open).unwrap();
    assert!(fixed.starts_with(&format!("{HEADER}\nAAAA\n")));
    assert!(all.iter().all(|f| fixed.contains(f.as_str())));
    assert_eq!(fs::read_to_string(backup(&open)).unwrap(), format!("{HEADER}\nAAAA\n"));
    assert_eq!(fs::read_to_string(&locked).unwrap(), format!("{HEADER}\n"));
    assert_eq!(fs::read_to_string(&odd).unwrap(), "not a block list\n");
    assert!(!backup(&done).exists() && !backup(&odd).exists());

    let (code, out) = run(&root, &["--check"], "");
    assert_eq!(code, 2, "locked one is still open\n{out}");
    assert!(out.contains("2 protected, 1 vulnerable"), "{out}");

    // restore: scan yes, restore yes
    let (_, out) = run(&root, &["--restore"], "y\ny\n\n");
    assert!(out.contains("restored:"), "{out}");
    assert_eq!(fs::read_to_string(&open).unwrap(), format!("{HEADER}\nAAAA\n"));
    assert!(!backup(&open).exists());

    let logs: Vec<_> = fs::read_dir(root.join("logs")).unwrap().flatten().collect();
    assert!(!logs.is_empty());
    let mut perms = fs::metadata(&locked).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&locked, perms).unwrap();
    fs::remove_dir_all(root).unwrap();
}
