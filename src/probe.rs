//! Optional live check: runs each runtime's own `java` with a tiny bundled class (probe/JavafixProbe.java,
//! compiled for Java 8) that connects to two hosts serving certificates from the compromised CAs and to one
//! normal host. A runtime is only "safe" when it refuses both test hosts while the normal host still works.
//! This is the only part of javafix that uses the network, and it runs only after its own consent.

use crate::scan::Runtime;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Hosts from https://emudhra.we-have-a-problem.com/ that present chains through EM DV TLS CA - G3B.
pub const TEST_HOSTS: [&str; 2] = ["dv-g3b-emudhra.we-have-a-problem.com", "dv-g3b-aaa-emudhra.we-have-a-problem.com"];
/// Control: must be reachable, otherwise the result says nothing.
pub const CONTROL_HOST: &str = "sessionserver.mojang.com";

const CLASS: &[u8] = include_bytes!("../probe/JavafixProbe.class");
const TIMEOUT: Duration = Duration::from_secs(60);
const PARALLEL: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Both test hosts refused, control reachable.
    Safe,
    /// At least one test host was trusted.
    Vulnerable,
    /// No usable answer (offline, control failed, Java could not start, timeout); the reason is kept.
    Inconclusive(String),
}

/// Reads the probe's output lines into a verdict.
pub fn verdict(output: &str) -> Verdict {
    let mut status = std::collections::HashMap::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(kind), Some(host)) = (parts.next(), parts.next()) {
            status.insert(host.to_string(), (kind.to_string(), parts.next().unwrap_or("").to_string()));
        }
    }
    if TEST_HOSTS.iter().any(|h| status.get(*h).is_some_and(|(k, _)| k == "ACCEPTED")) {
        return Verdict::Vulnerable;
    }
    match status.get(CONTROL_HOST) {
        Some((k, _)) if k == "ACCEPTED" => {}
        Some((_, why)) => return Verdict::Inconclusive(format!("{CONTROL_HOST}: {why}")),
        None => return Verdict::Inconclusive("no output".into()),
    }
    for h in TEST_HOSTS {
        match status.get(h) {
            Some((k, _)) if k == "REJECTED" => {}
            Some((_, why)) => return Verdict::Inconclusive(format!("{h}: {why}")),
            None => return Verdict::Inconclusive(format!("{h}: no answer")),
        }
    }
    Verdict::Safe
}

pub fn java_binary(home: &Path) -> Option<PathBuf> {
    let name = if cfg!(windows) { "java.exe" } else { "java" };
    let p = home.join("bin").join(name);
    p.is_file().then_some(p)
}

fn run_one(java: &Path, class_dir: &Path) -> Verdict {
    let mut cmd = Command::new(java);
    cmd.arg("-cp").arg(class_dir).arg("JavafixProbe").args(TEST_HOSTS).arg(CONTROL_HOST);
    // Options injected through the environment could change trust settings; test the runtime's defaults.
    for var in ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"] {
        cmd.env_remove(var);
    }
    let mut child = match cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(e) => return Verdict::Inconclusive(format!("java: {e}")),
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Verdict::Inconclusive("timeout".into());
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => return Verdict::Inconclusive(e.to_string()),
        }
    }
    match child.wait_with_output() {
        Ok(out) => verdict(&String::from_utf8_lossy(&out.stdout)),
        Err(e) => Verdict::Inconclusive(e.to_string()),
    }
}

/// Checks every runtime (a few at a time) and returns verdicts in the same order.
/// The class file lives in a fresh temp folder that is removed afterwards.
pub fn check_all(list: &[&Runtime], mut on_done: impl FnMut(&Runtime, &Verdict)) -> Vec<Verdict> {
    let dir = std::env::temp_dir().join(format!("javafix-probe-{}", std::process::id()));
    let ready = fs::create_dir_all(&dir).and_then(|_| fs::write(dir.join("JavafixProbe.class"), CLASS));
    let mut out = Vec::with_capacity(list.len());
    if let Err(e) = ready {
        for r in list {
            let v = Verdict::Inconclusive(format!("temp folder: {e}"));
            on_done(r, &v);
            out.push(v);
        }
        return out;
    }
    for chunk in list.chunks(PARALLEL) {
        let results: Vec<Verdict> = thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|r| {
                    let dir = &dir;
                    s.spawn(move || match java_binary(&r.home) {
                        Some(java) => run_one(&java, dir),
                        None => Verdict::Inconclusive("no bin/java".into()),
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or(Verdict::Inconclusive("crashed".into()))).collect()
        });
        for (r, v) in chunk.iter().zip(results) {
            on_done(r, &v);
            out.push(v);
        }
    }
    let _ = fs::remove_dir_all(&dir);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "dv-g3b-emudhra.we-have-a-problem.com";
    const B: &str = "dv-g3b-aaa-emudhra.we-have-a-problem.com";

    #[test]
    fn verdicts() {
        let ok = format!("REJECTED {A} CertPathValidatorException\nREJECTED {B} SunCertPathBuilderException\nACCEPTED {CONTROL_HOST} 403\n");
        assert_eq!(verdict(&ok), Verdict::Safe);
        let bad = format!("ACCEPTED {A} 200\nREJECTED {B} X\nACCEPTED {CONTROL_HOST} 403\n");
        assert_eq!(verdict(&bad), Verdict::Vulnerable);
        let offline = format!("ERROR {A} UnknownHostException\nERROR {B} UnknownHostException\nERROR {CONTROL_HOST} UnknownHostException\n");
        assert!(matches!(verdict(&offline), Verdict::Inconclusive(_)));
        let tls_old = format!("ERROR {A} SSLHandshakeException\nREJECTED {B} X\nACCEPTED {CONTROL_HOST} 403\n");
        assert!(matches!(verdict(&tls_old), Verdict::Inconclusive(_)), "an unrelated TLS error is not a refusal");
        assert!(matches!(verdict(""), Verdict::Inconclusive(_)));
    }

    #[test]
    fn bundled_class_is_java_8_bytecode() {
        assert_eq!(&CLASS[..4], &[0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(u16::from_be_bytes([CLASS[6], CLASS[7]]), 52, "class file major version 52 = Java 8");
    }
}
