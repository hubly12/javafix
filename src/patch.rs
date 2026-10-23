//! The only two places that write files: adding the missing fingerprints, and putting the backup back.

use crate::scan::{backup_path, missing, Runtime};
use std::fs;
use std::io::Write;

/// Keeps the original once, appends only the missing lines, then reads the file back to prove it.
pub fn apply(rt: &Runtime) -> Result<(), String> {
    let backup = backup_path(&rt.file);
    if !backup.exists() {
        fs::copy(&rt.file, &backup).map_err(|e| format!("backup: {e}"))?;
    }
    let bytes = fs::read(&rt.file).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes);
    let need = missing(&text);
    if need.is_empty() {
        return Ok(());
    }
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut add = String::new();
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        add.push_str(nl);
    }
    for f in &need {
        add.push_str(f);
        add.push_str(nl);
    }
    let mut file = fs::OpenOptions::new().append(true).open(&rt.file).map_err(|e| e.to_string())?;
    file.write_all(add.as_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    let after = fs::read(&rt.file).map_err(|e| e.to_string())?;
    if missing(&String::from_utf8_lossy(&after)).is_empty() {
        Ok(())
    } else {
        Err("verification after writing failed".into())
    }
}

/// Copies the backup over the file and removes the backup.
pub fn restore(rt: &Runtime) -> Result<(), String> {
    let backup = backup_path(&rt.file);
    if !backup.is_file() {
        return Err("no backup".into());
    }
    fs::copy(&backup, &rt.file).map_err(|e| e.to_string())?;
    fs::remove_file(&backup).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprints::{FINGERPRINTS, HEADER};
    use crate::scan::tests::{fake_jdk, temp_dir};
    use crate::scan::{inspect, State};

    #[test]
    fn apply_is_idempotent_keeps_one_backup_and_restore_round_trips() {
        let root = temp_dir("patch");
        let original = format!("{HEADER}\nAAAA\n{}", FINGERPRINTS[3]); // no trailing newline, one already present
        let file = fake_jdk(&root, "jdk", &original);

        let rt = inspect(&file).unwrap();
        assert_eq!((rt.state, rt.missing.len()), (State::NotBlocked, 15));
        apply(&rt).unwrap();
        apply(&inspect(&file).unwrap()).unwrap();

        let after = fs::read_to_string(&file).unwrap();
        assert!(after.starts_with(&format!("{original}\n")));
        assert_eq!(after.lines().filter(|l| l.len() == 64).count(), 16);
        assert_eq!(fs::read_to_string(backup_path(&file)).unwrap(), original);
        let rt = inspect(&file).unwrap();
        assert_eq!(rt.state, State::Blocked);
        assert!(rt.has_backup);

        restore(&rt).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), original);
        assert!(!backup_path(&file).exists());
        assert!(restore(&inspect(&file).unwrap()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn apply_keeps_crlf_files_crlf() {
        let root = temp_dir("crlf");
        let file = fake_jdk(&root, "jdk", &format!("{HEADER}\r\nAAAA\r\n"));
        apply(&inspect(&file).unwrap()).unwrap();
        let after = fs::read_to_string(&file).unwrap();
        assert_eq!(after.matches("\r\n").count(), after.matches('\n').count());
        fs::remove_dir_all(root).unwrap();
    }
}
