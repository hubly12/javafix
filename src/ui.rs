//! Console output, the two languages, questions, and the log file.

use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static KOREAN: AtomicBool = AtomicBool::new(false);
static COLOR: AtomicBool = AtomicBool::new(false);
static LOG: Mutex<Option<(File, PathBuf)>> = Mutex::new(None);

pub fn init(korean: bool, color: bool) {
    KOREAN.store(korean, Ordering::Relaxed);
    COLOR.store(color, Ordering::Relaxed);
}

pub fn korean() -> bool {
    KOREAN.load(Ordering::Relaxed)
}

/// Picks the Korean or English text.
pub fn t<'a>(ko: &'a str, en: &'a str) -> &'a str {
    if korean() { ko } else { en }
}

pub fn paint(text: &str, code: &str) -> String {
    if COLOR.load(Ordering::Relaxed) { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_string() }
}

pub fn red(s: &str) -> String { paint(s, "91") }
pub fn green(s: &str) -> String { paint(s, "92") }
pub fn yellow(s: &str) -> String { paint(s, "93") }
pub fn cyan(s: &str) -> String { paint(s, "96") }
pub fn dim(s: &str) -> String { paint(s, "90") }

/// Reads one answer from stdin; end of input counts as an empty answer (= no).
pub fn ask(question: &str) -> String {
    print!("\n{} ", yellow(question));
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => {
            println!();
            String::new()
        }
        Ok(_) => line.trim().to_string(),
    }
}

/// Only an explicit yes counts as consent.
pub fn confirm(question: &str) -> bool {
    let a = ask(&format!("{question} {}", t("[Y = 예 / 그 외 = 아니오]", "[Y = yes / anything else = no]")));
    matches!(a.to_ascii_lowercase().as_str(), "y" | "yes")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Opens `<dir>/log-<unix time>.txt`; logging silently stays off if that fails.
pub fn open_log(dir: Option<PathBuf>) {
    let Some(dir) = dir else { return };
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(format!("log-{}-{}.txt", now(), std::process::id()));
    if let Ok(file) = File::create(&path) {
        *LOG.lock().unwrap() = Some((file, path));
    }
}

pub fn log_path() -> Option<PathBuf> {
    LOG.lock().unwrap().as_ref().map(|(_, p)| p.clone())
}

pub fn log(line: &str) {
    if let Some((file, _)) = LOG.lock().unwrap().as_mut() {
        let _ = writeln!(file, "{} {}", now(), line);
    }
}
