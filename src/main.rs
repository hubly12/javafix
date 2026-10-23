//! JavaFix: checks every Java runtime on this computer for CVE-2026-91403 and, only with the user's consent,
//! blocks the 16 affected certificates in each runtime's block list. No network access, no telemetry.

mod fingerprints;
mod patch;
mod platform;
mod scan;
mod ui;

use scan::{Runtime, State};
use std::path::PathBuf;
use std::process::ExitCode;
use ui::{cyan, dim, green, red, t, yellow};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Fix,
    Restore,
}

struct Args {
    korean: Option<bool>,
    roots: Vec<PathBuf>,
    mode: Option<Mode>,
    elevated: bool,
    check: bool,
    no_pause: bool,
}

const USAGE: &str = "javafix — CVE-2026-91403 checker/fixer for Java runtimes

Usage: javafix [options]
  (no options)          interactive: explain, ask, scan, ask again, fix
  --check               scan only and print the result; exit 0 = all protected, 2 = something to fix
  --restore             interactive: put back the files this tool changed
  --lang ko|en          language (default: system language)
  --scan-root <dir>     scan this folder instead of the usual places (repeatable)
  --no-pause            do not wait for Enter before exiting
  -h, --help / -V, --version

사용법: 인수 없이 실행하면 설명 → 검사 동의 → 결과 → 수정 동의 순서로 진행합니다.";

fn parse_args() -> Result<Args, String> {
    let mut a = Args { korean: None, roots: Vec::new(), mode: None, elevated: false, check: false, no_pause: false };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(USAGE.to_string()),
            "-V" | "--version" => return Err(format!("javafix {}", env!("CARGO_PKG_VERSION"))),
            "--check" => a.check = true,
            "--restore" => a.mode = Some(Mode::Restore),
            "--fix" => a.mode = Some(Mode::Fix),
            "--elevated" => a.elevated = true,
            "--no-pause" => a.no_pause = true,
            "--lang" => match it.next().as_deref() {
                Some("ko") => a.korean = Some(true),
                Some("en") => a.korean = Some(false),
                _ => return Err("--lang needs ko or en".into()),
            },
            "--scan-root" => a.roots.push(PathBuf::from(it.next().ok_or("--scan-root needs a folder")?)),
            other => return Err(format!("unknown option: {other}\n\n{USAGE}")),
        }
    }
    Ok(a)
}

fn intro() {
    println!("{}", cyan("=============================================================="));
    println!("{}", cyan(t("  Java 보안 점검 도구 (CVE-2026-91403)", "  Java security check (CVE-2026-91403)")));
    println!("{}", cyan("=============================================================="));
    println!();
    println!("{}", t("이 도구가 하는 일", "What this tool does"));
    println!("{}", t(
        " - 2026년 10월, eMudhra 인증기관의 중간 인증서 8개(교차 서명 포함 16개)의 개인키가 노출된\n   것이 밝혀졌습니다. Java는 아직 이 인증서를 믿기 때문에, 같은 네트워크의 공격자가 아무\n   사이트(예: 마인크래프트 로그인 서버)로 위장할 수 있습니다.",
        " - In October 2026 the private keys of 8 eMudhra intermediate CAs (16 certificates with cross-signs)\n   turned out to be recoverable. Java still trusts them, so an attacker on your network can pose as\n   any website (for example the Minecraft login servers).",
    ));
    println!("{}", t(
        " - PC에 설치된 Java(마인크래프트 런처, 모드 런처, 개발 도구 포함)를 찾아 이 16개 인증서가\n   차단되어 있는지 확인합니다.",
        " - It finds the Java runtimes on this computer (Minecraft launchers, mod launchers, developer tools)\n   and checks whether these 16 certificates are blocked.",
    ));
    println!("{}", t(
        " - 수정은 OpenJDK가 안내한 임시 조치와 같습니다: 각 Java의 blocked.certs 끝에 인증서 지문\n   16줄을 추가합니다. 다른 파일은 건드리지 않습니다.",
        " - The fix is the stopgap published by OpenJDK: 16 certificate fingerprints are appended to each\n   runtime's blocked.certs. No other file is touched.",
    ));
    println!();
    println!("{}", t("약속", "Promises"));
    println!("{}", t(" - 인터넷에 접속하지 않고, 어떤 정보도 밖으로 보내지 않습니다.", " - No internet access; nothing is sent anywhere."));
    println!("{}", t(
        " - 바꾸는 파일마다 원본을 \"*.bak-cve-2026-91403\" 으로 백업하며, 되돌리기 메뉴로 복구할 수 있습니다.",
        " - Every changed file is backed up as \"*.bak-cve-2026-91403\" and can be put back from the menu.",
    ));
    println!("{}", t(" - 검사와 수정은 각각 동의를 받은 뒤에만 진행합니다.", " - Scanning and fixing each start only after you agree."));
    if let Some(p) = ui::log_path() {
        println!("{}", dim(&format!("{}{}", t(" - 기록: ", " - Log: "), p.display())));
    }
}

fn scan(args: &Args) -> Vec<Runtime> {
    let roots = if args.roots.is_empty() { platform::default_roots() } else { args.roots.clone() };
    println!();
    println!("{}", t("Java를 찾고 있습니다. 1~3분 걸릴 수 있습니다...", "Looking for Java runtimes. This can take 1-3 minutes..."));
    let list = scan::find(&roots, |r| println!("{}", dim(&format!("  {}{}", t("찾는 중: ", "searching: "), r.display()))));
    for r in &list {
        ui::log(&format!("SCAN {:?} missing={} {} {}", r.state, r.missing.len(), r.version, r.file.display()));
    }
    list
}

fn show(list: &[Runtime]) {
    println!();
    for (i, r) in list.iter().enumerate() {
        let tag = match r.state {
            State::Protected => green(t("[보호됨]    ", "[protected] ")),
            State::Vulnerable => red(t("[취약]      ", "[vulnerable]")),
            State::AppBundle => red(t("[앱 업데이트]", "[update app]")),
            State::Unknown => yellow(t("[확인 불가] ", "[unknown]   ")),
        };
        let note = if r.state == State::Vulnerable && !r.writable { t("  (관리자 권한 필요)", "  (needs administrator)") } else { "" };
        println!("{:>3}. {} Java {}{}", i + 1, tag, r.version, note);
        println!("     {}", dim(&r.home.display().to_string()));
    }
}

fn count(list: &[Runtime], s: State) -> usize {
    list.iter().filter(|r| r.state == s).count()
}

fn summary(list: &[Runtime]) {
    println!();
    if korean_ui() {
        println!(
            "결과: Java {}개 중 보호됨 {}개, 취약 {}개, 앱 업데이트 필요 {}개, 확인 불가 {}개",
            list.len(), count(list, State::Protected), count(list, State::Vulnerable), count(list, State::AppBundle), count(list, State::Unknown)
        );
    } else {
        println!(
            "Result: {} runtimes — {} protected, {} vulnerable, {} need an app update, {} unknown",
            list.len(), count(list, State::Protected), count(list, State::Vulnerable), count(list, State::AppBundle), count(list, State::Unknown)
        );
    }
    if count(list, State::AppBundle) > 0 {
        println!("{}", yellow(t(
            " \"앱 업데이트\"는 서명된 macOS 앱 안의 Java라 바꾸지 않습니다. 해당 앱을 최신 버전으로 업데이트하세요.",
            " \"update app\" runtimes sit inside signed macOS apps and are not modified; update those apps instead.",
        )));
    }
    if count(list, State::Unknown) > 0 {
        println!("{}", yellow(t(
            " \"확인 불가\"는 형식이 다른 파일이라 건드리지 않습니다. 해당 프로그램을 최신 버전으로 업데이트하세요.",
            " \"unknown\" files have another format and are left alone; update those programs instead.",
        )));
    }
}

fn korean_ui() -> bool {
    ui::korean()
}

fn apply_all(targets: &[&Runtime]) {
    let (mut ok, mut failed) = (0, 0);
    for r in targets {
        match patch::apply(r) {
            Ok(()) => {
                ok += 1;
                ui::log(&format!("FIXED {}", r.file.display()));
                println!("  {} {}", green(t("수정됨:", "fixed:")), r.home.display());
            }
            Err(e) => {
                failed += 1;
                ui::log(&format!("FAILED {} {e}", r.file.display()));
                println!("  {} {} - {e}", red(t("실패:", "failed:")), r.home.display());
            }
        }
    }
    println!("{}", cyan(&if korean_ui() { format!("수정 {ok}개, 실패 {failed}개") } else { format!("{ok} fixed, {failed} failed") }));
}

fn restore_all(targets: &[&Runtime]) {
    for r in targets {
        match patch::restore(r) {
            Ok(()) => {
                ui::log(&format!("RESTORED {}", r.file.display()));
                println!("  {} {}", green(t("되돌림:", "restored:")), r.home.display());
            }
            Err(e) => {
                ui::log(&format!("RESTORE-FAILED {} {e}", r.file.display()));
                println!("  {} {} - {e}", red(t("실패:", "failed:")), r.home.display());
            }
        }
    }
}

/// Arguments for the elevated copy: same language and roots, the chosen mode, no menu.
fn elevated_args(args: &Args, mode: Mode) -> Vec<String> {
    let mut v = vec!["--elevated".to_string(), if mode == Mode::Fix { "--fix" } else { "--restore" }.to_string()];
    v.push("--lang".into());
    v.push(if korean_ui() { "ko" } else { "en" }.into());
    for r in &args.roots {
        v.push("--scan-root".into());
        v.push(r.display().to_string());
    }
    if !cfg!(windows) {
        v.push("--no-pause".into()); // sudo runs in this terminal; this process pauses afterwards
    }
    v
}

fn ask_elevation(args: &Args, mode: Mode, n: usize) {
    let (q, done) = if cfg!(windows) {
        (
            if korean_ui() {
                format!("{n}개는 Program Files 등에 있어 관리자 권한이 필요합니다. 관리자 권한으로 다시 실행할까요?\n(Windows 확인 창이 뜨고, 새 창에서 한 번 더 동의를 받습니다)")
            } else {
                format!("{n} of them need administrator rights (Program Files etc.). Run again as administrator?\n(Windows asks for confirmation; the new window asks for your consent again)")
            },
            t("새 관리자 창에서 계속하세요.", "Continue in the new administrator window."),
        )
    } else {
        (
            if korean_ui() {
                format!("{n}개는 시스템 폴더에 있어 관리자(sudo) 권한이 필요합니다. sudo로 다시 실행할까요?\n(Mac 로그인 암호를 묻고, 실행 후 한 번 더 동의를 받습니다)")
            } else {
                format!("{n} of them are in system folders and need sudo. Run again with sudo?\n(asks for your login password, then asks for your consent again)")
            },
            "",
        )
    };
    if !ui::confirm(&q) {
        println!("{}", t("관리자 권한이 필요한 항목은 바꾸지 않았습니다.", "Items that need elevation were not changed."));
        return;
    }
    ui::log("consent: elevate");
    match platform::relaunch_elevated(&elevated_args(args, mode)) {
        Ok(()) => {
            if !done.is_empty() {
                println!("{done}");
            }
        }
        Err(e) => println!("{} {e}", red(t("권한 상승이 취소되었거나 실패했습니다:", "Elevation was cancelled or failed:"))),
    }
}

fn run_fix(args: &Args) {
    if !ui::confirm(t(
        "위 내용을 확인했고, 이 PC의 Java를 검사하는 데 동의합니까? (파일을 읽기만 합니다)",
        "Have you read the above, and do you agree to scan the Java runtimes on this computer? (read-only)",
    )) {
        println!("{}", t("검사하지 않고 종료합니다.", "Not scanning. Bye."));
        return;
    }
    ui::log("consent: scan");
    let list = scan(args);
    if list.is_empty() {
        println!("\n{}", green(t("설치된 Java를 찾지 못했습니다. 바꿀 것이 없습니다.", "No Java runtime found. Nothing to do.")));
        return;
    }
    show(&list);
    summary(&list);
    let open: Vec<&Runtime> = list.iter().filter(|r| r.state == State::Vulnerable).collect();
    if open.is_empty() {
        println!("\n{}", green(t("수정이 필요한 Java가 없습니다.", "No runtime needs fixing.")));
        return;
    }
    println!();
    println!("{}", cyan(t("수정하면 일어나는 일", "What fixing does")));
    if korean_ui() {
        println!(" - [취약] Java {}개의 blocked.certs 끝에 인증서 지문 16줄을 추가합니다.", open.len());
    } else {
        println!(" - Appends the 16 certificate fingerprints to blocked.certs of the {} [vulnerable] runtimes.", open.len());
    }
    println!("{}", t(
        " - 바꾸기 전 원본을 같은 폴더에 \"blocked.certs.bak-cve-2026-91403\" 으로 복사해 둡니다.",
        " - The original is first copied to \"blocked.certs.bak-cve-2026-91403\" in the same folder.",
    ));
    println!("{}", t(
        " - 차단되는 것은 문제의 인증서 16개뿐이라 일반 사이트와 마인크래프트 접속에는 영향이 없습니다.",
        " - Only these 16 certificates are blocked; normal websites and Minecraft are not affected.",
    ));
    println!("{}", t(
        " - 런처가 Java를 다시 내려받으면 원래대로 돌아갈 수 있습니다. 그때는 이 도구를 다시 실행하세요.",
        " - A launcher that re-downloads its Java may undo this; just run the tool again.",
    ));
    println!("{}", t(
        " - 근본 해결은 Java/런처를 최신 버전(25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 이상)으로 올리는 것입니다.",
        " - The real fix is updating Java/launchers (25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 or newer).",
    ));
    let running = platform::running_java();
    if running > 0 {
        println!();
        if korean_ui() {
            println!("{}", yellow(&format!("지금 실행 중인 Java 프로그램이 {running}개 있습니다 (마인크래프트 등).")));
        } else {
            println!("{}", yellow(&format!("{running} Java programs are running right now (Minecraft etc.).")));
        }
        println!("{}", yellow(t(
            "수정은 Java 프로그램을 새로 시작해야 적용됩니다. 이 도구는 프로그램을 종료하지 않습니다.",
            "Changes apply when those programs restart. This tool does not close them.",
        )));
    }

    let mine: Vec<&Runtime> = open.iter().copied().filter(|r| r.writable).collect();
    let locked: Vec<&Runtime> = open.iter().copied().filter(|r| !r.writable).collect();
    if !mine.is_empty() {
        let q = if korean_ui() {
            format!("위 [취약] 항목 중 지금 권한으로 고칠 수 있는 {}개를 수정할까요?", mine.len())
        } else {
            format!("Fix the {} vulnerable runtimes that can be changed with your current rights?", mine.len())
        };
        if ui::confirm(&q) {
            ui::log("consent: fix");
            apply_all(&mine);
        } else {
            println!("{}", t("수정하지 않았습니다.", "Nothing was changed."));
        }
    }
    if !locked.is_empty() {
        if args.elevated {
            println!("{}", yellow(t("(관리자 권한으로도 쓸 수 없는 파일입니다)", "(these files are not writable even with elevation)")));
            for r in &locked {
                println!("     {}", dim(&r.file.display().to_string()));
            }
        } else {
            ask_elevation(args, Mode::Fix, locked.len());
        }
    }
}

fn run_restore(args: &Args) {
    if !ui::confirm(t(
        "이 도구가 만든 백업을 찾기 위해 Java를 검사할까요? (파일을 읽기만 합니다)",
        "Scan the Java runtimes for backups made by this tool? (read-only)",
    )) {
        return;
    }
    let list: Vec<Runtime> = scan(args).into_iter().filter(|r| r.has_backup).collect();
    if list.is_empty() {
        println!("\n{}", green(t("이 도구가 만든 백업이 없습니다. 되돌릴 것이 없습니다.", "No backups from this tool. Nothing to restore.")));
        return;
    }
    println!("\n{}", t("백업이 있는 Java:", "Runtimes with a backup:"));
    show(&list);
    let mine: Vec<&Runtime> = list.iter().filter(|r| r.writable).collect();
    let locked: Vec<&Runtime> = list.iter().filter(|r| !r.writable).collect();
    if !mine.is_empty() {
        let q = if korean_ui() {
            format!("{}개를 원래 파일로 되돌릴까요? (16개 인증서 차단이 풀립니다)", mine.len())
        } else {
            format!("Put back the original file for {}? (the 16 certificates will be trusted again)", mine.len())
        };
        if ui::confirm(&q) {
            ui::log("consent: restore");
            restore_all(&mine);
        }
    }
    if !locked.is_empty() && !args.elevated {
        ask_elevation(args, Mode::Restore, locked.len());
    }
}

fn run_check(args: &Args) -> ExitCode {
    let list = scan(args);
    show(&list);
    summary(&list);
    if list.iter().any(|r| matches!(r.state, State::Vulnerable | State::AppBundle)) { ExitCode::from(2) } else { ExitCode::SUCCESS }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            println!("{msg}");
            return if msg.starts_with("unknown") || msg.starts_with("--") { ExitCode::from(64) } else { ExitCode::SUCCESS };
        }
    };
    let color = platform::enable_ansi();
    ui::init(args.korean.unwrap_or_else(platform::system_is_korean), color);
    ui::open_log(platform::log_dir());
    ui::log(&format!("start version={} elevated={} check={}", env!("CARGO_PKG_VERSION"), args.elevated, args.check));

    if args.check {
        return run_check(&args);
    }
    intro();
    if args.elevated {
        println!("\n{}", yellow(t("관리자 권한으로 실행 중입니다.", "Running with elevated rights.")));
    }
    let mode = match args.mode {
        Some(m) => Some(m),
        None => {
            println!();
            println!("{}", t("  1. 검사하고 필요하면 수정하기", "  1. Check, and fix if needed"));
            println!("{}", t("  2. 이 도구로 바꾼 것을 되돌리기", "  2. Undo what this tool changed"));
            println!("{}", t("  3. 아무것도 하지 않고 종료", "  3. Quit without changing anything"));
            match ui::ask(t("번호를 입력하세요:", "Enter a number:")).as_str() {
                "1" => Some(Mode::Fix),
                "2" => Some(Mode::Restore),
                _ => None,
            }
        }
    };
    match mode {
        Some(Mode::Fix) => run_fix(&args),
        Some(Mode::Restore) => run_restore(&args),
        None => println!("{}", t("종료합니다. 아무것도 바꾸지 않았습니다.", "Bye. Nothing was changed.")),
    }
    ui::log("end");
    if !args.no_pause {
        ui::ask(t("엔터를 누르면 창이 닫힙니다.", "Press Enter to close."));
    }
    ExitCode::SUCCESS
}
