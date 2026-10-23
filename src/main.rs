//! javafix: a stopgap for CVE-2026-91403. Finds Java runtimes, reports whether their block list contains the 16
//! affected certificates, can check each runtime with a real TLS connection, and, only with the user's consent,
//! adds the missing entries to the block list. It does not update Java, edit trust stores or enable revocation.

mod fingerprints;
mod patch;
mod platform;
mod probe;
mod scan;
mod ui;

use probe::Verdict;
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
    verify: bool,
    no_pause: bool,
}

const USAGE: &str = "javafix — CVE-2026-91403 stopgap for Java runtimes (block-list based)

Usage: javafix [options]
  (no options)          interactive: explain, ask, scan, optional live check, ask again, fix
  --check               scan only and print the result; exit 0 = every block list has all 16 entries,
                        2 = something needs attention (missing entries, app to update, live check failed)
  --verify              with --check: also run the live connection check (uses the network)
  --restore             interactive: put back the files this tool changed
  --lang ko|en          language (default: system language)
  --scan-root <dir>     scan this folder instead of the usual places (repeatable)
  --no-pause            do not wait for Enter before exiting
  -h, --help / -V, --version

사용법: 인수 없이 실행하면 설명 → 검사 동의 → 결과 → (선택) 실제 연결 검사 → 수정 동의 순서로 진행합니다.";

fn parse_args() -> Result<Args, String> {
    let mut a = Args { korean: None, roots: Vec::new(), mode: None, elevated: false, check: false, verify: false, no_pause: false };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(USAGE.to_string()),
            "-V" | "--version" => return Err(format!("javafix {}", env!("CARGO_PKG_VERSION"))),
            "--check" => a.check = true,
            "--verify" => a.verify = true,
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

fn korean_ui() -> bool {
    ui::korean()
}

fn intro() {
    println!("{}", cyan("=============================================================="));
    println!("{}", cyan(t("  Java 인증서 취약점 임시 대응 도구 (CVE-2026-91403)", "  Java certificate stopgap (CVE-2026-91403)")));
    println!("{}", cyan("=============================================================="));
    println!();
    println!("{}", t("무엇이 문제인가요", "The problem"));
    println!("{}", t(
        " - 2026년 10월, eMudhra 인증기관의 중간 인증서 8개(교차 서명 포함 16개)의 개인키가 노출된\n   것이 밝혀졌습니다. 수정되지 않은 Java는 이 인증서를 믿기 때문에, 같은 네트워크의 공격자가\n   아무 사이트(예: 마인크래프트 로그인 서버)로 위장할 수 있습니다.",
        " - In October 2026 the private keys of 8 eMudhra intermediate CAs (16 certificates with cross-signs)\n   turned out to be recoverable. Unpatched Java trusts them, so an attacker on your network can pose\n   as any website (for example the Minecraft login servers).",
    ));
    println!();
    println!("{}", t("이 도구가 하는 일", "What this tool does"));
    println!("{}", t(
        " 1. PC의 Java(마인크래프트 런처, 모드 런처, 개발 도구 포함)를 찾아, 각 Java의 차단 목록\n    (blocked.certs)에 문제의 인증서 16개가 들어 있는지 파일을 읽어 확인합니다.",
        " 1. Finds the Java runtimes on this computer (Minecraft launchers, mod launchers, developer tools)\n    and reads each block list (blocked.certs) to see whether the 16 certificates are in it.",
    ));
    println!("{}", t(
        " 2. (선택) 각 Java를 실제로 실행해, 문제의 인증서를 쓰는 테스트 사이트 접속이 거부되는지\n    확인합니다. 파일 검사보다 정확합니다.",
        " 2. (optional) Runs each Java for real and checks that test sites using these certificates are\n    refused. This is more reliable than reading the file.",
    ));
    println!("{}", t(
        " 3. 동의하면 차단 목록에 빠진 인증서를 추가합니다. OpenJDK가 안내한 임시 조치입니다.",
        " 3. With your consent, adds the missing entries to the block list (the stopgap published by OpenJDK).",
    ));
    println!();
    println!("{}", yellow(t("이 도구의 한계 (꼭 읽어 주세요)", "Limits (please read)")));
    println!("{}", t(
        " - 차단 목록 방식의 임시 대응입니다. Java 자체를 업데이트하지 않습니다.\n   근본 해결은 Java/런처를 수정된 버전으로 업데이트하는 것입니다.",
        " - This is a block-list stopgap. It does not update Java; updating Java/launchers is the real fix.",
    ));
    println!("{}", t(
        " - 신뢰 저장소(cacerts)의 루트 인증서를 지우거나, 인증서 폐기 검사(revocation)를 켜지 않습니다.\n   폐기 검사는 폐기 목록 서버에 닿지 않으면 마인크래프트 접속까지 실패할 수 있어 자동으로 켜지 않습니다.",
        " - It does not remove root certificates from the trust store (cacerts) and does not enable revocation\n   checking, which can break Minecraft logins when revocation servers are unreachable.",
    ));
    println!("{}", t(
        " - \"차단 목록 적용\"은 16개가 차단 목록에 있다는 뜻일 뿐, 그 Java가 모든 면에서 안전하다는 뜻은\n   아닙니다. 실제 동작은 2번 실제 연결 검사로 확인하세요.",
        " - \"blocklist applied\" only means the 16 entries are in the block list, not that the runtime is safe\n   in every respect. Use the live check (2) to see real behaviour.",
    ));
    println!();
    println!("{}", t("약속", "Promises"));
    println!("{}", t(
        " - 실제 연결 검사를 고른 경우에만 인터넷에 접속하며, 그때도 테스트 사이트 2곳과 Mojang 세션 서버에\n   접속만 해 보고 어떤 정보도 보내지 않습니다.",
        " - The network is used only for the live check you choose, which connects to 2 test sites and the\n   Mojang session server and sends no information.",
    ));
    println!("{}", t(
        " - 바꾸는 파일마다 원본을 \"*.bak-cve-2026-91403\" 으로 백업하며, 되돌리기 메뉴로 복구할 수 있습니다.",
        " - Every changed file is backed up as \"*.bak-cve-2026-91403\" and can be put back from the menu.",
    ));
    println!("{}", t(" - 검사, 연결 검사, 수정은 각각 동의를 받은 뒤에만 진행합니다.", " - Scanning, the live check and fixing each start only after you agree."));
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

fn state_tag(s: State) -> String {
    match s {
        State::Blocked => green(t("[차단 목록 적용]", "[blocklist applied]")),
        State::NotBlocked => red(t("[차단 목록 없음]", "[blocklist missing]")),
        State::AppBundle => red(t("[앱 업데이트]  ", "[update the app]  ")),
        State::Unknown => yellow(t("[확인 불가]    ", "[unknown format]  ")),
    }
}

fn verdict_text(v: &Verdict) -> String {
    match v {
        Verdict::Safe => green(t("실제 연결 검사: 안전 (위장 인증서 거부)", "live check: safe (fake certificates refused)")),
        Verdict::Vulnerable => red(t("실제 연결 검사: 취약 (위장 인증서를 믿음)", "live check: VULNERABLE (fake certificate trusted)")),
        Verdict::Inconclusive(why) => yellow(&format!("{} ({why})", t("실제 연결 검사: 판단 불가", "live check: inconclusive"))),
    }
}

fn show(list: &[Runtime]) {
    println!();
    for (i, r) in list.iter().enumerate() {
        let note = if r.state == State::NotBlocked && !r.writable { t("  (관리자 권한 필요)", "  (needs administrator)") } else { "" };
        println!("{:>3}. {} Java {}{}", i + 1, state_tag(r.state), r.version, note);
        println!("     {}", dim(&r.home.display().to_string()));
    }
}

fn count(list: &[Runtime], s: State) -> usize {
    list.iter().filter(|r| r.state == s).count()
}

fn summary(list: &[Runtime]) {
    println!();
    let (b, n, a, u) = (count(list, State::Blocked), count(list, State::NotBlocked), count(list, State::AppBundle), count(list, State::Unknown));
    if korean_ui() {
        println!("파일 검사 결과: Java {}개 중 차단 목록 적용 {b}개, 차단 목록 없음 {n}개, 앱 업데이트 필요 {a}개, 확인 불가 {u}개", list.len());
    } else {
        println!("File check: {} runtimes — {b} blocklist applied, {n} blocklist missing, {a} need an app update, {u} unknown format", list.len());
    }
    println!("{}", dim(t(
        " (파일 검사는 차단 목록만 봅니다. 실제로 막히는지는 실제 연결 검사로 확인할 수 있습니다.)",
        " (The file check only reads block lists; the live check shows whether connections are really refused.)",
    )));
    if a > 0 {
        println!("{}", yellow(t(
            " \"앱 업데이트\"는 서명된 macOS 앱 안의 Java라 바꾸지 않습니다. 해당 앱을 최신 버전으로 업데이트하세요.",
            " \"update the app\" runtimes sit inside signed macOS apps and are not modified; update those apps instead.",
        )));
    }
    if u > 0 {
        println!("{}", yellow(t(
            " \"확인 불가\"는 형식이 다른 파일이라 건드리지 않습니다. 해당 프로그램을 최신 버전으로 업데이트하세요.",
            " \"unknown format\" files are left alone; update those programs instead.",
        )));
    }
}

/// Runs the live check on the given runtimes and prints one line each.
fn live_check(list: &[&Runtime]) -> Vec<Verdict> {
    println!();
    if korean_ui() {
        println!("실제 연결 검사 중입니다 (Java {}개, 몇 분 걸릴 수 있습니다)...", list.len());
    } else {
        println!("Running the live check ({} runtimes, this can take a few minutes)...", list.len());
    }
    let verdicts = probe::check_all(list, |r, v| {
        ui::log(&format!("LIVE {v:?} {}", r.home.display()));
        println!("  {}  Java {}", verdict_text(v), r.version);
        println!("     {}", dim(&r.home.display().to_string()));
    });
    let n = |f: fn(&Verdict) -> bool| verdicts.iter().filter(|v| f(v)).count();
    let (safe, bad, unk) = (n(|v| *v == Verdict::Safe), n(|v| *v == Verdict::Vulnerable), n(|v| matches!(v, Verdict::Inconclusive(_))));
    println!();
    if korean_ui() {
        println!("실제 연결 검사 결과: 안전 {safe}개, 취약 {bad}개, 판단 불가 {unk}개");
    } else {
        println!("Live check: {safe} safe, {bad} vulnerable, {unk} inconclusive");
    }
    if unk > 0 {
        println!("{}", dim(t(
            " (판단 불가: 인터넷 연결이 없거나, 아주 오래된 Java라 접속 자체를 못 하거나, 실행 파일이 없는 경우입니다.)",
            " (inconclusive: offline, a Java too old to connect at all, or no java executable.)",
        )));
    }
    verdicts
}

fn ask_live_check(n: usize) -> bool {
    let q = if korean_ui() {
        format!(
            "실제 연결 검사도 할까요? 찾은 Java {n}개를 하나씩 실행해 테스트 사이트 2곳(we-have-a-problem.com)과\nMojang 세션 서버에 접속해 봅니다. 이 단계만 인터넷을 사용하며, 정보는 보내지 않습니다."
        )
    } else {
        format!(
            "Run the live check too? Each of the {n} runtimes is started and connects to 2 test sites\n(we-have-a-problem.com) and the Mojang session server. Only this step uses the network; nothing is sent."
        )
    };
    let yes = ui::confirm(&q);
    if yes {
        ui::log("consent: live check");
    }
    yes
}

fn apply_all(targets: &[&Runtime]) {
    let (mut ok, mut failed) = (0, 0);
    for r in targets {
        match patch::apply(r) {
            Ok(()) => {
                ok += 1;
                ui::log(&format!("FIXED {}", r.file.display()));
                println!("  {} {}", green(t("추가함:", "added:")), r.home.display());
            }
            Err(e) => {
                failed += 1;
                ui::log(&format!("FAILED {} {e}", r.file.display()));
                println!("  {} {} - {e}", red(t("실패:", "failed:")), r.home.display());
            }
        }
    }
    println!("{}", cyan(&if korean_ui() { format!("차단 목록 추가 {ok}개, 실패 {failed}개") } else { format!("{ok} block lists updated, {failed} failed") }));
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

    let all: Vec<&Runtime> = list.iter().collect();
    let checked = ask_live_check(all.len());
    if checked {
        let verdicts = live_check(&all);
        if list.iter().zip(&verdicts).any(|(r, v)| r.state == State::Blocked && *v == Verdict::Vulnerable) {
            println!("{}", red(t(
                " 차단 목록이 있는데도 위장 인증서를 믿는 Java가 있습니다. 차단 목록만으로는 부족하니 Java/런처를 꼭 업데이트하세요.",
                " Some runtimes trust the fake certificate despite the block list; update those Java installations/launchers.",
            )));
        }
    }

    let open: Vec<&Runtime> = list.iter().filter(|r| r.state == State::NotBlocked).collect();
    if open.is_empty() {
        println!("\n{}", green(t("차단 목록에 추가할 Java가 없습니다.", "No block list needs changes.")));
        return;
    }
    println!();
    println!("{}", cyan(t("차단 목록 추가(수정)를 하면 일어나는 일", "What adding the entries does")));
    if korean_ui() {
        println!(" - [차단 목록 없음] Java {}개의 blocked.certs 끝에 인증서 지문 16줄을 추가합니다.", open.len());
    } else {
        println!(" - Appends the 16 certificate fingerprints to blocked.certs of the {} [blocklist missing] runtimes.", open.len());
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
        " - 임시 대응입니다. Java/런처를 수정된 버전(25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 이상)으로\n   업데이트하는 것이 근본 해결입니다.",
        " - This is a stopgap. Updating Java/launchers (25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 or newer)\n   is the real fix.",
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
            "변경은 Java 프로그램을 새로 시작해야 적용됩니다. 이 도구는 프로그램을 종료하지 않습니다.",
            "Changes apply when those programs restart. This tool does not close them.",
        )));
    }

    let mine: Vec<&Runtime> = open.iter().copied().filter(|r| r.writable).collect();
    let locked: Vec<&Runtime> = open.iter().copied().filter(|r| !r.writable).collect();
    if !mine.is_empty() {
        let q = if korean_ui() {
            format!("지금 권한으로 바꿀 수 있는 {}개의 차단 목록에 16개를 추가할까요?", mine.len())
        } else {
            format!("Add the 16 entries to the {} block lists you can change with your current rights?", mine.len())
        };
        if ui::confirm(&q) {
            ui::log("consent: fix");
            apply_all(&mine);
            if checked {
                let q = t("추가한 Java를 실제 연결 검사로 다시 확인할까요? (인터넷 사용)", "Re-run the live check on the updated runtimes? (uses the network)");
                if ui::confirm(q) {
                    ui::log("consent: live re-check");
                    live_check(&mine);
                }
            }
        } else {
            println!("{}", t("바꾸지 않았습니다.", "Nothing was changed."));
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

/// Non-interactive report. Typing --check (and --verify) on the command line is the consent.
fn run_check(args: &Args) -> ExitCode {
    let list = scan(args);
    show(&list);
    summary(&list);
    let mut attention = list.iter().any(|r| matches!(r.state, State::NotBlocked | State::AppBundle));
    if args.verify {
        let all: Vec<&Runtime> = list.iter().collect();
        attention |= live_check(&all).contains(&Verdict::Vulnerable);
    }
    if attention { ExitCode::from(2) } else { ExitCode::SUCCESS }
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
    ui::log(&format!("start version={} elevated={} check={} verify={}", env!("CARGO_PKG_VERSION"), args.elevated, args.check, args.verify));

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
            println!("{}", t("  1. 검사하고 필요하면 차단 목록 추가하기", "  1. Check, and add the block-list entries if needed"));
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
