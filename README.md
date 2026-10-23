# javafix

**Java 인증서 취약점(CVE-2026-91403) 점검·수정 도구** — Windows / macOS

PC에 설치된 모든 Java(마인크래프트 런처, 모드 런처, 개발 도구, 직접 설치한 JDK)를 찾아 CVE-2026-91403에
취약한지 검사하고, **사용자가 직접 동의한 경우에만** OpenJDK가 안내한 임시 조치를 적용합니다.
외부 라이브러리 없이 Rust 표준 라이브러리만으로 만들어서, `src/` 폴더의 코드만 읽으면 하는 일을 모두 확인할 수 있습니다.

English: see [English](#english) below.

---

## 목차

1. [어떤 취약점인가요?](#1-어떤-취약점인가요)
2. [이 도구가 하는 일과 하지 않는 일](#2-이-도구가-하는-일과-하지-않는-일)
3. [다운로드와 실행](#3-다운로드와-실행)
4. [실행 화면 순서](#4-실행-화면-순서)
5. [결과 상태의 뜻](#5-결과-상태의-뜻)
6. [되돌리기](#6-되돌리기)
7. [명령줄 옵션](#7-명령줄-옵션)
8. [검사하는 위치](#8-검사하는-위치)
9. [자주 묻는 질문](#9-자주-묻는-질문)
10. [직접 빌드하기](#10-직접-빌드하기)
11. [라이선스](#11-라이선스)

---

## 1. 어떤 취약점인가요?

2026년 10월, 인증기관 eMudhra의 **중간 인증서 8개**의 개인키를 누구나 알아낼 수 있다는 사실이 밝혀졌습니다.
같은 키로 Sectigo "AAA Certificate Services"가 교차 서명한 인증서까지 합치면 **모두 16개**입니다.

Java는 이 인증서들의 상위 루트를 아직 믿기 때문에, 공격자가 같은 네트워크(공용 Wi-Fi 등)에 있으면
**아무 사이트로나 위장한 가짜 인증서**를 만들 수 있고 Java는 그것을 진짜로 받아들입니다.
예를 들어 마인크래프트 로그인(세션) 서버나 모드 다운로드 서버로 위장할 수 있습니다.

- 근본 해결: Java를 수정된 버전으로 업데이트합니다.
  (Oracle/OpenJDK 기준 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 이상. 배포판마다 번호가 다를 수 있습니다.)
- 문제: 마인크래프트 런처, 모드 런처, IDE 등은 **자기 Java를 따로 들고 있어서** 업데이트가 늦습니다.
- 이 도구: 그런 Java까지 모두 찾아서, OpenJDK가 공식 안내한 임시 조치(차단 목록에 16개 추가)를 적용합니다.

참고 자료

- OpenJDK 보안 공지: https://openjdk.org/groups/vulnerability/advisories/2026-10-21
- Oracle 보안 경고: https://www.oracle.com/security-alerts/alert-cve-2026-91403.html
- 인증서 목록: https://emudhra.we-have-a-problem.com/ (`impacted-intermediates.json`)

## 2. 이 도구가 하는 일과 하지 않는 일

| 구분 | 내용 |
|---|---|
| 읽는 파일 | 찾은 Java마다 `lib/security/blocked.certs` (Java 8은 `blacklisted.certs`)와 버전이 적힌 `release` 파일 |
| 바꾸는 파일 | 위 차단 목록 파일 **하나뿐**이며, 빠진 인증서 지문만 **파일 끝에 추가**합니다. 기존 줄은 지우거나 고치지 않습니다. |
| 백업 | 바꾸기 전에 원본을 같은 폴더에 `blocked.certs.bak-cve-2026-91403` 으로 복사합니다 (처음 한 번만). |
| 동의 | 검사 전, 수정 전, 관리자 권한 사용 전에 각각 `Y`를 입력해야 진행합니다. 다른 입력은 모두 "아니오"입니다. |
| 기록 | Windows `%LOCALAPPDATA%\JavaFix`, macOS `~/Library/Logs/JavaFix` 에 무엇을 검사하고 바꿨는지 남깁니다. |
| **하지 않는 일** | 인터넷 접속, 정보 전송, 프로그램 다운로드, 실행 중인 프로그램 종료, 다른 파일 수정, 서명된 macOS 앱(`.app`) 내부 수정 |

차단되는 것은 문제의 인증서 16개뿐이므로 일반 웹사이트, 마인크래프트 접속, 모드 다운로드에는 영향이 없습니다.

## 3. 다운로드와 실행

[Releases](../../releases) 페이지에서 운영체제에 맞는 파일을 받습니다.

| 운영체제 | 파일 |
|---|---|
| Windows (대부분의 PC) | `javafix-windows-x64.exe` |
| Windows (ARM 노트북) | `javafix-windows-arm64.exe` |
| macOS (Intel / Apple Silicon 공통) | `javafix-macos-universal.zip` |

받은 파일이 원본인지 확인하려면 `SHA256SUMS`의 값과 비교하세요.

```
certutil -hashfile javafix-windows-x64.exe SHA256      (Windows)
shasum -a 256 javafix-macos-universal.zip              (macOS)
```

**Windows**

1. `javafix-windows-x64.exe`를 더블클릭합니다.
2. "Windows의 PC 보호" 창이 뜨면 **추가 정보 → 실행**을 누릅니다. 코드 서명 인증서가 없는 프로그램이라 뜨는 경고입니다.

**macOS**

1. `javafix-macos-universal.zip`을 받아 압축을 풉니다(Safari는 자동으로 풉니다). `javafix-macos` 폴더가 생깁니다.
2. 폴더 안의 `javafix.command`를 더블클릭하면 터미널이 열리고 실행됩니다.
3. 애플 공증(notarization)을 받지 않은 프로그램이라 처음에는 "확인되지 않은 개발자" 경고가 뜹니다.
   - macOS 15(Sequoia) 이상: 경고 창을 닫고 **시스템 설정 → 개인정보 보호 및 보안** 맨 아래의
     **"그래도 열기"**를 누른 뒤 다시 더블클릭합니다.
   - macOS 14 이하: `javafix.command`를 **우클릭 → 열기 → 열기**를 누릅니다.

터미널에서 바로 실행하려면:

```
cd ~/Downloads/javafix-macos
xattr -d com.apple.quarantine javafix.command
./javafix.command
```

> `v0.1.0`의 압축되지 않은 `javafix-macos-universal` 파일은 내려받으면 실행 권한이 사라져서, 더블클릭하면
> 텍스트 편집기가 "텍스트 인코딩 유니코드(UTF-8)이(가) 적용되지 않습니다" 오류를 띄웁니다. `v0.1.1`부터 zip으로 배포합니다.
> 그 파일을 이미 받았다면 터미널에서 `chmod +x javafix-macos-universal` 후 `./javafix-macos-universal`로 실행할 수 있습니다.

## 4. 실행 화면 순서

1. **안내**: 취약점 설명, 도구가 하는 일, 약속(인터넷 미사용·백업·되돌리기), 기록 파일 위치를 보여 줍니다.
2. **메뉴**: `1` 검사하고 필요하면 수정 / `2` 되돌리기 / `3` 종료.
3. **검사 동의**: "이 PC의 Java를 검사하는 데 동의합니까? (파일을 읽기만 합니다)" — `Y`를 입력해야 검사를 시작합니다.
4. **검사**: 1~3분 정도 걸립니다. 찾는 위치가 화면에 표시됩니다.
5. **결과 목록**: 찾은 Java마다 상태, 버전, 설치 위치를 보여 주고 합계를 출력합니다.
6. **수정 내용 설명**: 무엇이 바뀌는지, 백업 위치, 영향 범위, 근본 해결 방법을 설명합니다.
   실행 중인 Java 프로그램이 있으면 "다시 시작해야 적용된다"고 알려 줍니다. 이 도구는 프로그램을 종료하지 않습니다.
7. **수정 동의**: 현재 권한으로 바꿀 수 있는 항목 수를 알려 주고 `Y`를 입력해야 수정합니다.
   수정 후에는 파일을 다시 읽어 16개가 모두 들어갔는지 확인합니다.
8. **관리자 권한 동의** (필요할 때만): Program Files(Windows)나 `/Library` 같은 시스템 폴더(macOS)에 있는 Java는
   관리자 권한이 있어야 바꿀 수 있습니다. 한 번 더 동의를 받은 뒤에
   - Windows: UAC 확인 창을 띄워 **새 관리자 창**에서 다시 실행합니다.
   - macOS: 같은 터미널에서 `sudo`로 다시 실행합니다(로그인 암호 입력).

   다시 실행된 쪽도 처음부터 설명하고 **검사와 수정에 대해 다시 동의**를 받습니다.
9. **마무리**: 마인크래프트, 런처, IDE 등 Java 프로그램을 다시 시작하면 적용됩니다.

## 5. 결과 상태의 뜻

| 표시 | 뜻 | 도구가 하는 일 |
|---|---|---|
| `[보호됨]` | 16개 인증서가 모두 차단되어 있음 | 없음 |
| `[취약]` | 일부 또는 전부가 차단되지 않음 | 동의하면 추가 |
| `[취약] (관리자 권한 필요)` | 위와 같지만 시스템 폴더에 있음 | 관리자 권한 동의 후 추가 |
| `[앱 업데이트]` | macOS의 서명된 앱 안에 들어 있는 Java | 바꾸지 않음 (앱 서명이 깨지므로). 해당 앱을 업데이트하세요. |
| `[확인 불가]` | 차단 목록 형식이 다른 파일 | 바꾸지 않음. 해당 프로그램을 업데이트하세요. |

## 6. 되돌리기

메뉴에서 `2`를 고르거나 `--restore`로 실행합니다. 이 도구가 만든 백업(`*.bak-cve-2026-91403`)이 있는 Java만 보여 주고,
동의하면 백업을 원래 파일 자리에 복사한 뒤 백업 파일을 지웁니다. 되돌리면 16개 인증서는 다시 신뢰되므로
Java를 업데이트한 뒤에만 되돌리는 것을 권장합니다.

## 7. 명령줄 옵션

```
javafix                      대화형 실행 (더블클릭과 같음)
javafix --check              검사만 하고 결과 출력. 종료 코드 0 = 모두 보호됨, 2 = 조치 필요
javafix --restore            되돌리기 모드로 바로 시작
javafix --lang ko|en         언어 선택 (기본: 시스템 언어)
javafix --scan-root <폴더>   지정한 폴더만 검사 (여러 번 사용 가능)
javafix --no-pause           끝날 때 엔터 대기 없이 종료
javafix --help / --version
```

`--check`는 아무것도 바꾸지 않으므로 여러 PC를 점검하는 관리자 스크립트에 쓸 수 있습니다.
명령줄에 직접 입력한 것 자체를 검사 동의로 봅니다.

## 8. 검사하는 위치

| 운영체제 | 위치 |
|---|---|
| Windows | `Program Files`, `Program Files (x86)`, `%LOCALAPPDATA%`, `%APPDATA%`, `%USERPROFILE%\curseforge` |
| macOS | `/Library/Java/JavaVirtualMachines`, `~/Library/Java/JavaVirtualMachines`, `~/Library/Application Support`, `/Applications`, `~/Applications`, `/Library/Internet Plug-Ins`, Homebrew (`/opt/homebrew`, `/usr/local/Cellar`) |
| 공통 | 홈 폴더의 숨김 폴더(`.jdks`, `.gradle`, `.lunarclient`, `.sdkman`, `.jabba` 등), `JAVA_HOME` |

다운로드·바탕화면·문서 폴더는 검사하지 않습니다(macOS 개인정보 보호 창이 뜨는 것을 피하기 위해).
그곳에 Java가 있다면 `--scan-root`로 직접 지정하세요. `node_modules`, `.git`, 휴지통 등 Java가 없는 큰 폴더는 건너뜁니다.

## 9. 자주 묻는 질문

**마인크래프트 접속이나 모드에 문제가 생기지 않나요?**
차단되는 것은 개인키가 노출된 인증서 16개뿐입니다. 정상적인 사이트는 이 인증서를 쓰지 않습니다.

**런처를 업데이트했더니 다시 [취약]으로 나와요.**
런처가 Java를 새로 내려받으면 차단 목록이 원래대로 돌아갈 수 있습니다. 도구를 한 번 더 실행하세요.
런처가 수정된 Java를 받아 왔다면 `[보호됨]`으로 나옵니다.

**Java를 업데이트했는데도 [취약]으로 나와요.**
배포판에 따라 차단 목록 대신 신뢰 루트를 빼는 방식으로 고친 경우가 있습니다(예: Temurin 25.0.5+8).
이 도구는 차단 목록만 보므로 `[취약]`으로 나올 수 있으며, 수정을 적용해도 문제없습니다(이중 방어).

**바이러스 백신이 경고해요.**
서명되지 않은 작은 실행 파일이라 오탐될 수 있습니다. 소스를 직접 확인하고 [10. 직접 빌드하기](#10-직접-빌드하기)로 빌드해도 됩니다.

**관리자 권한 없이 실행하면 어떻게 되나요?**
현재 사용자 권한으로 바꿀 수 있는 항목(런처 Java 등)만 수정하고, 시스템 폴더의 Java는 바꾸지 않은 채 남겨 둡니다.

## 10. 직접 빌드하기

Rust 1.74 이상이 필요합니다. 외부 라이브러리를 받지 않습니다.

```
cargo test
cargo build --release          # target/release/javafix(.exe)
```

GitHub에 `v*` 태그를 올리면 `.github/workflows/release.yml`이 Windows·macOS·Linux에서 테스트를 돌리고,
Windows x64/ARM64 exe와 macOS 통합 바이너리(zip)를 빌드해 `SHA256SUMS`와 함께 릴리스에 올립니다.
GitHub 공식 액션(checkout, upload/download-artifact)만 사용합니다.

소스 구성

| 파일 | 역할 |
|---|---|
| `src/fingerprints.rs` | 차단할 인증서 16개의 SHA-256 지문 |
| `src/scan.rs` | Java 찾기와 상태 판정 (읽기 전용) |
| `src/patch.rs` | 파일을 바꾸는 유일한 코드: 추가와 되돌리기 |
| `src/platform.rs` | 운영체제별 검사 위치, 언어, 관리자 권한 재실행 |
| `src/ui.rs` | 화면 출력, 질문, 기록 |
| `src/main.rs` | 실행 순서와 동의 흐름 |
| `tests/cli.rs` | 실제 실행 파일에 답을 입력해 보는 테스트 |

## 11. 라이선스

MIT. [LICENSE](LICENSE)를 보세요.

---

## English

### What it is

`javafix` is a small, dependency-free tool for **Windows and macOS**. It finds every Java runtime on a computer
(Minecraft launchers, mod launchers, IDEs, standalone JDKs) and checks it for **CVE-2026-91403**.
With the user's explicit consent, it applies the stopgap published by OpenJDK: the SHA-256 fingerprints of the
16 affected certificates are appended to each runtime's `lib/security/blocked.certs`.

### The vulnerability

In October 2026, the private keys of eight eMudhra intermediate CA certificates turned out to be recoverable.
Together with their Sectigo "AAA Certificate Services" cross-signs, that is 16 certificates.
Java still trusts the roots above them. Anyone on the network path can therefore mint a certificate for any host name
that Java will accept, for example a fake Minecraft session server.

The real fix is updating Java (25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 or newer from your vendor).
Runtimes bundled with launchers and apps update on their own schedule; javafix covers those as well.

### What it does and does not do

- **Reads** `lib/security/blocked.certs` (`blacklisted.certs` on Java 8) and `release` of each runtime.
- **Writes** only those block lists, and only after you type `Y`.
  - It appends the missing lines and keeps the original as `blocked.certs.bak-cve-2026-91403`.
  - It reads the file back to verify the result.
- **Never** downloads anything or uses the network.
- **Never** sends data, closes programs or edits other files.
- **Never** touches signed macOS `.app` bundles; those are reported as "update app".
- **Undo**: menu option 2 or `--restore`.
- **Log**: `%LOCALAPPDATA%\JavaFix` on Windows, `~/Library/Logs/JavaFix` on macOS.

### Flow

1. The tool explains the issue and what it will do.
2. You consent to a read-only scan.
3. It lists each runtime with its status.
4. It explains the change, then asks for consent to fix.
5. If some runtimes need administrator or sudo rights, it asks a separate consent and relaunches elevated.
   - On Windows this is a UAC prompt and a new window.
   - On macOS this is `sudo` in the same terminal.
6. The elevated copy explains everything again and asks for consent again.

Java reads the block list at startup. Restart running Java programs afterwards.

### Usage

```
javafix                      interactive (double-click works)
javafix --check              scan only; exit code 0 = all protected, 2 = something to fix
javafix --restore            undo
javafix --lang en|ko         language (default: system language)
javafix --scan-root <dir>    scan a specific folder (repeatable)
javafix --no-pause           do not wait for Enter at the end
```

macOS: download `javafix-macos-universal.zip`, unzip it and double-click `javafix-macos/javafix.command`
(it opens in Terminal). The binary is not notarized.
- On macOS 15 or later, allow it under System Settings → Privacy & Security → "Open Anyway".
- On macOS 14 or earlier, use right-click → Open.
- From Terminal: `xattr -d com.apple.quarantine javafix.command && ./javafix.command`.

The plain (not zipped) `javafix-macos-universal` file of v0.1.0 loses its executable bit when downloaded. Finder then opens it
in TextEdit ("text encoding Unicode (UTF-8) isn't applicable"). Use the zip from v0.1.1 on, or run `chmod +x` on that
file first.
Windows: the binary is not code-signed. Choose "More info → Run anyway" in SmartScreen.

### Building

```
cargo test
cargo build --release
```

Pushing a `v*` tag runs `.github/workflows/release.yml`, which does the following:

- tests on Windows, macOS and Linux;
- builds Windows x64/ARM64 and a zipped macOS universal binary;
- publishes a release with `SHA256SUMS`.

### License

MIT, see [LICENSE](LICENSE).
