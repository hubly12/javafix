# javafix

**Java 인증서 취약점(CVE-2026-91403) 차단 목록 방식 임시 대응 도구** — Windows / macOS

PC에 설치된 Java(마인크래프트 런처, 모드 런처, 개발 도구, 직접 설치한 JDK)를 모두 찾아,
OpenJDK가 안내한 **임시 조치(차단 목록에 문제의 인증서 16개 추가)**가 되어 있는지 확인합니다.
사용자가 동의하면 빠진 항목을 추가합니다. 선택하면 각 Java를 실제로 실행해 **위장 인증서가 정말 거부되는지**도 검사합니다.

> **이 도구는 완전한 해결책이 아닙니다.** Java를 업데이트하지 않고, 신뢰 저장소(cacerts)를 고치지 않으며,
> 인증서 폐기 검사를 켜지 않습니다. 근본 해결은 Java와 런처를 수정된 버전으로 업데이트하는 것입니다.
> 자세한 내용은 [3. 이 도구의 한계](#3-이-도구의-한계)를 읽어 주세요.

외부 라이브러리 없이 Rust 표준 라이브러리만으로 만들어서, `src/`와 `probe/` 폴더만 읽으면 하는 일을 모두 확인할 수 있습니다.

English: see [English](#english) below.

---

## 목차

1. [어떤 취약점인가요?](#1-어떤-취약점인가요)
2. [이 도구가 하는 일](#2-이-도구가-하는-일)
3. [이 도구의 한계](#3-이-도구의-한계)
4. [다운로드와 실행](#4-다운로드와-실행)
5. [실행 화면 순서](#5-실행-화면-순서)
6. [결과 표시의 뜻](#6-결과-표시의-뜻)
7. [실제 연결 검사](#7-실제-연결-검사)
8. [되돌리기](#8-되돌리기)
9. [명령줄 옵션](#9-명령줄-옵션)
10. [검사하는 위치](#10-검사하는-위치)
11. [자주 묻는 질문](#11-자주-묻는-질문)
12. [직접 빌드하기](#12-직접-빌드하기)
13. [라이선스](#13-라이선스)

---

## 1. 어떤 취약점인가요?

2026년 10월, 인증기관 eMudhra의 **중간 인증서 8개**의 개인키를 누구나 알아낼 수 있다는 사실이 밝혀졌습니다.
같은 키로 Sectigo "AAA Certificate Services"가 교차 서명한 인증서까지 합치면 **모두 16개**입니다.

수정되지 않은 Java는 이 인증서들을 믿기 때문에, 공격자가 같은 네트워크(공용 Wi-Fi 등)에 있으면
**아무 사이트로나 위장한 가짜 인증서**를 만들 수 있고 Java는 그것을 진짜로 받아들입니다.
예를 들어 마인크래프트 로그인(세션) 서버나 모드 다운로드 서버로 위장할 수 있습니다.

OpenJDK가 안내한 조치는 아래 세 가지 중 하나입니다.

| 공식 조치 | 이 도구 |
|---|---|
| Java를 수정된 버전으로 업데이트 (Oracle/OpenJDK 기준 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 이상) | ❌ 하지 않음 (안내만) |
| `blocked.certs`(Java 8은 `blacklisted.certs`)로 문제의 인증서 차단 | ✅ 16개 추가 |
| 인증서 폐기 검사 켜기 (`-Dcom.sun.net.ssl.checkRevocation=true -Dcom.sun.security.enableCRLDP=true`) | ❌ 하지 않음 ([이유](#3-이-도구의-한계)) |

참고 자료

- OpenJDK 보안 공지: https://openjdk.org/groups/vulnerability/advisories/2026-10-21
- Oracle 보안 경고: https://www.oracle.com/security-alerts/alert-cve-2026-91403.html
- 인증서 목록과 테스트 사이트: https://emudhra.we-have-a-problem.com/ (`impacted-intermediates.json`)

## 2. 이 도구가 하는 일

| 단계 | 내용 | 인터넷 |
|---|---|---|
| 파일 검사 | 찾은 Java마다 `lib/security/blocked.certs`(Java 8은 `blacklisted.certs`)와 `release` 파일을 읽어, 16개가 차단 목록에 있는지 봅니다. | 사용 안 함 |
| 실제 연결 검사 (선택) | 각 Java를 실제로 실행해 테스트 사이트 2곳과 Mojang 세션 서버에 접속해 보고, 위장 인증서가 거부되는지 확인합니다. [자세히](#7-실제-연결-검사) | 이 단계만 사용 |
| 차단 목록 추가 | 빠진 인증서 지문만 **파일 끝에 추가**합니다. 기존 줄은 지우거나 고치지 않고, 원본은 `blocked.certs.bak-cve-2026-91403`으로 백업합니다. 추가한 뒤 파일을 다시 읽어 확인합니다. | 사용 안 함 |
| 되돌리기 | 백업을 원래 자리에 복사합니다. | 사용 안 함 |

- **동의**: 검사, 실제 연결 검사, 차단 목록 추가, 관리자 권한 사용 전에 각각 `Y`를 입력해야 진행합니다. 다른 입력은 모두 "아니오"입니다.
- **기록**: Windows `%LOCALAPPDATA%\JavaFix`, macOS `~/Library/Logs/JavaFix`에 무엇을 검사하고 바꿨는지 남깁니다.
- 차단되는 것은 문제의 인증서 16개뿐이므로 일반 웹사이트, 마인크래프트 접속, 모드 다운로드에는 영향이 없습니다.

## 3. 이 도구의 한계

- **Java를 업데이트하지 않습니다.** 차단 목록은 임시 조치이고, 런처가 Java를 다시 내려받으면 원래대로 돌아갈 수 있습니다.
- **신뢰 저장소(`cacerts`)를 고치지 않습니다.** 루트 인증서를 지우면 정상 사이트까지 막힐 수 있어서 건드리지 않습니다.
  (예: Sectigo "AAA Certificate Services"는 많은 정상 사이트가 쓰는 루트입니다.)
- **인증서 폐기 검사(revocation)를 켜지 않습니다.** 켜면 접속할 때마다 폐기 목록 서버에 물어보는데, 그 서버에 닿지 않으면
  마인크래프트 로그인까지 실패할 수 있습니다. 또 이 설정은 프로그램마다 실행 옵션으로 넣어야 해서 일괄 적용하기 어렵습니다.
- **파일 검사의 "차단 목록 적용"은 차단 목록에 16개가 들어 있다는 뜻일 뿐**, 그 Java가 모든 면에서 안전하다는 뜻이 아닙니다.
  실제 동작은 [실제 연결 검사](#7-실제-연결-검사)로 확인하세요.
- 실제 연결 검사의 테스트 사이트는 16개 중 **EM DV TLS CA - G3B 계열**(eMudhra 경로와 Sectigo 경로)을 대표로 확인합니다.
  나머지 인증서는 같은 차단 방식이므로 함께 막히지만, 하나하나 접속해 보지는 않습니다.
- 코드 서명과 애플 공증을 받지 않은 프로그램이라 Windows SmartScreen과 macOS Gatekeeper 경고가 뜹니다.

## 4. 다운로드와 실행

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

## 5. 실행 화면 순서

1. **안내**: 취약점 설명, 도구가 하는 일, **한계**, 약속(백업·되돌리기·인터넷 사용 범위), 기록 파일 위치를 보여 줍니다.
2. **메뉴**: `1` 검사하고 필요하면 차단 목록 추가 / `2` 되돌리기 / `3` 종료.
3. **검사 동의** → **파일 검사**: 1~3분 정도 걸립니다. 찾은 Java마다 상태, 버전, 위치를 보여 줍니다.
4. **실제 연결 검사 동의** (선택): `Y`를 누르면 각 Java를 실행해 실제로 막히는지 확인합니다. `Y`가 아니면 건너뜁니다.
5. **차단 목록 추가 설명**: 무엇이 바뀌는지, 백업 위치, 영향 범위, 근본 해결 방법을 설명합니다.
   실행 중인 Java 프로그램이 있으면 "다시 시작해야 적용된다"고 알려 줍니다. 이 도구는 프로그램을 종료하지 않습니다.
6. **차단 목록 추가 동의**: `Y`를 입력해야 추가합니다. 4번을 했다면, 추가한 Java를 다시 실제 연결 검사할지 묻습니다.
7. **관리자 권한 동의** (필요할 때만): Program Files(Windows)나 `/Library` 같은 시스템 폴더(macOS)에 있는 Java는
   관리자 권한이 있어야 바꿀 수 있습니다. 한 번 더 동의를 받은 뒤에
   - Windows: UAC 확인 창을 띄워 **새 관리자 창**에서 다시 실행합니다.
   - macOS: 같은 터미널에서 `sudo`로 다시 실행합니다(로그인 암호 입력).

   다시 실행된 쪽도 처음부터 설명하고 **모든 단계에서 다시 동의**를 받습니다.
8. **마무리**: 마인크래프트, 런처, IDE 등 Java 프로그램을 다시 시작하면 적용됩니다.

## 6. 결과 표시의 뜻

파일 검사

| 표시 | 뜻 | 도구가 하는 일 |
|---|---|---|
| `[차단 목록 적용]` | 차단 목록에 16개가 모두 있음 (이것만으로 완전히 안전하다는 뜻은 아님) | 없음 |
| `[차단 목록 없음]` | 일부 또는 전부가 없음 | 동의하면 추가 |
| `[차단 목록 없음] (관리자 권한 필요)` | 위와 같지만 시스템 폴더에 있음 | 관리자 권한 동의 후 추가 |
| `[앱 업데이트]` | macOS의 서명된 앱 안에 있는 Java | 바꾸지 않음 (앱 서명이 깨지므로). 해당 앱을 업데이트하세요. |
| `[확인 불가]` | 차단 목록 형식이 다른 파일 | 바꾸지 않음. 해당 프로그램을 업데이트하세요. |

실제 연결 검사

| 표시 | 뜻 |
|---|---|
| `안전 (위장 인증서 거부)` | 테스트 사이트 2곳이 모두 거부되고, Mojang 세션 서버에는 정상으로 접속됨 |
| `취약 (위장 인증서를 믿음)` | 테스트 사이트 중 하나라도 접속됨. 차단 목록을 추가하거나 Java를 업데이트해야 합니다. |
| `판단 불가 (이유)` | 인터넷 연결 없음, 너무 오래된 Java라 접속 자체가 안 됨, 실행 파일 없음, 시간 초과 등 |

차단 목록이 없어도 실제 연결 검사가 `안전`일 수 있습니다. 배포판이 문제의 루트 인증서를 빼는 방식으로 고친 경우입니다(예: Temurin 25.0.5+8).
반대로 차단 목록이 있는데 `취약`으로 나오면, 그 Java는 반드시 업데이트하세요.

## 7. 실제 연결 검사

파일만 보는 검사의 한계를 보완하기 위한 선택 단계입니다.

- 이 도구에 들어 있는 아주 작은 Java 프로그램([`probe/JavafixProbe.java`](probe/JavafixProbe.java), Java 8 이상에서 실행)을
  임시 폴더에 풀고, 찾은 **각 Java로 실행**합니다. 검사가 끝나면 임시 폴더를 지웁니다.
- 접속하는 곳은 세 곳뿐입니다.
  - `dv-g3b-emudhra.we-have-a-problem.com`: eMudhra 경로의 위장 인증서 → **거부되어야 정상**
  - `dv-g3b-aaa-emudhra.we-have-a-problem.com`: Sectigo AAA 경로의 위장 인증서 → **거부되어야 정상**
  - `sessionserver.mojang.com`: 비교용 → **접속되어야 정상** (안 되면 인터넷 문제로 보고 판단 불가 처리)
- 접속만 해 보고(HTTPS `HEAD` 요청) 어떤 정보도 보내지 않습니다. `JAVA_TOOL_OPTIONS` 같은 환경 변수는 빼고 각 Java의 기본 설정으로 검사합니다.
- Java 4개씩 동시에 검사하며, Java 하나당 최대 60초입니다.

## 8. 되돌리기

메뉴에서 `2`를 고르거나 `--restore`로 실행합니다. 이 도구가 만든 백업(`*.bak-cve-2026-91403`)이 있는 Java만 보여 주고,
동의하면 백업을 원래 파일 자리에 복사한 뒤 백업 파일을 지웁니다. 되돌리면 16개 인증서는 다시 신뢰되므로
Java를 업데이트한 뒤에만 되돌리는 것을 권장합니다.

## 9. 명령줄 옵션

```
javafix                      대화형 실행 (더블클릭과 같음)
javafix --check              파일 검사만 하고 결과 출력 (아무것도 바꾸지 않음)
javafix --check --verify     파일 검사 + 실제 연결 검사 (인터넷 사용)
javafix --restore            되돌리기 모드로 바로 시작
javafix --lang ko|en         언어 선택 (기본: 시스템 언어)
javafix --scan-root <폴더>   지정한 폴더만 검사 (여러 번 사용 가능)
javafix --no-pause           끝날 때 엔터 대기 없이 종료
javafix --help / --version
```

`--check`의 종료 코드: `0` = 모든 차단 목록에 16개가 있음(`--verify`면 실제 검사에서 취약 없음), `2` = 조치가 필요한 항목 있음.
명령줄에 직접 입력한 것 자체를 검사 동의로 봅니다.

## 10. 검사하는 위치

| 운영체제 | 위치 |
|---|---|
| Windows | `Program Files`, `Program Files (x86)`, `%LOCALAPPDATA%`, `%APPDATA%`, `%USERPROFILE%\curseforge` |
| macOS | `/Library/Java/JavaVirtualMachines`, `~/Library/Java/JavaVirtualMachines`, `~/Library/Application Support`, `/Applications`, `~/Applications`, `/Library/Internet Plug-Ins`, Homebrew (`/opt/homebrew`, `/usr/local/Cellar`) |
| 공통 | 홈 폴더의 숨김 폴더(`.jdks`, `.gradle`, `.lunarclient`, `.sdkman`, `.jabba` 등), `JAVA_HOME` |

다운로드·바탕화면·문서 폴더는 검사하지 않습니다(macOS 개인정보 보호 창이 뜨는 것을 피하기 위해).
그곳에 Java가 있다면 `--scan-root`로 직접 지정하세요. `node_modules`, `.git`, 휴지통 등 Java가 없는 큰 폴더는 건너뜁니다.

## 11. 자주 묻는 질문

**이것만 실행하면 안전한가요?**
아니요. 차단 목록 방식의 임시 대응입니다. 실제 연결 검사에서 `안전`이 나오면 이번 위장 인증서는 막힌 것이지만,
Java와 런처를 수정된 버전으로 업데이트하는 것이 근본 해결입니다.

**마인크래프트 접속이나 모드에 문제가 생기지 않나요?**
차단되는 것은 개인키가 노출된 인증서 16개뿐입니다. 정상적인 사이트는 이 인증서를 쓰지 않습니다.

**런처를 업데이트했더니 다시 [차단 목록 없음]으로 나와요.**
런처가 Java를 새로 내려받으면 차단 목록이 원래대로 돌아갈 수 있습니다. 도구를 한 번 더 실행하세요.

**Java를 업데이트했는데도 [차단 목록 없음]으로 나와요.**
배포판에 따라 차단 목록 대신 루트 인증서를 빼는 방식으로 고친 경우가 있습니다(예: Temurin 25.0.5+8).
실제 연결 검사가 `안전`이면 이미 막힌 것이고, 차단 목록을 추가해도 문제없습니다(이중 방어).

**바이러스 백신이 경고해요.**
서명되지 않은 작은 실행 파일이라 오탐될 수 있습니다. 소스를 직접 확인하고 [12. 직접 빌드하기](#12-직접-빌드하기)로 빌드해도 됩니다.

**관리자 권한 없이 실행하면 어떻게 되나요?**
현재 사용자 권한으로 바꿀 수 있는 항목(런처 Java 등)만 바꾸고, 시스템 폴더의 Java는 그대로 둡니다.

## 12. 직접 빌드하기

Rust 1.74 이상이 필요합니다. 외부 라이브러리를 받지 않습니다.

```
cargo test
cargo build --release          # target/release/javafix(.exe)
```

실제 연결 검사용 Java 프로그램은 미리 컴파일한 `probe/JavafixProbe.class`를 실행 파일에 넣습니다.
CI가 매번 `javac --release 8`로 다시 컴파일해 저장소의 `.class`와 같은지 확인합니다.

GitHub에 `v*` 태그를 올리면 `.github/workflows/release.yml`이 Windows·macOS·Linux에서 테스트를 돌리고,
Windows x64/ARM64 exe와 macOS 통합 바이너리(zip)를 빌드해 `SHA256SUMS`와 함께 릴리스에 올립니다.
GitHub 공식 액션(checkout, setup-java, upload/download-artifact)만 사용합니다.

소스 구성

| 파일 | 역할 |
|---|---|
| `src/fingerprints.rs` | 차단할 인증서 16개의 SHA-256 지문 |
| `src/scan.rs` | Java 찾기와 파일 검사 (읽기 전용) |
| `src/probe.rs` | 실제 연결 검사 실행과 판정 |
| `probe/JavafixProbe.java` | 각 Java 안에서 실행되는 연결 검사 프로그램 |
| `src/patch.rs` | 파일을 바꾸는 유일한 코드: 추가와 되돌리기 |
| `src/platform.rs` | 운영체제별 검사 위치, 언어, 관리자 권한 재실행 |
| `src/ui.rs` | 화면 출력, 질문, 기록 |
| `src/main.rs` | 실행 순서와 동의 흐름 |
| `tests/cli.rs` | 실제 실행 파일에 답을 입력해 보는 테스트 |

## 13. 라이선스

MIT. [LICENSE](LICENSE)를 보세요.

---

## English

### What it is

`javafix` is a **block-list based stopgap** for **CVE-2026-91403** on Windows and macOS.
It finds every Java runtime on a computer: Minecraft launchers, mod launchers, IDEs and standalone JDKs.
For each runtime it does the following:

- checks whether the runtime's block list (`lib/security/blocked.certs`) contains the 16 affected certificates;
- optionally runs the runtime for real to see whether forged certificates are refused;
- with explicit consent, adds the missing entries (the workaround published by OpenJDK).

**It is not a complete fix.** It does not update Java, does not edit the trust store (`cacerts`) and does not enable
revocation checking. Updating Java and launchers is the real fix.

### The vulnerability

In October 2026, the private keys of eight eMudhra intermediate CA certificates turned out to be recoverable.
Together with their Sectigo "AAA Certificate Services" cross-signs, that is 16 certificates.
Unpatched Java trusts them, so anyone on the network path can mint a certificate that Java accepts for any host name,
for example a fake Minecraft session server.

The OpenJDK advisory lists three remedies:

- **Update Java** (25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 or newer). javafix does not do this.
- **Block the certificates in `blocked.certs`.** javafix does this.
- **Enable revocation checking.** javafix does not do this: it can make Minecraft logins fail when revocation servers
  are unreachable, and it has to be set per program.

### Steps

| Step | What happens | Network |
|---|---|---|
| File check | Reads `blocked.certs` (`blacklisted.certs` on Java 8) and `release` of each runtime | no |
| Live check (optional) | Runs each runtime's `java` with a tiny bundled class ([`probe/JavafixProbe.java`](probe/JavafixProbe.java), Java 8+) that connects to two test hosts serving forged-chain certificates and to `sessionserver.mojang.com` as a control | yes, only here |
| Add entries | Appends missing fingerprints, keeps the original as `blocked.certs.bak-cve-2026-91403`, verifies by reading back | no |
| Undo | Puts the backup back (`--restore`) | no |

Every step asks for consent (`Y`); anything else means no. Runtimes in system folders need a separate consent and an
elevated relaunch: a UAC prompt on Windows, `sudo` on macOS. The elevated copy asks for consent again.
Signed macOS `.app` bundles are never modified.

### Limits

- "Blocklist applied" only means the 16 entries are in the block list; the live check shows real behaviour.
- The live check exercises the EM DV TLS CA - G3B chains through both the eMudhra and the Sectigo AAA paths.
  The other certificates are blocked the same way but are not connected to individually.
- A runtime without the block list can still pass the live check when its vendor removed the roots instead
  (e.g. Temurin 25.0.5+8).
- The binaries are not code-signed or notarized.

### Usage

```
javafix                      interactive (double-click works)
javafix --check              file check only, changes nothing
javafix --check --verify     file check + live check (uses the network)
javafix --restore            undo
javafix --lang en|ko         language (default: system language)
javafix --scan-root <dir>    scan a specific folder (repeatable)
javafix --no-pause           do not wait for Enter at the end
```

`--check` exits with 0 when every block list has all 16 entries (and, with `--verify`, nothing failed the live check),
and with 2 when something needs attention.

### Download

- **Windows**: `javafix-windows-x64.exe` or `javafix-windows-arm64.exe`. Choose "More info → Run anyway" in SmartScreen.
- **macOS**: download `javafix-macos-universal.zip`, unzip it and double-click `javafix-macos/javafix.command`
  (it opens in Terminal).
  - On macOS 15 or later, allow it under System Settings → Privacy & Security → "Open Anyway".
  - On macOS 14 or earlier, use right-click → Open.
  - From Terminal: `xattr -d com.apple.quarantine javafix.command && ./javafix.command`.

The plain (not zipped) macOS binary of v0.1.0 loses its executable bit when downloaded, so Finder opens it in TextEdit.
Use the zip from v0.1.1 on.

### Building

```
cargo test
cargo build --release
```

CI recompiles `probe/JavafixProbe.java` with `javac --release 8` and checks that it matches the committed `.class`
that is embedded in the binary. Pushing a `v*` tag does the following:

- tests on Windows, macOS and Linux;
- builds Windows x64/ARM64 and a zipped macOS universal binary;
- publishes a release with `SHA256SUMS`.

### License

MIT, see [LICENSE](LICENSE).
