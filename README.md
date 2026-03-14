# AegisScan

**포트 스캔 기반 공격표면(Attack Surface) 통합 분석·리포팅 플랫폼**

내부 자산에 대한 고성능 포트 스캔(Connect/SYN) 결과를 기반으로 서비스 식별(배너·TLS), Nmap 결과 연동, 외부 관측(Shodan/Censys) 비교, **CVE 추출 및 EPSS 점수 조회**, **웹 보안 자동 분석(관리자 페이지 노출·정보 누출·디렉터리 리스팅) + 실시간 스크린샷 캡처**를 통해 **현재 노출면과 위험 요약**을 대시보드/보고서로 자동 제공합니다.

---

## 전체 실행 흐름 요약

```
[STEP 0] 설치
    ↓
[STEP 1] .env 설정 (외부 API 키 등)
    ↓
[STEP 2] Connect / SYN 포트 스캔  →  DB 저장  →  배너·TLS 자동 수집
              ↓
         웹 보안 분석 (관리자 노출 / 정보 누출 / 디렉터리 리스팅)
              ↓
         위험 탐지 시 → Playwright 실시간 스크린샷 자동 캡처
    ↓
[STEP 3] (선택) Nmap XML 임포트  →  내부 스캔 결과와 병합
    ↓
[STEP 4] (선택) 외부 관측 비교 (Shodan/Censys)  →  Shadow exposure 탐지
              ↓
         CVE 자동 추출  →  EPSS 점수 조회  →  취약점 DB 저장
    ↓
[STEP 5] 웹 대시보드에서 결과 확인
    ↓
[STEP 6] HTML 리포트 생성 (CVE/EPSS + 웹 보안 분석 + 스크린샷 포함)
```

---

## STEP 0. 설치

### 요구사항

| 항목 | 필수 여부 | 비고 |
|------|-----------|------|
| Python 3.10+ | **필수** | 3.10 / 3.11 / 3.12 / 3.14 확인됨 |
| scapy | 선택 | SYN 스캔 사용 시 (`pip install scapy`) |
| root/관리자 권한 | 선택 | SYN 스캔 시 raw socket 필요 |
| Shodan/Censys API 키 | 선택 | 외부 관측 비교 + CVE 추출 기능 사용 시 |
| 인터넷 연결 | 선택 | EPSS 점수 조회 시 (FIRST.org 공개 API, 인증 불필요) |
| playwright | 선택 | 웹 보안 스크린샷 캡처 시 (없으면 탐지만 수행, 스크린샷 생략) |

### 설치 절차

```bash
# 1) 프로젝트 폴더로 이동
cd /Users/ohreo/aegisscan

# 2) 가상환경이 이미 만들어져 있으므로 활성화만 하면 됩니다
source .venv/bin/activate

# ※ 처음부터 설치하는 경우:
#    python3 -m venv .venv
#    source .venv/bin/activate
#    pip install -e .

# 3) (선택) 스크린샷 기능을 사용하려면 Playwright 설치
pip install playwright
playwright install chromium

# 4) 설치 확인 — 아래 명령으로 도움말이 나오면 정상입니다
aegisscan --help
```

출력 예시:
```
usage: aegisscan [-h] [--version] {scan,import-nmap,external,report,serve} ...

AegisScan: Professional Network Security Scanner

positional arguments:
  {scan,import-nmap,external,report,serve}
    scan                Connect(+ SYN) 스캔 실행
    import-nmap         Nmap XML 결과 임포트
    external            외부 관측 비교 (Shodan/Censys) + CVE/EPSS 분석
    report              HTML 리포트 생성
    serve               웹 대시보드 시작
```

---

## STEP 1. 환경 변수 설정 (.env)

프로젝트 루트(`/Users/ohreo/aegisscan/`)에 `.env` 파일을 생성합니다. 외부 비교를 사용하지 않는다면 이 단계는 건너뛰어도 됩니다.

```bash
cat > .env << 'EOF'
# ===== DB (기본값으로 SQLite, 보통 수정 불필요) =====
DATABASE_URL=sqlite+aiosqlite:///./aegisscan.db

# ===== 외부 관측 API 키 (선택) =====
# Shodan — https://account.shodan.io 에서 발급
# CVE 추출 기능을 사용하려면 Shodan API 키가 필요합니다
SHODAN_API_KEY=

# Censys — https://search.censys.io/account/api 에서 발급
CENSYS_API_ID=
CENSYS_API_SECRET=

# ===== 스캔 기본값 (보통 수정 불필요) =====
DEFAULT_TIMEOUT_SEC=3.0
DEFAULT_RETRIES=2
DEFAULT_RATE_LIMIT_PER_SEC=100
EOF
```

> **참고**: EPSS 점수 조회는 FIRST.org의 공개 API를 사용하므로 별도 API 키가 필요하지 않습니다.

---

## STEP 2. 포트 스캔 실행

> **경고**: 반드시 본인이 소유하거나 스캔 허가를 받은 자산에만 사용하세요. `--i-own-or-am-authorized` 플래그 없이는 실행되지 않습니다.

### 기본 Connect 스캔 (가장 일반적)

```bash
aegisscan scan \
  --targets 127.0.0.1 \
  --ports 22,80,443,3306,8080 \
  --i-own-or-am-authorized
```

**실행 시 일어나는 일:**
1. SQLite DB 초기화 (최초 1회 자동, `aegisscan.db` 파일 생성)
2. 지정 호스트:포트에 TCP Connect 시도 → open / closed / filtered 판정
3. open 포트에 대해 **배너 그랩** (HTTP Server 헤더, SSH 버전 등)
4. HTTPS 포트(443, 8443)에 대해 **TLS 인증서** 수집
5. **웹 보안 자동 분석** (HTTP 포트 대상):
   - 관리자 페이지 노출 탐지 (23개 경로 프로빙)
   - 서버 정보 누출 탐지 (15개 패턴 매칭)
   - 디렉터리 리스팅 탐지 (5개 패턴 매칭)
   - **위험 탐지 시 Playwright로 실시간 스크린샷 자동 캡처** → `screenshots/` 폴더에 PNG 저장
6. 결과 전부 DB에 저장 후 `scan_run_id` 출력

### 웹 보안 자동 분석 상세

스캔 시 open 상태인 HTTP 포트(80, 443, 8080, 8443 등)에 대해 **자동으로** 다음 3가지 분석을 수행합니다:

#### ① 관리자 페이지 노출 (Admin Page Exposure)

| 탐지 조건 | 심각도 |
|-----------|--------|
| URL 경로에 `/admin`, `/login`, `/manage`, `/setup`, `/config`, `/wp-admin`, `/phpmyadmin`, `/console`, `/dashboard` 등이 포함되고, 응답이 실제 로그인/관리 페이지인 경우 | **high** |
| HTTP 401/403 인증 요구 응답 | **high** |

프로빙하는 경로 목록 (23개):
```
/admin, /admin/, /administrator, /login, /signin, /manage, /manager,
/management, /setup, /install, /config, /configuration, /wp-admin,
/wp-login.php, /phpmyadmin, /phpMyAdmin, /pma, /cpanel, /webmail,
/admin/login, /admin/dashboard, /console, /dashboard
```

#### ② 서버 정보 누출 (Information Leakage)

| 탐지 조건 | 심각도 |
|-----------|--------|
| 응답 헤더/본문에 `Apache/2.4.X`, `nginx/1.X`, `PHP/7.X.X`, `Microsoft-IIS/10.0` 등 서버 버전 정보 | **medium** |
| 응답 본문에 `/var/www/html/...`, `/home/user/...` 등 시스템 경로 노출 | **high** |
| Python Traceback, PHP Fatal error, Stack Trace 등 에러 메시지 노출 | **high** |

매칭 패턴 (15개):
```
Apache/X.X, nginx/X.X, PHP/X.X, Microsoft-IIS/X.X, OpenSSL/X.X,
Ubuntu, Debian, CentOS, /var/www/, /home/user/, /usr/share/,
X-Powered-By 헤더, Traceback, Fatal error, Stack Trace
```

#### ③ 디렉터리 리스팅 (Directory Listing)

| 탐지 조건 | 심각도 |
|-----------|--------|
| HTML 응답에 `<title>Index of /</title>` 포함 | **high** |
| `Name`, `Last modified`, `Size` 등 디렉터리 리스팅 특유의 표 형식 | **high** |
| `Parent Directory` 링크 존재 | **high** |

### 스크린샷 캡처

위 3가지 위험이 탐지되면 **Playwright(Headless Chromium)** 를 사용하여 해당 페이지의 스크린샷을 **실시간으로 자동 캡처**합니다.

- 저장 위치: `screenshots/` 폴더 (프로젝트 루트)
- 파일명 형식: `{IP}_{PORT}_{유형}_{경로}_{타임스탬프}.png`
- 해상도: 1280×900px
- HTTPS 인증서 오류 자동 무시 (보안 스캔 특성)

> **참고**: Playwright가 설치되어 있지 않으면 탐지는 정상 수행되지만 스크린샷만 생략됩니다.

### 출력 예시

```
Enriching open ports (Banner/TLS)...
Enriching: [████████████████████████████████████████] 100% (3/3)
    ▸ 10.0.1.5:80 [Banner] http — GET / -> 200
    ▸ 10.0.1.5:443 [TLS] subject=*.example.com expires=2026-08-15

Web Security Analysis (Admin/InfoLeak/DirList)...
Web analysis: [████████████████████████████████████████] 100% (2/2)
    ▸ 10.0.1.5:80 [Admin] HTTP 200 at /admin (login page detected) [screenshot]
    ▸ 10.0.1.5:80 [InfoLeak] Apache/2.4.52; Ubuntu; PHP/8.1.2 [screenshot]
    ▸ 10.0.1.5:8080 [DirList] Directory listing detected at / [screenshot]

Web Security Findings
  TYPE           HOST:PORT              SEVERITY   EVIDENCE                                 SCREENSHOT
  ───────────────────────────────────────────────────────────────────────────────────────────────
  Admin Page     10.0.1.5:80            high       HTTP 200 at /admin                       ✓ captured
  Info Leak      10.0.1.5:80            medium     Apache/2.4.52; Ubuntu; PHP/8.1.2         ✓ captured
  Dir Listing    10.0.1.5:8080          high       Directory listing detected at /           ✓ captured

Web Security Summary
  Total findings   : 3
  Screenshots      : 3
    Admin Page      : 1
    Info Leak       : 1
    Dir Listing     : 1
```

### 대역(CIDR) 스캔

```bash
# /24 대역의 상위 1024 포트
aegisscan scan \
  --targets 192.168.1.0/24 \
  --ports 1-1024 \
  --timeout 2.0 \
  --rate 200 \
  --i-own-or-am-authorized
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--targets` | IP 또는 CIDR, 쉼표로 여러 개 | (필수) |
| `--ports` | 포트 범위. `1-1024` 또는 `22,80,443` | `1-1024` |
| `--timeout` | 포트당 연결 타임아웃(초) | `3.0` |
| `--retries` | 실패 시 재시도 횟수 | `2` |
| `--rate` | 초당 요청 제한 (부하 조절) | 제한 없음 |
| `--no-enrich` | 배너/TLS/웹분석 수집 생략 (빠른 스캔 시) | `False` |
| `--syn` | SYN 스캔 추가 (아래 참고) | `False` |

### SYN 스캔 추가 (Connect vs SYN 비교)

```bash
# root 권한 필요 (sudo)
sudo $(which aegisscan) scan \
  --targets 192.168.1.10 \
  --ports 22,80,443 \
  --syn \
  --i-own-or-am-authorized
```

**SYN 스캔이 추가되면:**
- 패킷 레벨(SYN→SYN-ACK/RST)로 포트 상태를 판정합니다.
- Connect 결과와 SYN 결과가 다르면 **"Connect vs SYN 불일치"** 가 자동으로 `diff_findings` 테이블에 기록됩니다.
  - 예: Connect=open인데 SYN=filtered → 방화벽/필터링 장비 개입 의심
- 대시보드와 리포트에서 불일치 내역을 확인할 수 있습니다.

---

## STEP 3. (선택) Nmap XML 임포트

이미 Nmap으로 스캔한 XML 결과가 있다면 DB에 병합할 수 있습니다.

### Nmap으로 XML 생성하기 (참고)

```bash
# Nmap 스캔 + XML 출력 (AegisScan 외부에서 실행)
nmap -sV -oX scan_result.xml 192.168.1.0/24
```

### AegisScan에 임포트

```bash
aegisscan import-nmap ./scan_result.xml
```

**실행 시 일어나는 일:**
1. Nmap XML 파싱 (호스트, 포트, 서비스명, 버전, 스크립트 결과)
2. 기존 DB에 없는 호스트/포트는 새로 추가
3. `nmap_observations` 테이블에 Nmap 전용 정보(서비스명, 버전, 스크립트) 저장
4. 기존 자체 스캔 결과와 자동 병합

출력 예시:
```
INFO Nmap XML 파싱: 호스트 12, 항목 47
INFO Nmap 임포트 완료.
```

---

## STEP 4. (선택) 외부 관측 비교 + CVE/EPSS 분석

Shodan 또는 Censys에서 호스트의 공개 정보를 가져와 내부 스캔과 비교하고, **CVE 번호를 자동 추출**한 뒤 **EPSS 점수를 조회**하여 실질적인 위험도를 평가합니다.

### 사전 조건

`.env`에 Shodan 또는 Censys API 키가 설정되어 있어야 합니다 (STEP 1 참고).  
EPSS 점수 조회는 FIRST.org 공개 API를 사용하므로 **별도 키가 불필요**합니다.

### 실행

```bash
# Shodan 사용 (CVE 추출 + EPSS 점수 자동 조회)
aegisscan external --source shodan --limit 50

# Censys 사용
aegisscan external --source censys --limit 20

# EPSS 점수 조회를 생략하고 싶을 때
aegisscan external --source shodan --limit 50 --no-epss
```

| 옵션 | 설명 |
|------|------|
| `--source` | `shodan` 또는 `censys` |
| `--limit` | DB에 있는 호스트 중 조회할 최대 수 (API 쿼터 절약) |
| `--no-epss` | EPSS 점수 조회를 생략 (오프라인 환경 등) |

### EPSS 점수 기준 심각도

| EPSS 점수 | 심각도 | 의미 |
|-----------|--------|------|
| 0.7 이상 | **critical** | 30일 내 악용 확률이 매우 높음 — 즉시 패치 |
| 0.4 ~ 0.7 | **high** | 악용 확률이 높음 — 우선 조치 필요 |
| 0.1 ~ 0.4 | **medium** | 주의 관찰 대상 |
| 0.1 미만 | **low** | 상대적으로 낮은 위험 |

---

## STEP 5. 웹 대시보드

브라우저에서 결과를 시각적으로 확인합니다.

### 서버 시작

```bash
# 방법 1: aegisscan CLI로 시작 (권장)
aegisscan serve --port 8000

# 방법 2: uvicorn 직접 실행
cd /Users/ohreo/aegisscan
source .venv/bin/activate
uvicorn aegisscan.api.app:app --reload --host 0.0.0.0 --port 8000
```

### 대시보드에서 확인 가능한 항목

- **통계 카드**: 호스트 수, 열린 포트 수, 발견 수, **취약점(CVE) 수**, **웹 보안 발견 수**
- **열린 포트 Top**: 가장 많이 열린 포트 순위
- **Connect vs SYN 불일치**: 방화벽/필터링 의심 항목
- **Shadow Exposure**: 외부에서만 보이는 포트
- **TLS 만료 임박**: 30일 이내 만료될 인증서
- **CVE/EPSS 취약점**: EPSS 점수 기반 위험도별 취약점 목록
- **웹 보안 발견**: 관리자 페이지 노출, 정보 누출, 디렉터리 리스팅 + 스크린샷

### 주요 API 엔드포인트

```bash
# 전체 통계
curl http://localhost:8000/api/stats

# 호스트 목록 (검색 가능)
curl "http://localhost:8000/api/hosts?search=192.168"

# 특정 호스트의 포트 목록
curl http://localhost:8000/api/hosts/1/ports

# 열린 포트 Top 15
curl "http://localhost:8000/api/open-ports-top?limit=15"

# 차이/발견 목록 (유형별 필터 가능)
curl "http://localhost:8000/api/diff-findings?finding_type=shadow_exposure"
curl "http://localhost:8000/api/diff-findings?finding_type=high_epss_cve"

# 만료 임박 TLS
curl "http://localhost:8000/api/tls-expiring?days=30"

# 스캔 이력
curl http://localhost:8000/api/scan-runs

# ===== CVE/EPSS =====
curl http://localhost:8000/api/vulnerabilities
curl "http://localhost:8000/api/vulnerabilities?severity=critical"
curl "http://localhost:8000/api/vulnerabilities?min_epss=0.1"
curl http://localhost:8000/api/vulnerabilities/summary

# ===== 웹 보안 분석 (신규) =====

# 웹 보안 발견 전체 목록
curl http://localhost:8000/api/web-findings

# 유형별 필터
curl "http://localhost:8000/api/web-findings?finding_type=admin_exposure"
curl "http://localhost:8000/api/web-findings?finding_type=info_leak"
curl "http://localhost:8000/api/web-findings?finding_type=dir_listing"

# 심각도별 필터
curl "http://localhost:8000/api/web-findings?severity=high"

# 웹 보안 요약 통계
curl http://localhost:8000/api/web-findings/summary

# 스크린샷 이미지 직접 조회
curl http://localhost:8000/api/screenshots/{filename}.png
```

---

## STEP 6. HTML 리포트 생성

대시보드 없이도 보고서를 파일로 출력할 수 있습니다.

```bash
aegisscan report --output reports/my_report.html
```

생성된 `reports/my_report.html`을 브라우저에서 열면 다음이 포함되어 있습니다:

| 섹션 | 내용 |
|------|------|
| **Executive Summary** | 총 호스트, 열린 포트, CVE 수, **웹 보안 발견 수** |
| **High Risk Findings** | Connect/SYN 불일치, 외부 노출, EPSS 고위험 CVE 등 |
| **CVE / EPSS 취약점 분석** | CVE ID(NVD 링크), EPSS 점수, 시각화 바 |
| **웹 보안 분석** | 관리자 노출/정보 누출/디렉터리 리스팅 + **스크린샷 링크** |
| **열린 포트 Top** | 포트별 건수 순위표 |
| **TLS 인증서** | 호스트, 포트, 만료일 목록 |
| **Remediation Checklist** | 방화벽 차단, 인증서 갱신, **관리자 페이지 접근 제한**, **서버 헤더 제거**, **디렉터리 리스팅 비활성화** |

```bash
# 브라우저에서 열기 (macOS)
open reports/my_report.html
```

---

## 실전 시나리오 예시

### 시나리오 A: 내부 서버 정기 점검 (웹 보안 포함)

```bash
# 1. 스캔 (배너/TLS + 웹 보안 분석 + 스크린샷 자동 수행)
aegisscan scan \
  --targets 10.0.1.1,10.0.1.2,10.0.1.3,10.0.1.10,10.0.1.20 \
  --ports 22,80,443,3306,5432,6379,8080,8443,9200 \
  --i-own-or-am-authorized

# 2. 스크린샷 확인
ls screenshots/
#  → 10.0.1.1_80_admin_admin_1709510400.png
#  → 10.0.1.3_8080_infoleak_root_1709510400.png

# 3. 리포트
aegisscan report -o reports/weekly_check.html
open reports/weekly_check.html
```

### 시나리오 B: 기존 Nmap 결과를 활용한 분석

```bash
# 1. Nmap XML 임포트
aegisscan import-nmap /shared/nmap_scan_20260305.xml

# 2. 동일 대상에 자체 스캔 추가 (배너/TLS + 웹 분석 보강)
aegisscan scan --targets 192.168.10.0/24 --ports 1-1024 --i-own-or-am-authorized

# 3. 대시보드에서 비교 확인
aegisscan serve --port 8000
```

### 시나리오 C: 외부 노출면 + CVE/EPSS 취약점 점검 (Shodan)

```bash
# 1. .env에 SHODAN_API_KEY 설정 후
# 2. 먼저 내부 스캔
aegisscan scan --targets 203.0.113.0/24 --ports 1-1024 --i-own-or-am-authorized

# 3. 외부 관측 비교 + CVE 추출 + EPSS 조회 (자동 통합 수행)
aegisscan external --source shodan --limit 50

# 4. 리포트에서 결과 확인
aegisscan report -o reports/external_cve_report.html
open reports/external_cve_report.html
```

### 시나리오 D: 웹 보안 집중 점검

```bash
# 1. HTTP 포트만 집중 스캔
aegisscan scan \
  --targets 10.0.1.0/24 \
  --ports 80,443,8080,8443,3000,5000,8000,8888,9090 \
  --i-own-or-am-authorized

# 2. 관리자 페이지 노출만 확인
curl "http://localhost:8000/api/web-findings?finding_type=admin_exposure"

# 3. 스크린샷으로 증거 확보
ls screenshots/
# → 스크린샷 파일이 자동 생성되어 있음

# 4. 리포트에 스크린샷 포함하여 보고서 생성
aegisscan report -o reports/web_security.html
open reports/web_security.html
```

---

## 데이터 모델 (DB 테이블)

AegisScan은 **11개의 테이블**로 모든 데이터를 정규화하여 저장합니다.

| 테이블 | 역할 |
|--------|------|
| `scan_runs` | 스캔 실행 이력 (시작·종료 시간, 대상, 설정 해시) |
| `hosts` | 발견된 호스트 (IP, 호스트명, 태그) |
| `ports` | 포트 상태 (open/closed/filtered, RTT, Connect/SYN 결과) |
| `services` | 식별된 서비스 (서비스명, 제품, 버전, 신뢰도) |
| `banners` | 배너 원본 데이터 + 파싱된 필드 |
| `tls_certs` | TLS 인증서 (CN, SAN, 만료일, SHA-256 핑거프린트) |
| `nmap_observations` | Nmap 전용 데이터 (서비스명, 버전, 스크립트 결과) |
| `external_observations` | 외부 관측 데이터 (Shodan/Censys) |
| `diff_findings` | 분석 결과 (불일치, Shadow Exposure, EPSS 고위험 CVE, 심각도) |
| `vulnerabilities` | CVE/EPSS 취약점 (CVE ID, EPSS 점수, 백분위, 심각도, 출처) |
| **`web_findings`** | **웹 보안 발견 (유형, URL, 근거, 심각도, 스크린샷 경로)** |

---

## 트러블슈팅

| 현상 | 해결 |
|------|------|
| `command not found: aegisscan` | `source .venv/bin/activate` 가상환경 활성화 확인 |
| 스캔이 시작 안 됨 | `--i-own-or-am-authorized` 플래그 추가 |
| SYN 스캔 `permission denied` | `sudo`로 실행, scapy 설치 여부 확인 |
| `No module named 'greenlet'` | `pip install greenlet` |
| 외부 비교 결과 0건 | `.env`에 API 키 확인, 해당 IP가 Shodan/Censys에 존재하는지 확인 |
| CVE가 발견되지 않음 | Shodan에서 해당 IP에 취약점 정보가 없을 수 있음 (정상) |
| EPSS 조회 실패 / 타임아웃 | 인터넷 연결 확인, `--no-epss` 옵션으로 생략 가능 |
| 스크린샷이 캡처되지 않음 | `pip install playwright && playwright install chromium` 실행 |
| 웹 분석에서 결과 0건 | open 포트 중 HTTP 포트가 있어야 분석됨 (80, 443, 8080 등) |
| 리포트에 데이터 없음 | `aegisscan scan`을 먼저 실행하고 `--i-own-or-am-authorized` 포함 확인 |
| DB 초기화 문제 | `aegisscan.db` 파일 삭제 후 다시 스캔 실행 |
| 기존 DB에 새 테이블 없음 | 아무 명령(`aegisscan scan` 등) 실행 시 자동 생성됨 |

---

## 프로젝트 구조

```
aegisscan/
├── src/aegisscan/
│   ├── scanner/           # Connect 스캐너, SYN 스캐너, 레이트리밋/재시도
│   ├── enrichment/        # 배너 그랩, TLS 인증서 수집, 웹 보안 분석
│   │   ├── banner.py          # HTTP/SSH/TCP 배너 그랩
│   │   ├── tls_inspector.py   # TLS 인증서 수집
│   │   └── web_analyzer.py    # 관리자 노출/정보 누출/디렉터리 리스팅 + 스크린샷
│   ├── importer/          # Nmap XML 파싱·정규화
│   ├── external/          # Shodan/Censys 플러그인, EPSS 클라이언트
│   │   ├── base.py            # 외부 커넥터 추상 베이스
│   │   ├── shodan_connector.py # Shodan API + CVE 추출
│   │   ├── censys_connector.py # Censys API
│   │   └── epss_client.py     # FIRST.org EPSS API 배치 조회
│   ├── data/              # SQLAlchemy 모델 (11개 테이블), 세션
│   ├── service/           # 스캔 오케스트레이션, 외부 비교, 웹 분석 통합
│   ├── api/               # FastAPI 대시보드 + 스크린샷 제공 API
│   ├── report/            # Jinja2 HTML 리포트 생성
│   ├── templates/         # 리포트 템플릿 (CVE/EPSS + 웹 보안 섹션)
│   ├── config.py          # 설정(.env 로드)
│   ├── console.py         # CLI 컬러 출력, 결과 테이블 포맷
│   └── cli.py             # CLI 진입점
├── screenshots/           # 웹 보안 스크린샷 자동 저장 폴더
├── .env                   # 환경변수 (API 키 등)
├── aegisscan.db           # SQLite DB (자동 생성, 11개 테이블)
├── reports/               # 생성된 리포트 저장 폴더
├── requirements.txt
└── pyproject.toml
```

## 라이선스

MIT
