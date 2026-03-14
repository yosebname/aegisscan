# AegisScan

**포트 스캔 기반 공격표면(Attack Surface) 통합 분석·리포팅 플랫폼**

내부 자산에 대한 고성능 포트 스캔(Connect/SYN) 결과를 기반으로 서비스 식별(배너·TLS), Nmap 결과 연동, 외부 관측(Shodan/Censys) 비교를 통해 **현재 노출면과 위험 요약**을 대시보드/보고서로 자동 제공합니다.

---

## 전체 실행 흐름 요약

```
[STEP 0] 설치
    ↓
[STEP 1] .env 설정 (외부 API 키 등)
    ↓
[STEP 2] Connect / SYN 포트 스캔  →  DB 저장  →  배너·TLS 자동 수집
    ↓
[STEP 3] (선택) Nmap XML 임포트  →  내부 스캔 결과와 병합
    ↓
[STEP 4] (선택) 외부 관측 비교 (Shodan/Censys)  →  Shadow exposure 탐지
    ↓
[STEP 5] 웹 대시보드에서 결과 확인
    ↓
[STEP 6] HTML 리포트 생성
```

---

## STEP 0. 설치

### 요구사항

| 항목 | 필수 여부 | 비고 |
|------|-----------|------|
| Python 3.10+ | **필수** | 3.10 / 3.11 / 3.12 / 3.14 확인됨 |
| scapy | 선택 | SYN 스캔 사용 시 (`pip install scapy`) |
| root/관리자 권한 | 선택 | SYN 스캔 시 raw socket 필요 |
| Shodan/Censys API 키 | 선택 | 외부 관측 비교 기능 사용 시 |

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

# 3) 설치 확인 — 아래 명령으로 도움말이 나오면 정상입니다
aegisscan --help
```

출력 예시:
```
usage: aegisscan [-h] {scan,import-nmap,external,report} ...

AegisScan: 포트 스캔 기반 공격표면 분석

positional arguments:
  {scan,import-nmap,external,report}
    scan                Connect(+ SYN) 스캔 실행
    import-nmap         Nmap XML 결과 임포트
    external            외부 관측 비교 (Shodan/Censys)
    report              HTML 리포트 생성
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
5. 결과 전부 DB에 저장 후 `scan_run_id` 출력

출력 예시:
```
INFO 스캔 완료. scan_run_id=1
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
| `--no-enrich` | 배너/TLS 수집 생략 (빠른 스캔 시) | `False` |
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

## STEP 4. (선택) 외부 관측 비교

Shodan 또는 Censys에서 호스트의 공개 정보를 가져와 내부 스캔과 비교합니다.

### 사전 조건

`.env`에 API 키가 설정되어 있어야 합니다 (STEP 1 참고).

### 실행

```bash
# Shodan 사용
aegisscan external --source shodan --limit 50

# 또는 Censys 사용
aegisscan external --source censys --limit 20
```

| 옵션 | 설명 |
|------|------|
| `--source` | `shodan` 또는 `censys` |
| `--limit` | DB에 있는 호스트 중 조회할 최대 수 (API 쿼터 절약) |

**실행 시 일어나는 일:**
1. DB에 저장된 호스트 IP 목록을 가져옵니다.
2. 각 IP에 대해 Shodan/Censys API로 공개 포트·서비스 정보를 조회합니다.
3. `external_observations` 테이블에 외부 관측 데이터를 저장합니다.
4. **내부 스캔 결과와 비교:**
   - **외부에만 보이는 포트** → `diff_findings`에 `shadow_exposure` (severity: high)로 기록
   - **내부에만 열린 포트** → 경계 장비가 정상 차단 중 (정보성)

출력 예시:
```
INFO 외부 비교 완료. DiffFinding 3 건
```

---

## STEP 5. 웹 대시보드

브라우저에서 결과를 시각적으로 확인합니다.

### 서버 시작

```bash
cd /Users/ohreo/aegisscan
source .venv/bin/activate
uvicorn aegisscan.api.app:app --reload --host 0.0.0.0 --port 8000
```

출력:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [...]
```

### 접속

| URL | 내용 |
|-----|------|
| http://localhost:8000 | **대시보드 메인** — 통계, 열린 포트 Top, 불일치/외부노출, TLS 만료 |
| http://localhost:8000/docs | **Swagger API 문서** — 모든 엔드포인트를 브라우저에서 직접 테스트 |

### 대시보드에서 확인 가능한 항목

- **통계 카드**: 호스트 수, 열린 포트 수, 발견(차이/외부노출) 수
- **열린 포트 Top**: 가장 많이 열린 포트 순위
- **Connect vs SYN 불일치**: 방화벽/필터링 의심 항목
- **Shadow Exposure**: 외부에서만 보이는 포트
- **TLS 만료 임박**: 30일 이내 만료될 인증서

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

# 만료 임박 TLS
curl "http://localhost:8000/api/tls-expiring?days=30"

# 스캔 이력
curl http://localhost:8000/api/scan-runs
```

---

## STEP 6. HTML 리포트 생성

대시보드 없이도 보고서를 파일로 출력할 수 있습니다.

```bash
aegisscan report --output reports/my_report.html
```

출력:
```
INFO 리포트 저장: reports/my_report.html
```

생성된 `reports/my_report.html`을 브라우저에서 열면 다음이 포함되어 있습니다:

| 섹션 | 내용 |
|------|------|
| **Executive Summary** | 총 호스트 수, 열린 포트 수, 발견 수 |
| **High Risk Findings** | Connect/SYN 불일치, 외부 노출 등 위험 항목 |
| **열린 포트 Top** | 포트별 건수 순위표 |
| **TLS 인증서** | 호스트, 포트, 만료일 목록 |
| **Remediation Checklist** | 방화벽 차단, 인증서 갱신, VPN 제한 등 조치 템플릿 |

```bash
# 브라우저에서 열기 (macOS)
open reports/my_report.html
```

---

## 실전 시나리오 예시

### 시나리오 A: 내부 서버 10대 정기 점검

```bash
# 1. 스캔
aegisscan scan \
  --targets 10.0.1.1,10.0.1.2,10.0.1.3,10.0.1.10,10.0.1.20 \
  --ports 22,80,443,3306,5432,6379,8080,8443,9200 \
  --i-own-or-am-authorized

# 2. 리포트
aegisscan report -o reports/weekly_check.html
open reports/weekly_check.html
```

### 시나리오 B: 기존 Nmap 결과를 활용한 분석

```bash
# 1. Nmap XML 임포트
aegisscan import-nmap /shared/nmap_scan_20260305.xml

# 2. 동일 대상에 자체 스캔 추가 (배너/TLS 보강)
aegisscan scan --targets 192.168.10.0/24 --ports 1-1024 --i-own-or-am-authorized

# 3. 대시보드에서 비교 확인
uvicorn aegisscan.api.app:app --reload --port 8000
```

### 시나리오 C: 외부 노출면 점검 (Shodan)

```bash
# 1. .env에 SHODAN_API_KEY 설정 후
# 2. 먼저 내부 스캔
aegisscan scan --targets 203.0.113.0/24 --ports 1-1024 --i-own-or-am-authorized

# 3. 외부 관측 비교
aegisscan external --source shodan --limit 50

# 4. 리포트에서 "외부에만 노출된 포트" 확인
aegisscan report -o reports/external_exposure.html
open reports/external_exposure.html
```

---

## 트러블슈팅

| 현상 | 해결 |
|------|------|
| `command not found: aegisscan` | `source .venv/bin/activate` 가상환경 활성화 확인 |
| 스캔이 시작 안 됨 | `--i-own-or-am-authorized` 플래그 추가 |
| SYN 스캔 `permission denied` | `sudo`로 실행, scapy 설치 여부 확인 |
| `No module named 'greenlet'` | `pip install greenlet` |
| 외부 비교 결과 0건 | `.env`에 API 키 확인, 해당 IP가 Shodan/Censys에 존재하는지 확인 |
| 리포트에 데이터 없음 | `aegisscan scan`을 먼저 실행하고 `--i-own-or-am-authorized` 포함 확인 |
| DB 초기화 문제 | `aegisscan.db` 파일 삭제 후 다시 스캔 실행 |

---

## 프로젝트 구조

```
aegisscan/
├── src/aegisscan/
│   ├── scanner/           # Connect 스캐너, SYN 스캐너, 레이트리밋/재시도
│   ├── enrichment/        # 배너 그랩, TLS 인증서 수집
│   ├── importer/          # Nmap XML 파싱·정규화
│   ├── external/          # Shodan/Censys 플러그인
│   ├── data/              # SQLAlchemy 모델, 세션
│   ├── service/           # 스캔 오케스트레이션, 외부 비교
│   ├── api/               # FastAPI 대시보드 + static HTML
│   ├── report/            # Jinja2 HTML 리포트 생성
│   ├── templates/         # 리포트 템플릿
│   ├── config.py          # 설정(.env 로드)
│   └── cli.py             # CLI 진입점
├── .env                   # 환경변수 (API 키 등)
├── aegisscan.db           # SQLite DB (자동 생성)
├── reports/               # 생성된 리포트 저장 폴더
├── requirements.txt
└── pyproject.toml
```

## 라이선스

MIT
