# AegisScan 사용 가이드

## 1. 설치 및 환경

### 1.1 설치

```bash
cd aegisscan
pip install -e .
```

또는 의존성만 설치 후 모듈로 실행:

```bash
pip install -r requirements.txt
# 실행 시 프로젝트 루트에서
PYTHONPATH=src python -m aegisscan.cli scan --targets 127.0.0.1 --ports 80 --i-own-or-am-authorized
```

### 1.2 환경 변수 (.env)

프로젝트 루트에 `.env` 파일을 두고 다음을 설정할 수 있습니다.

```ini
# DB (기본: sqlite+aiosqlite:///./aegisscan.db)
DATABASE_URL=sqlite+aiosqlite:///./aegisscan.db

# 외부 관측 (선택)
SHODAN_API_KEY=your_shodan_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret

# 스캔 기본값
DEFAULT_TIMEOUT_SEC=3.0
DEFAULT_RETRIES=2
DEFAULT_RATE_LIMIT_PER_SEC=100
```

---

## 2. CLI 사용법

### 2.1 스캔 (scan)

**반드시 허가된 자산에만 사용하세요.** `--i-own-or-am-authorized` 없으면 스캔이 실행되지 않습니다.

```bash
# 단일 호스트, 주요 포트만
aegisscan scan --targets 192.168.1.10 --ports 22,80,443,8080 --i-own-or-am-authorized

# 대역 스캔 (예: /24)
aegisscan scan --targets 192.168.1.0/24 --ports 1-1024 --i-own-or-am-authorized

# 여러 대역/호스트
aegisscan scan --targets 10.0.0.0/24,192.168.1.1 --ports 1-1024 --i-own-or-am-authorized

# SYN 스캔 포함 (root/관리자 권한 필요, scapy 사용)
sudo aegisscan scan --targets 192.168.1.0/24 --ports 80,443 --syn --i-own-or-am-authorized

# 배너/TLS 수집 없이 포트만
aegisscan scan --targets 127.0.0.1 --ports 1-1000 --no-enrich --i-own-or-am-authorized

# 레이트 제한 (초당 50개)
aegisscan scan --targets 192.168.1.0/24 --ports 80,443 --rate 50 --i-own-or-am-authorized
```

- **Connect 스캔**: 애플리케이션 레벨 TCP 연결. 권한 불필요.
- **SYN 스캔**: 패킷 레벨. 방화벽/필터링 차이로 Connect와 결과가 다를 수 있음. 이 차이는 대시보드/리포트의 "Connect vs SYN 불일치"로 확인 가능.

### 2.2 Nmap XML 임포트 (import-nmap)

이미 Nmap으로 스캔한 결과를 DB에 넣을 때 사용합니다.

```bash
aegisscan import-nmap /path/to/scan.xml
```

- 서비스명·버전·스크립트 결과가 `nmap_observations` 등으로 정규화되어 저장됩니다.
- 동일 호스트/포트가 있으면 Nmap 관측만 추가됩니다.

### 2.3 외부 관측 비교 (external)

Shodan/Censys에서 공개된 포트/서비스 정보를 가져와 내부 스캔과 비교합니다.  
**외부에만 보이는 포트(Shadow exposure)** 가 있으면 `diff_findings`에 기록됩니다.

```bash
# Shodan (SHODAN_API_KEY 필요)
aegisscan external --source shodan --limit 50

# Censys (CENSYS_API_ID, CENSYS_API_SECRET 필요)
aegisscan external --source censys --limit 50
```

- `--limit`: DB에 있는 호스트 중 조회할 개수.

### 2.4 리포트 생성 (report)

현재 DB 내용을 바탕으로 HTML 리포트를 생성합니다.

```bash
aegisscan report --output reports/report.html
```

- Executive Summary, High Risk Findings, 열린 포트 Top, TLS 목록, Remediation Checklist 등이 포함됩니다.

---

## 3. 웹 대시보드

```bash
uvicorn aegisscan.api.app:app --reload --host 0.0.0.0 --port 8000
```

- **대시보드**: http://localhost:8000  
- **API 문서**: http://localhost:8000/docs  

### 주요 API

| 경로 | 설명 |
|------|------|
| `GET /api/stats` | 호스트 수, 열린 포트 수, 발견 수 |
| `GET /api/scan-runs` | 스캔 실행 이력 |
| `GET /api/hosts` | 호스트 목록 (search 파라미터로 필터) |
| `GET /api/hosts/{id}/ports` | 해당 호스트 포트 목록 |
| `GET /api/open-ports-top` | 열린 포트별 건수 Top N |
| `GET /api/diff-findings` | Connect vs SYN 불일치, Shadow exposure 등 |
| `GET /api/tls-expiring?days=30` | 만료 임박 TLS 인증서 |

---

## 4. 사용 시나리오

### 시나리오 1: 내부 자산 점검 (기본)

1. 자산 목록(호스트/대역) 확인 후 `--i-own-or-am-authorized` 와 함께 스캔 실행.
2. Connect(+ 필요 시 SYN) 스캔 후 열린 포트에 배너/TLS 수집.
3. 대시보드에서 서비스 분포·주요 노출 포트 확인.
4. `aegisscan report -o reports/scan.html` 로 HTML 리포트 저장.

### 시나리오 2: Nmap 결과와 결합

1. 운영팀이 생성한 Nmap XML을 `aegisscan import-nmap scan.xml` 로 임포트.
2. 필요 시 동일 대역에 대해 자체 스캔을 돌려 결과 병합.
3. 대시보드/리포트에서 "변경점·리스크 요약" 확인.

### 시나리오 3: 외부 노출면 비교 (공격표면 관리)

1. Shodan/Censys API 키 설정 후 `aegisscan external --source shodan` 실행.
2. 대시보드 "외부에만 노출된 포트" / `diff_findings` 확인.
3. Remediation Checklist에 따라 방화벽/보안그룹/리버스프록시 등 조치 검토.

---

## 5. 주의사항 및 제한

- **법적·윤리**: 허가 없는 네트워크 스캔은 금지됩니다. 반드시 소유하거나 권한이 있는 자산만 스캔하세요.
- **SYN 스캔**: raw socket 사용으로 인해 Windows에서는 제한이 있을 수 있고, Linux/macOS에서는 root 권한이 필요할 수 있습니다. scapy 미설치 시 SYN 스캔은 건너뜁니다.
- **외부 API**: Shodan/Censys는 쿼터 제한이 있으므로 `--limit` 로 호스트 수를 조절하세요.
- **성능**: 대역이 크면 포트 수·타임아웃·레이트에 따라 시간이 길어질 수 있습니다. `--ports` 로 범위를 줄이거나 `--rate` 로 부하를 조절하세요.

---

## 6. 트러블슈팅

| 현상 | 확인 사항 |
|------|-----------|
| `ModuleNotFoundError: aegisscan` | `pip install -e .` 또는 `PYTHONPATH=src` 로 실행 |
| 스캔이 시작되지 않음 | `--i-own-or-am-authorized` 지정 여부 |
| SYN 스캔이 동작하지 않음 | scapy 설치 여부, root/관리자 권한, 방화벽 |
| 외부 비교 결과 없음 | .env 의 API 키, 해당 IP가 Shodan/Censys에 존재하는지 |
| 리포트 템플릿 오류 | `aegisscan.templates` 패키지에 `report.html` 포함 여부 (pip install -e . 권장) |

이 가이드로 AegisScan을 실무에 맞게 조정·확장할 수 있습니다.
