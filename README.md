# AegisScan

**포트 스캔 기반 공격표면(Attack Surface) 통합 분석·리포팅 플랫폼**

내부 자산에 대한 고성능 포트 스캔(Connect/SYN) 결과를 기반으로 서비스 식별(배너·TLS), Nmap 결과 연동, 외부 관측(Shodan/Censys) 비교를 통해 **현재 노출면과 위험 요약**을 대시보드/보고서로 자동 제공합니다.

## 요구사항

- Python 3.10+
- (선택) SYN 스캔: `scapy`, **관리자/root 권한** (raw socket)
- (선택) 외부 비교: Shodan/Censys API 키

## 설치

```bash
cd aegisscan
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
# greenlet이 SQLAlchemy 비동기 세션에 필요하므로 함께 설치됨
```

## 빠른 시작

### 1. DB 초기화 및 Connect 스캔 (허가된 자산만 스캔)

```bash
# 허가된 자산임을 확인한 뒤 스캔 (필수 플래그)
python -m aegisscan.cli scan --targets 127.0.0.1 --ports 22,80,443,8080 --i-own-or-am-authorized
```

- `--targets`: IP 또는 CIDR (쉼표 구분, 예: `192.168.1.0/24`, `10.0.0.1`)
- `--ports`: 포트 범위 `1-1024` 또는 `80,443,22`
- `--syn`: SYN 스캔 추가 (root/관리자 권한 필요)
- `--no-enrich`: 배너/TLS 수집 생략
- `--rate`: 초당 요청 제한 (예: `100`)

### 2. Nmap XML 임포트

```bash
python -m aegisscan.cli import-nmap /path/to/nmap-result.xml
```

### 3. 외부 관측 비교 (API 키 필요)

`.env`에 설정:

```
SHODAN_API_KEY=your_key
CENSYS_API_ID=...
CENSYS_API_SECRET=...
```

```bash
python -m aegisscan.cli external --source shodan --limit 50
```

### 4. HTML 리포트 생성

```bash
python -m aegisscan.cli report --output reports/report.html
```

### 5. 웹 대시보드

```bash
uvicorn aegisscan.api.app:app --reload --host 0.0.0.0 --port 8000
```

브라우저에서 `http://localhost:8000` 접속. API 문서: `http://localhost:8000/docs`

## 프로젝트 구조

```
aegisscan/
├── src/aegisscan/
│   ├── scanner/       # Connect 스캐너, SYN 스캐너, 레이트리밋/재시도
│   ├── enrichment/    # 배너 그랩, TLS 인증서 수집
│   ├── importer/      # Nmap XML 파싱·정규화
│   ├── external/      # Shodan/Censys 플러그인
│   ├── data/          # SQLAlchemy 모델, 세션
│   ├── service/       # 스캔 오케스트레이션, 외부 비교
│   ├── api/            # FastAPI 대시보드
│   ├── report/         # Jinja2 HTML 리포트
│   └── cli.py          # CLI 진입점
├── templates/reports/
├── requirements.txt
├── pyproject.toml
└── GUIDE.md            # 상세 가이드
```

## 데이터 모델 요약

- **scan_runs**: 스캔 실행 이력, config_hash로 재현
- **hosts / ports**: 호스트·포트 상태 (state_connect, state_syn)
- **services / banners / tls_certs**: 서비스 식별·배너·TLS
- **nmap_observations**: Nmap 임포트 결과
- **external_observations**: Shodan/Censys 등 외부 관측
- **diff_findings**: Connect vs SYN 불일치, Shadow exposure 등

## 비기능 요구사항

- **윤리/안전**: 스캔 전 `--i-own-or-am-authorized` 로 허가된 자산 확인 필수
- **재현성**: ScanRun별 `config_hash`로 동일 설정 재실행 가능
- **보안**: API 키는 `.env` 또는 환경변수 사용, 코드에 하드코딩 금지

## 라이선스

MIT
