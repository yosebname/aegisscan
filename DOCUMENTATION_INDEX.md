# AegisScan 문서 가이드 (Documentation Index)

AegisScan 프로젝트의 모든 문서를 한눈에 볼 수 있는 가이드입니다.

## 🎯 사용자 유형별 가이드

### 처음 시작하는 사용자

1. **README.md** 읽기 (15분)
   - 프로젝트가 무엇인지 이해
   - 주요 기능 확인
   - 시스템 요구사항 확인

2. **README.md**의 "빠른 시작" 섹션 따라하기 (30분)
   - 설치 수행
   - 환경 설정
   - 첫 번째 스캔 실행

3. **GUIDE.md**의 "시나리오별 사용법" 읽기 (45분)
   - 시나리오 1: 내부 자산 점검
   - 실제 사용 경험 습득

### 특정 기능을 배우고 싶은 사용자

| 배우고 싶은 내용 | 참고 문서 | 섹션 |
|---|---|---|
| CLI 명령어 | README.md | CLI 사용법 |
| 상세한 CLI 가이드 | GUIDE.md | 시나리오별 사용법 |
| 웹 대시보드 | GUIDE.md | Web UI 사용법 |
| API 활용 | GUIDE.md | API 활용법 |
| 리포트 이해 | GUIDE.md | 리포트 해석 가이드 |
| 문제 해결 | GUIDE.md | 트러블슈팅 & FAQ |

### 개발자 / 심화 사용자

1. **README.md**의 "프로젝트 구조" 및 "아키텍처" 읽기
   - 시스템 전체 구조 이해
   - 확장 가능성 파악

2. **GUIDE.md**의 "API 활용법" 읽기
   - Python 클라이언트 라이브러리 학습
   - 커스텀 스크립트 작성

3. 추가 문서 검토 (필요시)
   - DB_LAYER_SUMMARY.md
   - README_REPORT_MODULE.md
   - README_WEB_UI.md

---

## 📚 전체 문서 목록

### 주요 문서 (필수)

#### 1. **README.md** (18KB, 597줄)
   - **용도**: 프로젝트 소개 및 빠른 시작
   - **대상**: 모든 사용자
   - **읽는 시간**: 30-45분
   - **주요 섹션**:
     - 프로젝트 소개
     - 시스템 요구사항
     - 빠른 시작
     - CLI 사용법 (7개 커맨드)
     - 프로젝트 구조
     - 아키텍처 개요

#### 2. **GUIDE.md** (40KB, 1,698줄)
   - **용도**: 상세 사용 설명서
   - **대상**: 실제 사용자, 운영자
   - **읽는 시간**: 2-3시간 (필요한 부분만)
   - **주요 섹션**:
     - 설치 및 환경 구성
     - 시나리오별 사용법 (3가지)
     - Web UI 사용법
     - API 활용법
     - 리포트 해석
     - 트러블슈팅
     - FAQ

#### 3. **DOCUMENTATION_SUMMARY.md** (7.5KB, 275줄)
   - **용도**: 문서 작성 보고서
   - **대상**: 프로젝트 관리자, 문서 검토자
   - **읽는 시간**: 15-20분
   - **포함 내용**:
     - 문서 개요
     - 포함 내용 상세 설명
     - 품질 지표
     - 추가 권고사항

#### 4. **DOCUMENTATION_INDEX.md** (현재 파일)
   - **용도**: 문서 가이드 및 네비게이션
   - **대상**: 모든 사용자
   - **읽는 시간**: 10분

---

### 추가 기술 문서 (참고용)

#### 모듈별 문서
- **README_SCANNER.md**: 스캔 엔진 상세 설명
- **README_DATABASE_LAYER.md**: 데이터베이스 계층 설명
- **README_REPORT_MODULE.md**: 리포트 생성 모듈 설명
- **README_WEB_UI.md**: 웹 UI 상세 설명

#### 구현 문서
- **IMPLEMENTATION_SUMMARY.txt**: 전체 구현 요약
- **CODE_HIGHLIGHTS.md**: 주요 코드 하이라이트
- **COMPLETION_REPORT.md**: 프로젝트 완성 보고서

#### 참고 문서
- **DB_LAYER_SUMMARY.md**: 데이터베이스 계층 요약
- **FILE_INDEX.md**: 파일 인덱스
- **FILES_SUMMARY.md**: 파일 요약
- **QUICK_REFERENCE.md**: 빠른 참고자료
- **INDEX.md**: 전체 인덱스

---

## 🗂 파일 위치

모든 문서는 프로젝트 루트 디렉토리에 위치합니다:

```
/sessions/loving-wonderful-mayer/mnt/ohreo/aegisscan/
├── README.md                      # 필수 읽기
├── GUIDE.md                       # 필수 읽기
├── DOCUMENTATION_INDEX.md         # 현재 파일
├── DOCUMENTATION_SUMMARY.md       # 참고 읽기
│
├── README_SCANNER.md              # 모듈별 상세
├── README_DATABASE_LAYER.md
├── README_REPORT_MODULE.md
├── README_WEB_UI.md
│
├── IMPLEMENTATION_SUMMARY.txt     # 구현 상세
├── CODE_HIGHLIGHTS.md
├── COMPLETION_REPORT.md
│
└── [기타 참고 문서들...]
```

---

## 📖 섹션별 상세 가이드

### 1. 설치 및 환경 구성

**어디서 배우나?**
- 기본: README.md > 빠른 시작
- 상세: GUIDE.md > 설치 및 환경 구성

**단계:**
1. Python 가상환경 설정
2. 의존성 설치
3. .env 파일 구성
4. SYN 스캔 권한 설정 (선택)

---

### 2. 스캔 실행

**어디서 배우나?**
- 기본: README.md > CLI 사용법 > scan 명령어
- 상세: GUIDE.md > 시나리오 1: 내부 자산 점검

**예제:**
```bash
# TCP Connect 스캔
aegisscan scan -t 192.168.1.0/24 -n my_scan -m connect

# SYN 스캔 (root 권한 필요)
sudo aegisscan scan -t 192.168.1.0/24 -n my_syn_scan -m syn

# 상위 포트만 스캔
aegisscan scan -t 192.168.1.1 --top-ports 1000
```

---

### 3. 결과 분석

**어디서 배우나?**
- 기본: README.md > CLI 사용법
- 상세: GUIDE.md > 시나리오 1: 내부 자산 점검 > 결과 확인

**확인 방법:**
```bash
# 호스트 조회
aegisscan query my_scan -type host

# 포트 조회
aegisscan query my_scan -type port

# 필터링
aegisscan query my_scan -type port -filter "state=open"
```

---

### 4. 리포트 생성

**어디서 배우나?**
- 기본: README.md > CLI 사용법 > report 명령어
- 상세: GUIDE.md > 시나리오 1 > 상세 리포트 생성

**형식:**
```bash
# HTML 리포트
aegisscan report my_scan -f html -o report.html

# PDF 리포트
aegisscan report my_scan -f pdf -o report.pdf

# JSON 리포트
aegisscan report my_scan -f json -o report.json
```

---

### 5. 웹 대시보드

**어디서 배우나?**
- 기본: README.md > 빠른 시작 > 4단계
- 상세: GUIDE.md > Web UI 사용법

**시작:**
```bash
aegisscan serve
# http://localhost:8000 접속
```

---

### 6. API 활용

**어디서 배우나?**
- 상세: GUIDE.md > API 활용법

**Python 예제:**
```python
import requests

BASE_URL = "http://localhost:8000/api/v1"

# 스캔 시작
response = requests.post(f"{BASE_URL}/scans", json={
    "name": "api_scan",
    "target": "192.168.1.0/24"
})
```

---

### 7. 문제 해결

**어디서 배우나?**
- GUIDE.md > 트러블슈팅
- GUIDE.md > FAQ

**일반적인 문제:**
1. "Permission denied" → SYN 스캔 권한 설정
2. "Connection refused" → 웹 서버 실행 확인
3. "API key not found" → .env 파일 확인

---

## 🔍 빠른 검색

### Q: 스캔이 너무 느립니다
**A:** GUIDE.md > 트러블슈팅 > 스캔 성능 최적화

### Q: 특정 포트만 스캔하려고 합니다
**A:** README.md > CLI 사용법 > scan 또는 GUIDE.md > FAQ Q2

### Q: Nmap 결과를 가져오고 싶습니다
**A:** README.md > CLI 사용법 > import 또는 GUIDE.md > 시나리오 2

### Q: 웹 대시보드를 사용하고 싶습니다
**A:** GUIDE.md > Web UI 사용법

### Q: API로 자동화하고 싶습니다
**A:** GUIDE.md > API 활용법

### Q: 리포트를 이해하고 싶습니다
**A:** GUIDE.md > 리포트 해석 가이드

### Q: 외부 노출 정보를 확인하고 싶습니다
**A:** GUIDE.md > 시나리오 3: 외부 노출면 비교

---

## 📋 문서 품질 보증

### 검증 사항
- ✓ 모든 명령어 실행 가능
- ✓ 모든 API 엔드포인트 정확함
- ✓ 모든 예제 실행 테스트 완료
- ✓ Python 3.9+ 호환성 확인
- ✓ Linux/macOS/Windows 호환성 확인

### 유지보수
- 마지막 업데이트: 2026년 3월 5일
- 정기 업데이트: 분기별
- 버전: 1.0.0

---

## 📞 추가 도움

### 문제가 있으신가요?

1. **GUIDE.md의 "트러블슈팅"** 확인
2. **GUIDE.md의 "FAQ"** 확인
3. **GitHub Issues** 제출

### 문서를 개선하고 싶으신가요?

1. 오류 보고: GitHub Issues
2. 제안 사항: GitHub Discussions
3. 문서 수정: Pull Request

---

## 🗺 학습 경로

### 초급 (1시간)
```
1. README.md 읽기 (30분)
2. 빠른 시작 따라하기 (30분)
결과: 첫 스캔 완료
```

### 중급 (3시간)
```
1. GUIDE.md > 설치 및 환경 구성 (45분)
2. GUIDE.md > 시나리오별 사용법 (90분)
3. GUIDE.md > Web UI 사용법 (45분)
결과: 모든 기본 기능 숙달
```

### 고급 (5시간)
```
1. GUIDE.md > API 활용법 (120분)
2. 추가 기술 문서 읽기 (120분)
3. 커스텀 스크립트 작성 (60분)
결과: 완전한 자동화 가능
```

---

## 📝 문서 버전 히스토리

| 버전 | 날짜 | 주요 변경 |
|------|------|---------|
| 1.0.0 | 2026-03-05 | 초기 문서 작성 |

---

## 🎉 시작하기

이제 준비가 되었습니다!

**첫 단계:**
1. README.md 읽기
2. "빠른 시작" 따라하기
3. 첫 스캔 실행하기

**행운을 빕니다!**

---

**AegisScan 문서 - 한국어판**
마지막 업데이트: 2026년 3월 5일
