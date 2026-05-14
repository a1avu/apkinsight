# APKInsight — 7주차 변경사항

그냥 꿀팁인데 vscode extension에서 Markdown Preview Github Styling 이거 설치하고 md파일 우클릭해서 preview로 열면 md 파일을 아주 이쁘게 볼 수 있답니다   (사실 걍 노션에 복붙하면 되긴 함)

## 사용법
그냥
~~~
docker compose up --build
~~~
하십쇼

## 신규 파일

| 파일 | 설명 |
|------|------|
| `lib_version_detect.py` | APK 내부 파일을 직접 파싱하여 써드파티 라이브러리 버전 탐지 |
| `osv_lookup.py` | OSV.dev API 기반 CVE 조회 + 한국어 번역 |
| `lib_patterns.json` | 탐지 룰셋 (Maven 좌표, DEX 패턴, META-INF 경로 등) |

### 사용법
```bash
# 1단계: APK에서 라이브러리/버전 추출
python lib_version_detect.py target.apk libs.json

# 2단계: OSV.dev CVE 조회
python osv_lookup.py libs.json osv_findings.json
```

---

## lib_version_detect.py

APK 내부 아래 파일들을 순서대로 파싱하여 라이브러리명 + 버전을 추출합니다.

| 탐지 대상 | 방법 |
|-----------|------|
| `META-INF/*.version` | AndroidX/kotlinx 계열 버전 파일 직접 파싱 |
| `*.properties` | `groupId` / `artifactId` / `version` 키 추출 (pom.properties 포함) |
| `lib/*.so` 파일명 | 파일명 regex로 버전 추출 (arm64-v8a 우선) |
| `kotlin-tooling-metadata.json` | Kotlin 버전 및 AGP 버전 추출 |
| `assets/` 설정파일 | `.json` / `.properties` / `.txt` 내 버전 패턴 매칭 |
| `.so` 바이너리 strings | ASCII 문자열에서 `X version Y.Y.Y` 패턴 추출 |
| `classes*.dex` | DEX 문자열 풀 — UA 패턴(`okhttp/4.9.0`)과 클래스 존재 탐지(`Lretrofit2/Retrofit;`) |
| `META-INF/` 추가 경로 | Maven `pom.properties` 누락 보강 |

버전을 못 뽑은 라이브러리는 `version: null` 상태로 등록되고 `osv_lookup.py`의 `run_osv_scan_unknown()`이 처리합니다.

모든 탐지 규칙은 `lib_patterns.json`에서 로드합니다. 새 라이브러리 추가 시 코드 수정 없이 JSON만 편집하면 됩니다.

---

## osv_lookup.py

| 변경 내용 | 설명 |
|-----------|------|
| `run_osv_scan()` | 버전 확인된 라이브러리 대상 OSV.dev 정확한 CVE 조회 |
| `run_osv_scan_unknown()` | 버전 미확인 라이브러리 대상 패키지 단위 CVE 경고 조회 |
| `translate_ko()` | `deep-translator`로 CVE summary 한국어 번역 |
| `summary_ko` 필드 | findings에 추가 — 한국어 번역 요약 |
| `summaries_ko` 필드 | warnings에 추가 — 대표 CVE 최대 3개 한국어 요약 |

`deep-translator` 미설치 시 원문 영어 그대로 반환합니다 (예외 처리됨).

---

## analyze.py

### 파이프라인 변경 (5단계 → 7단계)

| 단계 | 내용 | 출력 |
|------|------|------|
| 1단계 | JADX 디컴파일 | `jadx_out/` |
| **2단계 (신규)** | `lib_version_detect` — 라이브러리 버전 탐지 | `_libs.json` |
| **3단계 (신규)** | `osv_lookup` — OSV CVE 조회 | `_osv.json` |
| 4단계 | mobsfscan 정적 분석 | `_mobsfscan.json` |
| 5단계 | grep_custom.py 패턴 매칭 | `_custom.json` |
| 6단계 | merge.py 결과 통합 | `_merge.json` |
| 7단계 | Ollama / Gemini API 분석 | `_llm.json` |

### 추가된 import
```python
from lib_version_detect import detect_libs_from_apk
from osv_lookup import run_osv_scan, run_osv_scan_unknown
```

### DELETE /analysis/{analysis_id} 수정
- **변경 전**: DB 레코드만 삭제, `output/` 파일 잔존
- **변경 후**: DB에서 `apk_name` 조회 → DB 삭제 → `output/<apk_name>/` 폴더 `shutil.rmtree()`로 삭제
- 프론트에서 별도 파라미터 없이 `DELETE /analysis/{id}`만 보내면 됨 (shadcn 교체 후에도 동일)

### GET /analysis/{id}/osv 신규 추가
- 사이드바 조회 시 라이브러리/CVE 카드 데이터 제공용 임시 엔드포인트
- `analysis_id` → DB에서 `apk_name` 조회 → `_libs.json`, `_osv.json` 파일 읽어서 반환
- **나중에 DB에 osv/libs 테이블 추가되면 이 엔드포인트 대체 예정**

### latest_result에 libs/osv 추가
```python
payload = {
    "apk_name": apk_name,
    "data": results_to_send,
    "libs": ...,  # 신규
    "osv":  ...,  # 신규
}
```

---

## Dockerfile

```dockerfile
# 신규 COPY
COPY lib_version_detect.py .
COPY osv_lookup.py .
COPY lib_patterns.json .

# pip install에 추가
sqlalchemy       # db_delete.py 의존성 누락 수정
deep-translator  # CVE summary 한국어 번역
```

---

## temp_front.html

### 04 — 라이브러리 / CVE 카드 추가
탭 4개로 구성:

| 탭 | 내용 |
|----|------|
| 전체 | 탐지된 전체 라이브러리 목록 (버전, 타입, 소스) |
| 버전 확인 | 버전이 확인된 라이브러리 |
| CVE 발견 | CVE 존재 라이브러리 — **한국어 번역 요약(`summary_ko`) 포함** |
| 버전 미확인 경고 | 버전 불명이지만 패키지 단위 CVE 존재 — **한국어 요약(`summaries_ko`) 포함** |

### 기타 변경
- 기존 `써드파티 결과` 섹션 제거 (LLM이 써드파티 코드 미분석)
- `fetchResult()` — 분석 완료 후 `renderLibs(data.libs, data.osv)` 호출 추가
- `viewAnalysis()` — DB 조회 시 `/analysis/{id}/osv` 호출 후 `renderLibs()` 호출 추가
- `statusTextMap`에 `queing_lib_detect`, `queing_osv` 상태 추가

---

## 8주차 수행 계획

- 써드파티 관련 JSON 파일(libs.json, osv.json) DB 테이블 설계 및 저장/조회/삭제 파이프라인 구현
- shadcn UI 기반 정식 프론트엔드 연동 후 위험 점수, 진행도 기능 추가

## apkinsight_v2 변경사항

### 1. 스캔 로그 누락 수정
- `[4/7]`, `[5/7]` 단계 로그가 출력되지 않던 문제 수정
  - `analyze.py` 수정

### 2. 기능 추가
- `clean_apk` 추가

### 3. 다크 모드 업데이트
- Android 플랫폼 배지 다크 모드 색상 적용
- 취약점 유형 TOP 5 차트 배경 및 축선 색상 다크 모드 적용
- 써드파티 분석 요약 아이콘(CVE 확인 / 버전 미확인 / 취약점 없음) 다크 모드 색상 적용
- 수정 방안 박스 다크 모드 색상 적용
- 다크 모드 전환 시 로고 이미지 자동 교체 (`apkinsight.png` ↔ `apkinsight_dark.png`)
  - `dark-mode.css` 수정
  - `dark-mode.js` 수정


---

- 상세 분석 -> cve 발견 항목 -> 심각도 출력 이상하게 나옴
	(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
	-> cvss 라이브러리 사용으로 해결
- pdf 위험점수 반영 안됨, 위험도(하이/미디움/로우) 각각 갯수 못 셈 -> 해결 왠지 모르겠는데 되네 ...??  -> 0
- 백엔드 파일 한데 묶기 -> 0

- shadcn ui로 프론트 변경

- 상단 검색창 제거

- pdf 보고서 생성 양식 변경 
  -> (전체 수정방안 보여주기, cve항목 먼저 보여주기(가독성을 위해))

- 서드파티 분석에 source에 아무것도 추가가 안되던 거 수정 
  -> META-INF/com.google.android.gms_play-services-basement.version
  -> classes.dex
  -> kotlin-tooling-metadata.json
  -> pom.properties 경로 등

