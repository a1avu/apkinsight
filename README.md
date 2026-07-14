# APKInsight

Android APK 파일을 업로드하면 보안 취약점을 자동으로 분석하고 리포트를 생성해주는 웹 서비스입니다.

## 주요 기능

- **APK 디컴파일** — JADX로 소스코드 추출, 패키지명 기반 써드파티 필터링
- **라이브러리 버전 탐지** — META-INF, DEX, `.so`, pom.properties 등 다중 경로 파싱
- **CVE 조회** — OSV.dev Batch API로 탐지된 라이브러리의 취약점 자동 조회 및 한국어 번역
- **정적 분석** — mobsfscan + 커스텀 패턴(patterns.json) 기반 코드 스캔
- **AI 분석** — Gemini API(비동기 병렬 배치) 또는 자체 Ollama 서버를 통한 취약점 분석 및 수정 방안 제시
- **위험 점수 산출** — 심각도(High/Medium/Low) 및 CVE 기반 점수 계산
- **PDF 보고서 생성** — 분석 결과를 한국어 PDF로 다운로드
- **분석 이력 관리** — PostgreSQL 기반 분석 결과 저장/조회/삭제

## 기술 스택

| 구분 | 기술 |
|------|------|
| 프론트엔드 | React + TypeScript + shadcn/ui + Vite |
| 백엔드 | FastAPI + Python 3.12 |
| DB | PostgreSQL 17 |
| 정적 분석 | JADX 1.5.4, mobsfscan 0.4.5 |
| CVE 조회 | OSV.dev API |
| AI 분석 | Google Gemini API (asyncio 비동기 병렬 처리) / Ollama |
| 컨테이너 | Docker (멀티스테이지 빌드) |

## 실행 방법

### 요구사항

- Docker
- Docker Compose
- Git

### 최신 코드 받기

처음 클론하거나 업데이트된 코드를 받을 때:

```bash
# 처음 클론
git clone https://github.com/a1avu/apkinsight.git
cd apkinsight

# 이미 클론한 경우 최신 코드로 업데이트
git pull origin main
```

코드를 pull한 후에는 반드시 `--build` 옵션으로 다시 빌드하세요.

### 시작

```bash
docker compose up --build
```

빌드 완료 후 브라우저에서 `http://localhost:8000` 접속

### 종료

```bash
docker compose down
```

분석 결과(DB 데이터)를 함께 삭제하려면:

```bash
docker compose down -v
rm -rf db_data
```

## 사용 방법

1. **APK 업로드** — 메인 페이지에서 분석할 `.apk` 파일을 업로드
2. **LLM 선택** — Gemini 또는 Ollama 중 하나를 선택하고 API 키 입력
3. **분석 진행** — 7단계 파이프라인이 순서대로 실행되며 진행 상황 표시
4. **결과 확인** — 분석 완료 후 취약점 목록, 라이브러리/CVE, 위험 점수 확인
5. **PDF 다운로드** — 상세 분석 페이지에서 보고서 다운로드

## 분석 파이프라인

| 단계 | 내용 | 출력 파일 |
|------|------|-----------|
| 1/7 | JADX 디컴파일 | `jadx_out/` |
| 2/7 | 라이브러리 버전 탐지 | `{apk_name}_libs.json` |
| 3/7 | OSV CVE 조회 | `{apk_name}_osv.json` |
| 4/7 | mobsfscan 정적 분석 | `{apk_name}_mobsfscan.json` |
| 5/7 | 커스텀 패턴 매칭 | `{apk_name}_custom.json` |
| 6/7 | 결과 병합 | `{apk_name}_merge.json` |
| 7/7 | AI 분석 (비동기 병렬 배치, 최대 3회 재시도) | `{apk_name}_llm.json` |

분석 결과는 `output/{apk_name}/` 폴더와 PostgreSQL DB에 저장됩니다.

## 디렉터리 구조

```
.
├── backend/                  # FastAPI 백엔드
│   ├── analyze.py            # 메인 서버 + 분석 파이프라인
│   ├── lib_version_detect.py # 라이브러리 버전 탐지
│   ├── osv_lookup.py         # OSV CVE 조회
│   ├── merge.py              # 분석 결과 병합
│   ├── grep_custom.py        # 커스텀 패턴 스캔
│   ├── gemini_api.py         # Gemini AI 분석
│   ├── ollama_client.py      # Ollama AI 분석
│   ├── pdf_report.py         # PDF 보고서 생성
│   ├── manifest_analyzer.py  # AndroidManifest 분석
│   ├── patterns.json         # 커스텀 보안 패턴 룰셋
│   ├── lib_patterns.json     # 라이브러리 탐지 룰셋
│   ├── init_db.py            # DB 테이블 초기화
│   ├── db_insert.py          # DB 저장
│   ├── db_select.py          # DB 조회
│   └── db_delete.py          # DB 삭제
├── front-react/              # React 프론트엔드
│   └── src/
│       └── pages/
│           ├── UploadScan.tsx      # APK 업로드 페이지
│           ├── Dashboard.tsx       # 대시보드
│           ├── RecentScans.tsx     # 분석 이력 목록
│           └── DetailedAnalysis.tsx # 상세 분석 결과
├── input/                    # APK 임시 업로드 경로 (볼륨 마운트)
├── output/                   # 분석 결과 저장 경로 (볼륨 마운트)
├── ollama_server.py          # Ollama 전용 분석 서버 (별도 실행)
├── Dockerfile                # 멀티스테이지 빌드 (React + Python)
└── compose.yaml              # Docker Compose 설정
```

## Ollama 서버 (`ollama_server.py`)

로컬에 설치된 Ollama를 FastAPI로 감싸는 **별도 분석 서버**입니다. 메인 Docker 앱과 독립적으로 실행되며, 프론트엔드에서 LLM 선택 시 "Ollama"를 선택하면 이 서버가 호출됩니다.

### 사전 요구사항

- [Ollama](https://ollama.com) 설치 및 실행 중
- 분석에 사용할 모델 다운로드:
  ```bash
  ollama pull qwen3.5:9b
  ```
- Python 패키지:
  ```bash
  pip install fastapi uvicorn requests json-repair
  ```

### 실행

```bash
uvicorn ollama_server:app --host 0.0.0.0 --port 8001
```

기본적으로 Ollama는 `http://localhost:11434`에서 실행 중이어야 합니다.

### 인증

모든 요청에 `x-api-key` 헤더가 필요합니다.

허용된 API 키:

| 키 |
|----|
| `01092298107` |
| `01088842022` |
| `01099638729` |
| `01071811680` |

### 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/analyze` | findings JSON 파일을 받아 LLM 분석 결과 반환 |
| `GET` | `/health` | 서버 상태 및 로드된 모델 확인 |

#### `POST /analyze` 요청 예시

```bash
curl -X POST http://localhost:8001/analyze \
  -H "x-api-key: 01092298107" \
  -F "file=@{apk_name}_final_custom.json"
```

#### `/analyze` 응답 형식

false positive가 제거된 findings 배열을 반환합니다. 각 항목에 `risk`, `explanation`, `fix` 필드가 추가됩니다.

```json
[
  {
    "type": "hardcoded_secret",
    "file_path": "com/example/Config.java",
    "code": "String API_KEY = \"abc123\";",
    "risk": "HIGH",
    "explanation": "API 키가 소스코드에 하드코딩되어 있어 APK 역공학 시 노출됩니다.",
    "fix": "서버에서 런타임에 수신하거나 환경 변수로 분리하세요. 예: `String key = BuildConfig.API_KEY;`"
  }
]
```

### 동작 방식

- findings를 5개씩 배치로 나눠 순서를 섞은 뒤 Ollama에 순차 전송
- 각 배치 최대 3회 재시도, 실패 시 모델을 언로드 후 재시도
- `_idx` 필드로 배치 처리 후 원래 순서로 결과 재조합
- false positive로 판단된 항목은 최종 결과에서 제거

### 메인 앱과 연결하기

`ollama_server.py`는 Docker 바깥에서 실행되는 별도 서버입니다. Docker 앱이 이 서버를 호출하려면 `backend/ollama_client.py`의 `SERVER_URL`을 실행 중인 서버 주소로 변경해야 합니다.

```python
# backend/ollama_client.py
SERVER_URL = "http://<ollama-server-ip>:<port>/analyze"
```

변경 후 Docker 앱을 다시 빌드하세요:

```bash
docker compose up --build
```

---

## API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/analyze` | APK 파일 업로드 및 분석 시작 |
| `GET` | `/status` | 현재 분석 진행 상태 조회 |
| `GET` | `/result` | 최신 분석 결과 조회 (1회성) |
| `GET` | `/analysis/list` | 전체 분석 이력 목록 |
| `GET` | `/analysis/{id}` | 특정 분석 상세 결과 |
| `GET` | `/analysis/{id}/osv` | 특정 분석의 라이브러리/CVE 정보 |
| `GET` | `/report/{id}` | PDF 보고서 다운로드 |
| `DELETE` | `/analysis/{id}` | 분석 결과 삭제 (DB + 파일) |

## 룰셋 커스터마이징

### 보안 패턴 추가 (`backend/patterns.json`)

커스텀 grep 스캔에 사용되는 보안 패턴을 정의합니다. 코드 수정 없이 JSON 편집만으로 새 패턴을 추가할 수 있습니다.

### 라이브러리 탐지 패턴 추가 (`backend/lib_patterns.json`)

Maven 좌표, DEX 클래스 패턴, META-INF 경로 등 라이브러리 탐지 규칙을 정의합니다. 새 라이브러리 추가 시 코드 수정 없이 JSON만 편집하면 됩니다.

## 환경 변수

`compose.yaml`에서 아래 값을 변경할 수 있습니다.

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `DB_HOST` | `db` | PostgreSQL 호스트 |
| `DB_PORT` | `5432` | PostgreSQL 포트 |
| `DB_NAME` | `apkinsight` | DB 이름 |
| `DB_USER` | `apkinsight` | DB 사용자 |
| `DB_PASSWORD` | `apkinsight123` | DB 비밀번호 |
