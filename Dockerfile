# ================================
# APKInsight 분석 엔진
# Python 3.12 slim / JADX 1.5.4 / mobsfscan 0.4.5
# ================================

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Java + 유틸 + aapt 설치
RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    wget \
    unzip \
    grep \
    aapt \
    fonts-nanum \
    && rm -rf /var/lib/apt/lists/*

# JADX 1.5.4 설치
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.4/jadx-1.5.4.zip -O /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && rm /tmp/jadx.zip

ENV PATH="/opt/jadx/bin:$PATH"

# Python 라이브러리 설치
# apkleaks 삭제
RUN pip install --no-cache-dir \
    mobsfscan==0.4.5 \
    fastapi \
    uvicorn \
    python-multipart \
    requests \
    google-genai \
    pydantic  \
    psycopg[binary] \
    sqlalchemy \
    deep-translator \
    reportlab

# 작업 디렉토리
WORKDIR /app

# 분석 스크립트 복사
#apkleaks 관련 .py 삭제
COPY grep_custom.py .
COPY manifest_analyzer.py .
COPY patterns.json .
COPY merge.py .
COPY gemini_api.py .
COPY ollama_client.py .
COPY analyze.py .
COPY init_db.py .
COPY db_insert.py .
COPY db_select.py .
COPY db_delete.py .
COPY lib_version_detect.py .
COPY osv_lookup.py .
COPY lib_patterns.json .
COPY pdf_report.py .


#프론트 html 복사
COPY temp_front.html .

# 입출력 디렉토리
RUN mkdir -p /input /output

# JADX 결과 경로
ENV JADX_OUT_DIR=/output/jadx
ENV JADX_SOURCES_DIR=/output/jadx/sources

ENTRYPOINT ["python3", "analyze.py"]