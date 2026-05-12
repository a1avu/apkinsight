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
    reportlab \
    cvss

# 작업 디렉토리
WORKDIR /app

# 백엔드 파일 복사
COPY backend/ .
COPY front-react/dist/ front-react/dist/

# 입출력 디렉토리
RUN mkdir -p /input /output

# JADX 결과 경로
ENV JADX_OUT_DIR=/output/jadx
ENV JADX_SOURCES_DIR=/output/jadx/sources

ENTRYPOINT ["python3", "analyze.py"]