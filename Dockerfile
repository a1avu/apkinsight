# ================================
# Stage 1: React 빌드
# ================================
FROM node:20-slim AS frontend-builder
WORKDIR /frontend
COPY front-react/package*.json ./
RUN npm install
COPY front-react/ ./
RUN npm run build

# ================================
# Stage 2: APKInsight 분석 엔진
# ================================
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    wget \
    unzip \
    grep \
    aapt \
    fonts-nanum \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.4/jadx-1.5.4.zip -O /tmp/jadx.zip \
    && mkdir -p /opt/jadx \
    && unzip /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && rm /tmp/jadx.zip

ENV PATH="/opt/jadx/bin:$PATH"

RUN pip install --no-cache-dir \
    mobsfscan==0.4.5 \
    fastapi \
    uvicorn \
    python-multipart \
    requests \
    google-genai \
    pydantic \
    psycopg[binary] \
    sqlalchemy \
    deep-translator \
    reportlab \
    cvss

WORKDIR /app

COPY backend/ .
# Stage 1에서 빌드된 결과물 복사
COPY --from=frontend-builder /frontend/dist/ front-react/dist/

RUN mkdir -p /input /output

ENV JADX_OUT_DIR=/output/jadx
ENV JADX_SOURCES_DIR=/output/jadx/sources

ENTRYPOINT ["python3", "analyze.py"]
