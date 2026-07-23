
import json
import os
import sys
import time
import math
import random
import requests
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from json_repair import repair_json

OLLAMA_MODEL = "qwen3.5:9b"
OLLAMA_URL   = "http://localhost:11434/api/chat"
BATCH_SIZE   = 5
ALLOWED_API_KEYS = {"01092298107", "01088842022", "01099638729", "01071811680"}

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "_idx": {"type": "integer"},
                    "is_false_positive": {"type": "boolean"},
                    "risk": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                    "explanation": {"type": "string"},
                    "fix": {"type": "string"}
                },
                "required": ["_idx", "is_false_positive", "risk", "explanation", "fix"]
            }
        }
    },
    "required": ["results"]
}

app = FastAPI(title="APKInsight Ollama Analyzer")


def call_llm_batch(batch, batch_num, total_batches, retry_attempt=0):
    prompt = f"""CRITICAL: You must generate ALL {len(batch)} findings in ONE array before stopping. Do not stop after the first item.

You are a mobile application security analyst. Below is a static analysis result of an Android APK.
All findings are from the application's own code (third-party libraries have already been excluded).

For each finding, determine:
Pay attention to the "code" field to determine what is actually being stored or used.

1. is_false_positive - true if this is noise (e.g. error message strings, MIME type constants, internal routing strings, generic e.printStackTrace() with no sensitive data)
2. risk - HIGH / MEDIUM / LOW
3. explanation - one sentence in Korean for non-expert users explaining why this is dangerous
4. fix - one sentence in Korean describing the fix + a single line of secure code example (if applicable)

RULES:
- Respond ONLY with a JSON object of the form {{"results": [...]}}, where "results" is an array containing exactly {len(batch)} objects — never a bare array, never a single object.
- Output array length MUST equal input array length ({len(batch)} items). Do NOT add or remove items.
- You MUST output exactly {len(batch)} items. Each finding must have its own entry. Do NOT merge, skip, or combine any findings even if they look identical.
- NEVER invent or add findings not present in the input list.
- Each output object MUST include the "_idx" field from the corresponding input finding.
- endpoint_disclosure findings that contain only MIME types, blob:/data: prefixes, or internal framework routing are false positives.
- mobsfscan findings with null file_path and null code are advisory warnings, not confirmed vulnerabilities — set risk=LOW and is_false_positive=false.
- Risk must reflect actual exploitability. Not every finding is HIGH or MEDIUM. Use LOW for findings that are theoretically concerning but difficult to exploit in practice.
- fix field: write a short Korean sentence explaining what to change, followed by a code snippet if helpful. Example: "하드코딩 대신 서버에서 런타임에 수신하세요. 예: `String key = BuildConfig.API_KEY;`"
- fix field for manifest issues: provide the corrected XML attribute. Example: `android:allowBackup='false'`
- fix field for advisory warnings (null code): provide a general recommendation without code.
- fix field code examples: use SINGLE quotes for XML/attribute values, never double quotes, to avoid breaking JSON string escaping. Example: `<meta-data android:name='...' android:value='...'/>` NOT `android:name=\"...\"`.

Respond ONLY with a JSON object. No markdown, no explanation outside the object.
Format:
{{"results": [{{"_idx": <original _idx>, "is_false_positive": true/false, "risk": "HIGH/MEDIUM/LOW", "explanation": "한국어 위험 설명", "fix": "한국어 수정 방법 + 핵심 코드 예시"}}]}}

Findings:
{json.dumps(batch, ensure_ascii=False)}"""

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "format": RESULT_SCHEMA,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0 if retry_attempt == 0 else 0.1,
            "num_ctx": 32768,
        }
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=None)
    response.raise_for_status()
    raw = response.json()["message"]["content"].strip()

    print(f"\n[RAW OUTPUT batch {batch_num}/{total_batches}]\n{raw}\n[/RAW OUTPUT]\n")  # TEMP DEBUG

    if "```" in raw:
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as je:
        print(f"[json-repair] 복구 시도: {je}")
        raw = repair_json(raw)
        parsed = json.loads(raw)

    # results 키로 감싸져서 온 경우 풀어내기
    if isinstance(parsed, dict) and "results" in parsed:
        result = parsed["results"]
    elif isinstance(parsed, dict):
        result = [parsed]  # 혹시 여전히 단일 객체로 오면 폴백
    else:
        result = parsed  # 혹시 여전히 순수 배열로 오면 그대로

    if not isinstance(result, list) or not all(isinstance(x, dict) for x in result):
        raise ValueError(f"응답 형식 오류: 배열이 아니거나 원소가 dict가 아님 → {type(result)}")

    print(f"[DEBUG] result 타입들: {[type(x).__name__ for x in result]}")  # TEMP DEBUG
    for x in result:  # TEMP DEBUG
        print(f"  -> {repr(x)[:200]}")  # TEMP DEBUG

    if len(result) != len(batch):
        raise ValueError(f"길이 불일치: 입력 {len(batch)}개 vs 출력 {len(result)}개")

    # _idx 검증
    input_idxs = {item["_idx"] for item in batch}
    output_idxs = {item.get("_idx") for item in result}
    if input_idxs != output_idxs:
        raise ValueError(f"_idx 불일치: 입력 {input_idxs} vs 출력 {output_idxs}")

    return result


def _retry_split_batch(batch_findings, batch_num, total_batches, idx_to_result):
    """최종 재시도까지 실패한 배치를 2등분해서 한 번씩만 더 시도. 그래도 실패하면 해당 항목은 결과에서 누락된다."""
    if len(batch_findings) <= 1:
        print(f"[배치 {batch_num}/{total_batches}] 항목 {len(batch_findings)}개 분할 불가 — 누락 처리")
        return
    mid = len(batch_findings) // 2
    for half in (batch_findings[:mid], batch_findings[mid:]):
        if not half:
            continue
        try:
            result = call_llm_batch(half, batch_num, total_batches, retry_attempt=1)
            for llm_res in result:
                idx_to_result[llm_res["_idx"]] = llm_res
        except Exception as e:
            print(f"[배치 {batch_num}/{total_batches}] 분할 재시도 실패({len(half)}개) — 누락 처리: {e}")


def run_analysis(findings):
    indexed = list(enumerate(findings))
    random.shuffle(indexed)
    shuffled_findings = [f for _, f in indexed]

    total_batches = math.ceil(len(shuffled_findings) / BATCH_SIZE)
    total_start = time.time()

    # _idx 기반 결과 저장
    idx_to_result = {}

    for i in range(total_batches):
        batch_findings = shuffled_findings[i * BATCH_SIZE:(i + 1) * BATCH_SIZE]

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                result = call_llm_batch(batch_findings, i + 1, total_batches, retry_attempt=attempt - 1)
                for llm_res in result:
                    idx_to_result[llm_res["_idx"]] = llm_res
                break
            except Exception as e:
                print(f"[배치 {i+1}/{total_batches}] 오류 (시도 {attempt}/{max_retries}): {e}")
                if attempt == max_retries:
                    _retry_split_batch(batch_findings, i + 1, total_batches, idx_to_result)
                    break
                requests.post(OLLAMA_URL.replace("/api/chat", "/api/generate"),
                              json={"model": OLLAMA_MODEL, "keep_alive": 0})
                time.sleep(3)

    print(f"[LLM] 전체 완료 ({time.time() - total_start:.1f}초)")

    merged = []
    for finding in findings:
        orig_idx = finding["_idx"]
        llm_res = idx_to_result.get(orig_idx)
        if not llm_res:
            continue
        if llm_res.get("is_false_positive", False):
            continue
        item = dict(finding)
        item.pop("_idx", None)  # 최종 결과에서 _idx 제거
        item["risk"] = llm_res.get("risk", "LOW")
        item["explanation"] = llm_res.get("explanation", "")
        item["fix"] = llm_res.get("fix", "")
        merged.append(item)

    return merged

def verify_api_key(request: Request):
    api_key = request.headers.get("x-api-key")
    if not api_key or api_key not in ALLOWED_API_KEYS:
        raise HTTPException(status_code=401, detail="유효하지 않은 API 키입니다.")
    return api_key

@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key)
    ):
    """_final_custom.json 파일을 받아서 LLM 분석 결과 반환"""
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="JSON 파일만 허용됩니다.")

    content = await file.read()
    try:
        findings = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="JSON 파싱 실패")

    if not isinstance(findings, list):
        raise HTTPException(status_code=400, detail="JSON 배열이어야 합니다.")

    print(f"[*] {file.filename} - findings {len(findings)}개 분석 시작")
    result = run_analysis(findings)
    print(f"[*] 완료: {len(result)}개 반환")

    return JSONResponse(content=result)



@app.get("/health")
def health(api_key: str = Depends(verify_api_key)):
    return {"status": "ok", "model": OLLAMA_MODEL}
