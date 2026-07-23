import asyncio
import json
import math
import os
import random
import sys
from google import genai
from google.genai import types

GEMINI_MODEL = "gemini-2.5-flash"
BATCH_SIZE   = 20  # Gemini는 컨텍스트 크니까 20개씩


async def call_gemini_batch_async(client, batch, batch_num, total_batches, semaphore):
    async with semaphore:
        prompt = f"""You are a mobile application security analyst. Below is a static analysis result of an Android APK.
All findings are from the application's own code (third-party libraries have already been excluded).

For each finding, determine:
Pay attention to the "code" field to determine what is actually being stored or used.

1. is_false_positive - true if this is noise (e.g. error message strings, MIME type constants, internal routing strings, generic e.printStackTrace() with no sensitive data)
2. risk - HIGH / MEDIUM / LOW
3. explanation - one sentence in Korean for non-expert users explaining why this is dangerous
4. fix - one sentence in Korean describing the fix + a single line of secure code example (if applicable)

RULES:
- Output array length MUST equal input array length ({len(batch)} items). Do NOT add or remove items.
- You MUST output exactly {len(batch)} items. Each finding must have its own entry. Do NOT merge, skip, or combine any findings even if they look identical.
- NEVER invent or add findings not present in the input list.
- Each output object MUST include the "_idx" field from the corresponding input finding.
- endpoint_disclosure findings that contain only MIME types, blob:/data: prefixes, or internal framework routing are false positives.
- mobsfscan findings with null file_path and null code are advisory warnings, not confirmed vulnerabilities — set risk=LOW and is_false_positive=false.
- Risk must reflect actual exploitability. Not every finding is HIGH or MEDIUM. Use LOW for findings that are theoretically concerning but difficult to exploit in practice.
- fix field: write a short Korean sentence explaining what to change, followed by a code snippet if helpful. Example: "하드코딩 대신 서버에서 런타임에 수신하세요. 예: `String key = BuildConfig.API_KEY;`"
- fix field for manifest issues: provide the corrected XML attribute. Example: `android:allowBackup=\"false\"`
- fix field for advisory warnings (null code): provide a general recommendation without code.

Respond ONLY with a JSON array. No markdown, no explanation outside the array.
Format:
[{{"_idx": <original _idx>, "is_false_positive": true/false, "risk": "HIGH/MEDIUM/LOW", "explanation": "한국어 위험 설명", "fix": "한국어 수정 방법 + 핵심 코드 예시"}}]

Findings:
{json.dumps(batch, ensure_ascii=False)}"""

        print(f"[배치 {batch_num}/{total_batches}] 요청 중...", flush=True)

        for attempt in range(1, 4):
            try:
                response = await client.aio.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0,
                    ),
                )

                raw = response.text.strip()
                if "```" in raw:
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                raw = raw.strip()

                result = json.loads(raw)

                if len(result) != len(batch):
                    raise ValueError(f"길이 불일치: 입력 {len(batch)}개 vs 출력 {len(result)}개")

                input_idxs = {item["_idx"] for item in batch}
                output_idxs = {item.get("_idx") for item in result}
                if input_idxs != output_idxs:
                    raise ValueError(f"_idx 불일치")

                print(f"[배치 {batch_num}/{total_batches}] 완료 ({len(result)}개)")
                return result

            except Exception as e:
                print(f"[배치 {batch_num}] 오류 (시도 {attempt}/3): {e}")
                if attempt == 3:
                    raise
                await asyncio.sleep(2)


async def ask_gemini_async(findings, apk_name, output_dir, api_key):
    print(f"\n[LLM] Gemini {GEMINI_MODEL}에 분석 요청 중... ({len(findings)}개 findings)")

    client = genai.Client(api_key=api_key)

    indexed = list(enumerate(findings))
    random.shuffle(indexed)
    shuffled_findings = [f for _, f in indexed]

    batches = [
        shuffled_findings[i * BATCH_SIZE:(i + 1) * BATCH_SIZE]
        for i in range(math.ceil(len(shuffled_findings) / BATCH_SIZE))
    ]
    total_batches = len(batches)

    semaphore = asyncio.Semaphore(10)  # Tier 1이니까 10 동시

    tasks = [
        call_gemini_batch_async(client, batch, i + 1, total_batches, semaphore)
        for i, batch in enumerate(batches)
    ]

    idx_to_result = {}
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"[배치 {i+1}] 최종 실패: {result}")
            sys.exit(1)
        for llm_res in result:
            idx_to_result[llm_res["_idx"]] = llm_res

    merged = []
    for finding in findings:
        orig_idx = finding["_idx"]
        llm_res = idx_to_result.get(orig_idx)
        if not llm_res:
            continue
        if llm_res.get("is_false_positive", False):
            continue
        item = dict(finding)
        item.pop("_idx", None)
        item["risk"] = llm_res.get("risk", "LOW")
        item["explanation"] = llm_res.get("explanation", "")
        item["fix"] = llm_res.get("fix", "")
        merged.append(item)

    output_path = os.path.join(output_dir, f"{apk_name}_llm.json")
    with open(output_path, "w") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)

    print(f"[LLM] 완료: {output_path}")
    print(f"[LLM] 오탐 제거 후: {len(findings)}개 → {len(merged)}개")

    high   = [r for r in merged if r.get("risk") == "HIGH"]
    medium = [r for r in merged if r.get("risk") == "MEDIUM"]
    low    = [r for r in merged if r.get("risk") == "LOW"]
    print(f"\n  HIGH: {len(high)}개 / MEDIUM: {len(medium)}개 / LOW: {len(low)}개")

    return merged


def ask_gemini(findings, apk_name, output_dir, api_key):
    return asyncio.run(ask_gemini_async(findings, apk_name, output_dir, api_key))


def main(merge_json, api_key):
    base = os.path.basename(merge_json)
    apk_name = base.replace("_merge.json", "")
    output_dir = os.path.dirname(os.path.abspath(merge_json))

    with open(merge_json) as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        print("[ERROR] 입력 파일이 JSON 배열이 아닙니다.")
        sys.exit(1)

    print(f"[*] {apk_name} - findings {len(findings)}개 분석 시작")
    ask_gemini(findings, apk_name, output_dir, api_key)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 gemini_analyze.py <apk_name>_merge.json <API_KEY>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
