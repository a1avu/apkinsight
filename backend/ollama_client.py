import json
import os
import sys
import requests

SERVER_URL = "https://2171255capstone.iptime.org:8443/analyze"


def main(merge_json, api_key):
    if not os.path.exists(merge_json):
        print(f"[ERROR] 파일 없음: {merge_json}")
        sys.exit(1)

    base    = os.path.basename(merge_json)
    apk_name = base.replace("_merge.json", "")
    output_path = os.path.join(os.path.dirname(merge_json), f"{apk_name}_llm.json")

    print(f"[*] {base} 전송 중...")

    with open(merge_json, "rb") as f:
        response = requests.post(
            SERVER_URL,
            headers={"x-api-key": api_key},
            files={"file": (base, f, "application/json")},
            verify=False,
            timeout=None  # 아니면 넉넉하게 600 이런 식으로
        )

    response.raise_for_status()
    result = response.json()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[*] 저장 완료: {output_path} ({len(result)}개)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 ollama_client.py <apk_name>_merge.json <API_KEY>")
        sys.exit(1)
    main(sys.argv[1],sys.argv[2])
