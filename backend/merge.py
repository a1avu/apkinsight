import json
import os
import sys

MAX_CODE_LENGTH = 300

THIRD_PARTY_PATTERNS = [
    "androidx/", "androidx\\",
    "com/google/", "com\\google\\",
    "kotlin/", "kotlin\\",
    "com/squareup/", "com\\squareup\\",
    "io/reactivex/", "io\\reactivex\\",
    "okhttp3/", "okhttp3\\",
    "retrofit2/", "retrofit2\\",
    "com/facebook/", "com\\facebook\\",
    "io/jsonwebtoken/", "io\\jsonwebtoken\\",
    "org/apache/", "org\\apache\\",
    "com/amazonaws/", "com\\amazonaws\\",
]

def is_third_party(file_path):
    if not file_path:
        return False
    for pattern in THIRD_PARTY_PATTERNS:
        if pattern in file_path:
            return True
    return False

def trim_code(code, max_len=MAX_CODE_LENGTH):
    if not code:
        return ""
    code = code.strip()
    if len(code) > max_len:
        return code[:max_len] + "...(truncated)"
    return code

# ============================================================
# mobsfscan severity 매핑
# 기본: ERROR → HIGH, WARNING → MEDIUM, INFO → LOW
# 예외: certificate_pinning / root_detection → INFO이나 실질 위험이 높아 MEDIUM 상향
# ============================================================
MOBSFSCAN_SEVERITY_OVERRIDE = {
    "android_certificate_pinning":      "MEDIUM",
    "android_ssl_pinning":              "MEDIUM",
    "android_root_detection":           "MEDIUM",
}

MOBSFSCAN_SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}

def mobsfscan_severity(category: str, raw_severity: str) -> str:
    """
    mobsfscan 원본 severity(ERROR/WARNING/INFO)를
    APKInsight 기준(HIGH/MEDIUM/LOW)으로 변환한다.
    일부 INFO 항목은 실질 위험을 고려해 MEDIUM으로 상향한다.
    """
    if category in MOBSFSCAN_SEVERITY_OVERRIDE:
        return MOBSFSCAN_SEVERITY_OVERRIDE[category]
    return MOBSFSCAN_SEVERITY_MAP.get(raw_severity.upper(), "LOW")


def parse_mobsfscan(mobsfscan_json_path):
    with open(mobsfscan_json_path) as f:
        data = json.load(f)
    results = []
    for cat, val in data.get("results", {}).items():
        metadata = val.get("metadata", {})
        cwe = metadata.get("cwe", "")
        owasp = metadata.get("owasp-mobile", "")
        raw_sev = metadata.get("severity", "INFO")
        severity = mobsfscan_severity(cat, raw_sev)
        files = val.get("files", [])
        if not files:
            results.append({
                "source": "mobsfscan",
                "category": cat,
                "cwe": cwe,
                "owasp": owasp,
                "severity": severity,
                "file_path": None,
                "line": None,
                "code": None,
                "is_third_party": False,
            })
        else:
            for f in files:
                file_path = f.get("file_path", "")
                match_lines = f.get("match_lines", [])
                line = str(match_lines[0]) if match_lines else None
                results.append({
                    "source": "mobsfscan",
                    "category": cat,
                    "cwe": cwe,
                    "owasp": owasp,
                    "severity": severity,
                    "file_path": file_path,
                    "line": line,
                    "code": trim_code(f.get("match_string", "")),
                    "is_third_party": is_third_party(file_path),
                })
    return results

def parse_custom(custom_json_path):
    with open(custom_json_path) as f:
        data = json.load(f)
    results = []
    for item in data.get("findings", []):
        results.append({
            "source": "custom_grep",
            "category": item.get("category", ""),
            "cwe": item.get("cwe", ""),
            "owasp": item.get("owasp", ""),
            "severity": item.get("severity", ""),
            "file_path": item.get("file_path", ""),
            "line": str(item.get("line", "")),
            "code": trim_code(item.get("code", "")),
            "is_third_party": item.get("is_third_party", False),
        })
    return results

def dedup_key(item):
    """중복 판단 키: category + file_path + line"""
    return (
        item.get("category", ""),
        item.get("file_path") or "",
        str(item.get("line") or ""),
    )

def deduplicate(mobsfscan, custom_grep):
    """
    mobsfscan 우선. custom_grep에서 mobsfscan이 이미 잡은 항목 제거.
    """
    mobsf_keys = set(dedup_key(r) for r in mobsfscan)
    deduped_custom = [r for r in custom_grep if dedup_key(r) not in mobsf_keys]
    removed = len(custom_grep) - len(deduped_custom)
    if removed:
        print(f"  [dedup] custom_grep 중복 {removed}개 제거")
    return deduped_custom

def main(mobsfscan_json, custom_json=None): #이곳에서 써드파티와 아닌 것을 구분할 것입니다.
    base = os.path.basename(mobsfscan_json)
    apk_name = base.replace("_mobsfscan.json", "")
    output_dir = os.path.dirname(os.path.abspath(mobsfscan_json))
    output_path = os.path.join(output_dir, f"{apk_name}_final.json")


    mobsf_results = parse_mobsfscan(mobsfscan_json)
    custom_results = parse_custom(custom_json) if custom_json and os.path.exists(custom_json) else []

    # 중복 제거 (mobsfscan 우선)
    if custom_results:
        custom_results = deduplicate(mobsf_results, custom_results)


    # [여기서부터 추가]
    # 이미 만들어진 'final' 변수에서 바로 분류를 수행
    all_findings = mobsf_results + custom_results
    
    custom_only = [item for item in all_findings if not item.get("is_third_party", False)]
    third_party_only = [item for item in all_findings if item.get("is_third_party", False)]
    
    # 기존 output_path를 재활용하여 파일 이름만 살짝 변경
    # 03.24)) merge.py 출력 결과물 이름 변경
    custom_path = output_path.replace("_final.json", "_merge.json") #직접 작성했으니 custom
    tp_path = output_path.replace("_final.json", "_final_third_party.json") #써드파티는 그대로 써드파티 적
    #[여기까지 추가]

    # llm들 버그 잡기 위한 노력 1    
    for i, item in enumerate(custom_only):
        item["_idx"] = i

    for i, item in enumerate(third_party_only):
        item["_idx"] = i

    with open(custom_path, "w") as f:
        json.dump(custom_only, f, indent=2, ensure_ascii=False)
    
    with open(tp_path, "w") as f:
        json.dump(third_party_only, f, indent=2, ensure_ascii=False)

    print(f"완료: {output_path}")
    print(f"  mobsfscan: {len(mobsf_results)}개")
    print(f"  custom_grep: {len(custom_results)}개")
    print(f"  total: {len(mobsf_results) + len(custom_results)}개")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 merge.py <apk_name>_mobsfscan.json <apk_name>_custom.json")
        sys.exit(1)
    custom = sys.argv[3] if len(sys.argv) > 3 else None
    main(sys.argv[1], sys.argv[2])