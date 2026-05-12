import os
import re
import sys
import json
from collections import Counter

from manifest_analyzer import find_manifest, analyze_manifest

# ============================================================
# 패턴 로드  (patterns.json → 런타임에 읽기)
# ============================================================

def load_patterns(patterns_path: str = None) -> dict:
    """
    patterns.json을 로드한다.
    경로를 지정하지 않으면 이 스크립트와 같은 디렉터리에서 찾는다.
    """
    if patterns_path is None:
        patterns_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns.json")
    with open(patterns_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# 파일 필터
# ============================================================

THIRD_PARTY_PATTERNS = [
    "androidx/", "androidx\\",
    "com/google/", "com\\google\\",
    "kotlin/", "kotlin\\",
    "kotlinx/", "kotlinx\\",
    "com/squareup/", "com\\squareup\\",
    "io/reactivex/", "io\\reactivex\\",
    "okhttp3/", "okhttp3\\",
    "okio/", "okio\\",
    "retrofit2/", "retrofit2\\",
    "com/facebook/", "com\\facebook\\",
    "io/jsonwebtoken/", "io\\jsonwebtoken\\",
    "org/apache/", "org\\apache\\",
    "com/amazonaws/", "com\\amazonaws\\",
    "io/grpc/", "io\\grpc\\",
    "com/jakewharton/", "com\\jakewharton\\",
    "com/bumptech/", "com\\bumptech\\",
    "com/airbnb/", "com\\airbnb\\",
    "io/coil/", "io\\coil\\",
    "com/github/", "com\\github\\",
    "org/jetbrains/", "org\\jetbrains\\",
    "com/nhn/", "com\\nhn\\",            # Naver SDK
    "com/kakao/sdk/", "com\\kakao\\sdk\\",
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".mp3", ".mp4", ".ttf", ".otf", ".woff",
    ".class", ".dex", ".so", ".jar",
    ".zip", ".aar", ".proto", ".bin",
}


def is_third_party(file_path: str) -> bool:
    return any(p in file_path for p in THIRD_PARTY_PATTERNS)


def should_skip(file_path: str) -> bool:
    return os.path.splitext(file_path)[1].lower() in SKIP_EXTENSIONS


# ============================================================
# 소스코드 스캔
# ============================================================

def scan_file(file_path: str, patterns: dict) -> list:
    findings = []
    if should_skip(file_path):
        return findings
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for category, meta in patterns.items():
        cwe      = meta.get("cwe", "")
        owasp    = meta.get("owasp", "")
        severity = meta.get("severity", "MEDIUM")
        for pattern in meta.get("patterns", []):
            compiled = re.compile(pattern)
            for i, line in enumerate(lines):
                if compiled.search(line):
                    findings.append({
                        "source": "custom_grep",
                        "category": category,
                        "cwe": cwe,
                        "owasp": owasp,
                        "severity": severity,
                        "file_path": file_path,
                        "line": i + 1,
                        "code": line.strip()[:300],
                        "is_third_party": is_third_party(file_path),
                    })
    return findings


def scan_directory(source_dir: str, patterns: dict) -> list:
    all_findings = []
    for root, dirs, files in os.walk(source_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            all_findings.extend(scan_file(fpath, patterns))
    return all_findings


def find_res_values_dir(source_dir: str) -> str | None:
    """
    source_dir 기준으로 상위를 거슬러 올라가며 res/values/ 디렉터리를 찾는다.
    jadx 출력 구조: jadx_out/resources/res/values/
    """
    curr_dir = os.path.abspath(source_dir)
    while True:
        candidate = os.path.join(curr_dir, "resources", "res", "values")
        if os.path.isdir(candidate):
            return candidate
        candidate = os.path.join(curr_dir, "res", "values")
        if os.path.isdir(candidate):
            return candidate
        parent_dir = os.path.dirname(curr_dir)
        if parent_dir == curr_dir:
            break
        curr_dir = parent_dir
    return None


# ============================================================
# 엔트리포인트
# ============================================================

def main(source_dir: str, output_path: str, patterns_path: str = None):
    """
    지정된 소스 디렉터리를 스캔하여 패턴과 매니페스트 취약점을 찾아 JSON으로 저장합니다.

    :param source_dir: 디컴파일된 애플리케이션의 소스 코드 디렉터리. 패키지 기반으로 깊은
                       위치에 있을 수 있으므로, 매니페스트는 상위 디렉터리로 올라가며 탐색합니다.
    :param output_path: 결과를 저장할 JSON 파일 경로
    :param patterns_path: patterns.json 경로 (None이면 스크립트와 같은 디렉터리에서 탐색)
    """
    print(f"[custom_grep] 패턴 로드 중...")
    patterns = load_patterns(patterns_path)
    print(f"[custom_grep] {len(patterns)}개 카테고리 로드 완료")

    # 1. 소스 코드 전체를 스캔하여 패턴을 탐지합니다.
    print(f"[custom_grep] 소스코드 스캔 중: {source_dir}")
    findings = scan_directory(source_dir, patterns)

    # 2. res/values/ 디렉터리를 찾아 추가 스캔합니다 (strings.xml 등).
    res_values_dir = find_res_values_dir(source_dir)
    if res_values_dir:
        print(f"[custom_grep] res/values/ 스캔 중: {res_values_dir}")
        res_findings = scan_directory(res_values_dir, patterns)
        findings.extend(res_findings)
        print(f"[custom_grep] res/values/: {len(res_findings)}개 발견")
    else:
        print("[custom_grep] res/values/ 찾을 수 없음")

    # 3. 매니페스트 파일을 찾기 위해 현재 디렉터리부터 상위로 검색합니다.
    manifest_path = find_manifest(source_dir)
    if manifest_path:
        print(f"[custom_grep] 매니페스트 분석 중: {manifest_path}")
        # 매니페스트에서 발견된 취약점을 existing findings에 추가합니다.
        manifest_findings = analyze_manifest(manifest_path)
        findings.extend(manifest_findings)
        print(f"[custom_grep] 매니페스트: {len(manifest_findings)}개 발견")
    else:
        print("[custom_grep] AndroidManifest.xml 찾을 수 없음")

    # 4. 카테고리별 탐지 결과 개수 출력
    cats = Counter(f["category"] for f in findings)
    print(f"[custom_grep] 총 {len(findings)}개 발견")
    for cat, cnt in cats.most_common():
        print(f"  {cat}: {cnt}개")

    # 5. JSON 결과 저장
    result = {
        "source_dir": source_dir,
        "total": len(findings),
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[custom_grep] 저장: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 grep_custom.py <source_dir> <output.json> [patterns.json]")
        sys.exit(1)
    patterns_path = sys.argv[3] if len(sys.argv) >= 4 else None
    main(sys.argv[1], sys.argv[2], patterns_path)