import json
import time
import urllib.request
import urllib.error
from pathlib import Path

try:
    from deep_translator import GoogleTranslator
    _translator_available = True
except ImportError:
    _translator_available = False


def translate_ko(text: str) -> str:
    if not text or not _translator_available:
        return text
    try:
        return GoogleTranslator(source="en", target="ko").translate(text[:500])
    except Exception:
        return text


OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 50


def query_osv_batch(queries: list[dict]) -> list[list[dict]]:
    """여러 패키지를 한 번에 조회. queries 순서대로 결과 리스트 반환."""
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return [r.get("vulns", []) for r in data.get("results", [])]
    except urllib.error.HTTPError as e:
        print(f"  [HTTP {e.code}] querybatch 실패")
        return [[] for _ in queries]
    except Exception as e:
        print(f"  [ERR] querybatch: {e}")
        return [[] for _ in queries]


def fetch_vuln_detail(vuln_id: str) -> dict:
    """단일 vuln ID로 상세 정보(summary, affected) 조회."""
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    req = urllib.request.Request(url, headers={"Content-Type": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def extract_fixed_version(vuln: dict) -> str:
    """vuln 상세 응답에서 fixed 버전 추출."""
    versions = []
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    versions.append(evt["fixed"])
    return max(versions) if versions else ""


# artifact → 올바른 (group, artifact) 강제 재매핑
ARTIFACT_OVERRIDES: dict[str, tuple[str, str]] = {
    "coroutines_android":  ("org.jetbrains.kotlinx", "kotlinx-coroutines-android"),
    "coroutines_core":     ("org.jetbrains.kotlinx", "kotlinx-coroutines-core"),
    "coroutines-android":  ("org.jetbrains.kotlinx", "kotlinx-coroutines-android"),
    "coroutines-core":     ("org.jetbrains.kotlinx", "kotlinx-coroutines-core"),
    "room-ktx":            ("androidx.room",          "room-ktx"),
    "room-runtime":        ("androidx.room",          "room-runtime"),
    "versionedparcelable": ("androidx.versionedparcelable", "versionedparcelable"),
}

GROUP_OVERRIDES: dict[str, str] = {
    "kotlinx": "org.jetbrains.kotlinx",
    "androidxedparcelable": "androidx.versionedparcelable",
}

ARTIFACT_RENAME: dict[str, str] = {
    "coroutines_android":      "kotlinx-coroutines-android",
    "coroutines_core":         "kotlinx-coroutines-core",
    "coroutines_play_services":"kotlinx-coroutines-play-services",
    "coroutines_reactive":     "kotlinx-coroutines-reactive",
    "coroutines_rx2":          "kotlinx-coroutines-rx2",
    "coroutines_rx3":          "kotlinx-coroutines-rx3",
    "coroutines_test":         "kotlinx-coroutines-test",
    "coroutines_debug":        "kotlinx-coroutines-debug",
    "coroutines_slf4j":        "kotlinx-coroutines-slf4j",
    "serialization_core":      "kotlinx-serialization-core",
    "serialization_json":      "kotlinx-serialization-json",
    "serialization_json_okio": "kotlinx-serialization-json-okio",
    "serialization_protobuf":  "kotlinx-serialization-protobuf",
    "serialization_cbor":      "kotlinx-serialization-cbor",
}


def normalize_coords(group: str, artifact: str) -> tuple[str, str]:
    if artifact in ARTIFACT_OVERRIDES:
        return ARTIFACT_OVERRIDES[artifact]
    if group in GROUP_OVERRIDES:
        group = GROUP_OVERRIDES[group]
    if artifact in ARTIFACT_RENAME:
        artifact = ARTIFACT_RENAME[artifact]
    return group, artifact


def make_package_name(group: str, artifact: str) -> str:
    if group and artifact and group != artifact:
        return f"{group}:{artifact}"
    return artifact


def extract_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if score.startswith("CVSS:3"):
            try:
                from cvss import CVSS3
                c = CVSS3(score)
                severity = c.severities()[0]
                if severity in ("Critical", "High"):
                    return "High"
                elif severity == "Medium":
                    return "Medium"
                elif severity in ("Low", "None"):
                    return "Low"
            except Exception:
                pass
    db = vuln.get("database_specific", {})
    return db.get("severity", "Unknown")


def run_osv_scan(libs: list[dict], delay: float = 0.0) -> list[dict]:
    valid = []
    for lib in libs:
        version = lib.get("version")
        if not version:
            continue
        group = lib.get("group") or ""
        artifact = lib.get("artifact") or lib.get("name") or ""
        if not group:
            print(f"  SKIP {artifact}@{version} (group 없음)")
            continue
        group, artifact = normalize_coords(group, artifact)
        pkg_name = make_package_name(group, artifact)
        valid.append((lib, pkg_name, version))

    total = len(valid)
    findings = []

    for batch_start in range(0, total, OSV_BATCH_SIZE):
        batch = valid[batch_start:batch_start + OSV_BATCH_SIZE]
        queries = [
            {"version": ver, "package": {"name": pkg, "ecosystem": "Maven"}}
            for _, pkg, ver in batch
        ]
        end_idx = min(batch_start + OSV_BATCH_SIZE, total)
        print(f"[OSV 배치 {batch_start+1}~{end_idx}/{total}] 조회 중...", flush=True)

        results = query_osv_batch(queries)

        for (lib, pkg_name, version), vulns in zip(batch, results):
            if vulns:
                print(f"  ⚠️  {pkg_name}@{version} — {len(vulns)}개 취약점 (상세 조회 중...)")
                for v in vulns:
                    vuln_id = v.get("id")
                    detail = fetch_vuln_detail(vuln_id) if vuln_id else {}
                    summary = detail.get("summary") or v.get("summary", "")
                    fixed_version = extract_fixed_version(detail) or extract_fixed_version(v)
                    findings.append({
                        "library":       pkg_name,
                        "version":       version,
                        "vuln_id":       vuln_id,
                        "summary":       summary,
                        "summary_ko":    translate_ko(summary),
                        "severity":      extract_severity(detail or v),
                        "aliases":       detail.get("aliases") or v.get("aliases", []),
                        "fixed_version": fixed_version,
                        "source":        lib.get("version_source", ""),
                    })

    return findings


def run_osv_scan_unknown(libs: list[dict], delay: float = 0.0) -> list[dict]:
    """버전 미확인 라이브러리 대상 패키지 전체 CVE 경고 조회"""
    warnings = []
    candidates = [
        l for l in libs
        if not l.get("version")
        and l.get("group")
        and l.get("version_source", "").startswith("dex:class")
    ]

    if not candidates:
        return []

    print(f"\n버전 미확인 라이브러리 {len(candidates)}개 CVE 경고 배치 조회 중...\n")

    for batch_start in range(0, len(candidates), OSV_BATCH_SIZE):
        batch = candidates[batch_start:batch_start + OSV_BATCH_SIZE]
        pkg_infos = []
        for lib in batch:
            group = lib.get("group") or ""
            artifact = lib.get("artifact") or lib.get("name") or ""
            group, artifact = normalize_coords(group, artifact)
            pkg_name = make_package_name(group, artifact)
            pkg_infos.append((lib, pkg_name))

        queries = [
            {"package": {"name": pkg, "ecosystem": "Maven"}}
            for _, pkg in pkg_infos
        ]
        end_idx = min(batch_start + OSV_BATCH_SIZE, len(candidates))
        print(f"[OSV unknown 배치 {batch_start+1}~{end_idx}/{len(candidates)}] 조회 중...", flush=True)

        results = query_osv_batch(queries)

        for (lib, pkg_name), vulns in zip(pkg_infos, results):
            if vulns:
                print(f"  ⚠️  {pkg_name} (버전미확인) — {len(vulns)}개 CVE (상위 3개 상세 조회 중...)")

                # 상위 3개 vuln ID만 상세 조회
                top_ids = [v.get("id") for v in vulns[:3] if v.get("id")]
                details = [fetch_vuln_detail(vid) for vid in top_ids]

                # fixed_version: 전체 vulns에서 추출 (배치 응답에 있을 수도 있음)
                # 없으면 상세 조회한 것에서 추출
                fixed_version = ""
                for d in details:
                    fv = extract_fixed_version(d)
                    if fv:
                        fixed_version = fv
                        break
                if not fixed_version:
                    for v in vulns:
                        fv = extract_fixed_version(v)
                        if fv:
                            fixed_version = fv
                            break

                summaries_ko = []
                for d in details:
                    s = d.get("summary", "")
                    if s:
                        summaries_ko.append(translate_ko(s))

                warnings.append({
                    "library":       pkg_name,
                    "version":       "UNKNOWN",
                    "warning":       f"버전 미확인 — 패키지에 {len(vulns)}개 CVE 존재",
                    "vuln_count":    len(vulns),
                    "fixed_version": fixed_version or "불명",
                    "vuln_ids":      [v.get("id") for v in vulns],
                    "summaries_ko":  summaries_ko,
                    "source":        lib.get("version_source", ""),
                })

    return warnings


def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python osv_lookup.py <lib_version_detect_output.json>")
        return

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "osv_findings.json"

    with open(input_path, encoding="utf-8") as f:
        libs = json.load(f)

    print(f"총 {len(libs)}개 라이브러리 중 버전 확인된 것만 OSV 조회\n")

    findings = run_osv_scan(libs)
    warnings = run_osv_scan_unknown(libs)

    print(f"\n{'='*60}")
    if findings:
        print(f"⚠️  취약점 발견: {len(findings)}건\n")
        for f in findings:
            cves = [a for a in f["aliases"] if a.startswith("CVE-")]
            cve_str = ", ".join(cves) if cves else "CVE 없음"
            print(f"  [{f['vuln_id']}] {f['library']}@{f['version']}")
            print(f"    CVE: {cve_str}")
            print(f"    요약: {f['summary'][:80]}")
            print(f"    심각도: {f['severity']}")
            print(f"    수정 버전: {f.get('fixed_version') or '-'}")
            print()
    else:
        print("취약점 없음 (또는 OSV DB에 등록된 취약점 없음)")

    if warnings:
        print(f"\n{'='*60}")
        print(f"🔍 버전 미확인 경고: {len(warnings)}건\n")
        for w in warnings:
            print(f"  {w['library']} (버전 불명)")
            print(f"    CVE {w['vuln_count']}개 존재 | 최신 fix: {w['fixed_version']}")
            print(f"    관련 ID: {', '.join(w['vuln_ids'][:3])}{'...' if len(w['vuln_ids']) > 3 else ''}")
            print()

    result = {"findings": findings, "warnings": warnings}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"→ {output_path} 저장 완료")


if __name__ == "__main__":
    main()