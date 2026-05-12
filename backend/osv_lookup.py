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
    """영문 텍스트를 한국어로 번역. 실패 시 원문 반환."""
    if not text or not _translator_available:
        return text
    try:
        return GoogleTranslator(source="en", target="ko").translate(text[:500])
    except Exception:
        return text


OSV_API = "https://api.osv.dev/v1/query"


def query_osv(package: str, version: str, ecosystem: str = "Maven") -> list[dict]:
    payload = json.dumps({
        "version": version,
        "package": {
            "name": package,
            "ecosystem": ecosystem
        }
    }).encode()

    req = urllib.request.Request(
        OSV_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("vulns", [])
    except urllib.error.HTTPError as e:
        print(f"  [HTTP {e.code}] {package}@{version}")
        return []
    except Exception as e:
        print(f"  [ERR] {package}@{version}: {e}")
        return []


def query_osv_no_version(package: str, ecosystem: str = "Maven") -> list[dict]:
    """버전 없이 패키지 전체 CVE 조회 — 버전 미확인 라이브러리용"""
    payload = json.dumps({
        "package": {
            "name": package,
            "ecosystem": ecosystem
        }
    }).encode()

    req = urllib.request.Request(
        OSV_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("vulns", [])
    except Exception:
        return []


def run_osv_scan_unknown(libs: list[dict], delay: float = 0.3) -> list[dict]:
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

    print(f"\n버전 미확인 라이브러리 {len(candidates)}개 CVE 경고 조회 중...\n")

    for i, lib in enumerate(candidates, 1):
        group = lib.get("group") or ""
        artifact = lib.get("artifact") or lib.get("name") or ""
        group, artifact = normalize_coords(group, artifact)
        pkg_name = make_package_name(group, artifact)

        print(f"[{i}/{len(candidates)}] {pkg_name} (버전미확인)", end=" ... ", flush=True)

        vulns = query_osv_no_version(pkg_name)

        if vulns:
            print(f"⚠️  {len(vulns)}개 CVE 존재!")
            affected_versions = []
            for v in vulns:
                for aff in v.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for evt in rng.get("events", []):
                            if "fixed" in evt:
                                affected_versions.append(evt["fixed"])
            latest_fix = max(affected_versions) if affected_versions else "불명"

            # 대표 summary 번역 (최대 3개)
            summaries_ko = [
                translate_ko(v.get("summary", ""))
                for v in vulns[:3] if v.get("summary")
            ]

            warnings.append({
                "library":      pkg_name,
                "version":      "UNKNOWN",
                "warning":      f"버전 미확인 — 패키지에 {len(vulns)}개 CVE 존재 (최신 fix: {latest_fix})",
                "vuln_count":   len(vulns),
                "latest_fix":   latest_fix,
                "vuln_ids":     [v.get("id") for v in vulns],
                "summaries_ko": summaries_ko,
                "source":       lib.get("version_source", ""),
            })
        else:
            print("CVE 없음")

        time.sleep(delay)

    return warnings


# artifact → 올바른 (group, artifact) 강제 재매핑
# lib_version_detect가 잘못된 group을 내보내는 경우 보정
ARTIFACT_OVERRIDES: dict[str, tuple[str, str]] = {
    # kotlinx coroutines: detect가 "kotlinx" group으로 내보내는 경우
    "coroutines_android":  ("org.jetbrains.kotlinx", "kotlinx-coroutines-android"),
    "coroutines_core":     ("org.jetbrains.kotlinx", "kotlinx-coroutines-core"),
    "coroutines-android":  ("org.jetbrains.kotlinx", "kotlinx-coroutines-android"),
    "coroutines-core":     ("org.jetbrains.kotlinx", "kotlinx-coroutines-core"),
    # room-ktx는 group이 빠질 수 있음
    "room-ktx":            ("androidx.room",          "room-ktx"),
    "room-runtime":        ("androidx.room",          "room-runtime"),
    # versionedparcelable typo 보정 (androidxedparcelable)
    "versionedparcelable": ("androidx.versionedparcelable", "versionedparcelable"),
}

GROUP_OVERRIDES: dict[str, str] = {
    # kotlinx → org.jetbrains.kotlinx
    "kotlinx": "org.jetbrains.kotlinx",
    # androidxedparcelable typo
    "androidxedparcelable": "androidx.versionedparcelable",
}

ARTIFACT_RENAME: dict[str, str] = {
    # kotlinx META-INF 파일명 → Maven artifact명 (_를 - 로, kotlinx- 접두어 추가)
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
    """group/artifact 정규화 (알려진 오류 보정)"""
    # artifact 레벨 강제 재매핑
    if artifact in ARTIFACT_OVERRIDES:
        return ARTIFACT_OVERRIDES[artifact]
    # group 보정
    if group in GROUP_OVERRIDES:
        group = GROUP_OVERRIDES[group]
    # artifact 이름 보정
    if artifact in ARTIFACT_RENAME:
        artifact = ARTIFACT_RENAME[artifact]
    return group, artifact



def make_package_name(group: str, artifact: str) -> str:
    """group + artifact → Maven 패키지명"""
    if group and artifact and group != artifact:
        return f"{group}:{artifact}"
    return artifact


def run_osv_scan(libs: list[dict], delay: float = 0.2) -> list[dict]:
    findings = []
    total = len([l for l in libs if l.get("version")])
    idx = 0

    for lib in libs:
        version = lib.get("version")
        if not version:
            continue

        idx += 1
        group = lib.get("group") or ""
        artifact = lib.get("artifact") or lib.get("name") or ""

        # group 없으면 Maven 조회 의미 없음 → 스킵
        if not group:
            print(f"[{idx}/{total}] {artifact}@{version} ... SKIP (group 없음)")
            continue

        # 알려진 좌표 오류 보정
        group, artifact = normalize_coords(group, artifact)

        pkg_name = make_package_name(group, artifact)

        print(f"[{idx}/{total}] {pkg_name}@{version}", end=" ... ", flush=True)

        vulns = query_osv(pkg_name, version)

        if vulns:
            print(f"⚠️  {len(vulns)}개 취약점!")
            for v in vulns:
                summary = v.get("summary", "")
                findings.append({
                    "library":    pkg_name,
                    "version":    version,
                    "vuln_id":    v.get("id"),
                    "summary":    summary,
                    "summary_ko": translate_ko(summary),
                    "severity":   extract_severity(v),
                    "aliases":    v.get("aliases", []),
                    "source":     lib.get("version_source", ""),
                })
        else:
            print("OK")

        time.sleep(delay)

    return findings

def extract_severity(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if score.startswith("CVSS:3"):
            try:
                from cvss import CVSS3
                c = CVSS3(score)
                severity = c.severities()[0]  # "Critical", "High", "Medium", "Low", "None"
                # Critical → High로 통합
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


def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python osv_lookup.py <lib_version_detect_output.json>")
        print("       (lib_version_detect.py 결과 json 파일 필요)")
        return

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "osv_findings.json"

    with open(input_path, encoding="utf-8") as f:
        libs = json.load(f)

    print(f"총 {len(libs)}개 라이브러리 중 버전 확인된 것만 OSV 조회\n")

    findings = run_osv_scan(libs)

    # 버전 미확인 라이브러리 CVE 경고 조회
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
            print()
    else:
        print("취약점 없음 (또는 OSV DB에 등록된 취약점 없음)")

    if warnings:
        print(f"\n{'='*60}")
        print(f"🔍 버전 미확인 경고: {len(warnings)}건\n")
        for w in warnings:
            print(f"  {w['library']} (버전 불명)")
            print(f"    CVE {w['vuln_count']}개 존재 | 최신 fix: {w['latest_fix']}")
            print(f"    관련 ID: {', '.join(w['vuln_ids'][:3])}{'...' if len(w['vuln_ids']) > 3 else ''}")
            print()

    result = {"findings": findings, "warnings": warnings}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"→ {output_path} 저장 완료")


if __name__ == "__main__":
    main()