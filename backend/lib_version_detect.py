import zipfile
import re
import json
import struct
from pathlib import Path


# ── 패턴 로드 ─────────────────────────────────────────────────────────────

def _load_patterns(json_path: str | None = None) -> dict:
    path = json_path or (Path(__file__).parent / "lib_patterns.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)

_P = _load_patterns()

KNOWN_MAVEN_COORDS:  dict = _P["known_maven_coords"]
ARTIFACT_OVERRIDES:  dict = {k: tuple(v) for k, v in _P["artifact_overrides"].items()}
GROUP_OVERRIDES:     dict = _P["group_overrides"]
ARTIFACT_RENAME:     dict = _P["artifact_rename"]
UA_LIB_MAP:          dict = _P["ua_lib_map"]
DEX_CLASS_PRESENCE:  list = _P["dex_class_presence"]
METAINF_EXTRA_PATHS: list = [(re.compile(e["pattern"]), e["group"], e["artifact"])
                              for e in _P["metainf_extra_paths"]]
MAVEN_POM_GROUPS:    dict = _P["maven_pom_groups"]
ASSET_VERSION_PATTERNS: list = [re.compile(p) for p in _P["asset_version_patterns"]]
SO_NOISE_KEYWORDS:   set  = set(_P["so_noise_keywords"])
SO_GENERAL_SKIP:     set  = set(_P["so_general_skip"])
SO_KNOWN_LIBS: list = [
    (re.compile(e["so_pattern"]), re.compile(e["ver_pattern"]), e["group"], e["artifact"])
    for e in _P["so_known_libs"]
]

UA_VERSION_RE = re.compile(
    r"^(" + "|".join(re.escape(k) for k in UA_LIB_MAP) + r")/(\d+\.\d+\.\d+(?:[-\.]\w+)?)$"
)


# ── 버전 검증 ──────────────────────────────────────────────────────────────

VERSION_RE = re.compile(r"^\d+\.\d+[\.\d\-a-zA-Z+]*$")

def is_valid_version(v: str) -> bool:
    if not v:
        return False
    if len(v) > 30 or " " in v:
        return False
    return bool(VERSION_RE.match(v))


# ── 파일명 파싱 ────────────────────────────────────────────────────────────

def parse_version_filename(filename: str) -> tuple:
    name = filename.replace(".version", "")
    idx = name.find("_")
    if idx == -1:
        return name, name
    return name[:idx], name[idx+1:]


# ── Maven 좌표 보강 ────────────────────────────────────────────────────────

def resolve_maven_coords(artifact: str, group) -> tuple:
    if group:
        return group, artifact
    coords = KNOWN_MAVEN_COORDS.get(artifact)
    if coords:
        return coords[0], coords[1]
    return None, artifact


def normalize_coords(group: str, artifact: str) -> tuple:
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


# ── properties 파싱 ────────────────────────────────────────────────────────

def parse_properties_file(content: str) -> dict:
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


# ── DEX 문자열 추출 ────────────────────────────────────────────────────────

def extract_dex_strings(data: bytes) -> list[str]:
    if data[:4] != b"dex\n":
        return []
    try:
        string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
        string_ids_off  = struct.unpack_from("<I", data, 0x3C)[0]
        strings = []
        for i in range(min(string_ids_size, 200000)):
            str_off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            length = 0
            shift = 0
            pos = str_off
            while pos < len(data):
                b = data[pos]; pos += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if pos + length > len(data):
                continue
            try:
                strings.append(data[pos:pos+length].decode("utf-8", errors="ignore"))
            except Exception:
                pass
        return strings
    except Exception:
        return []


# ── DEX UA 버전 상수 스캔 ──────────────────────────────────────────────────

def scan_dex_for_versions(strings: list[str]) -> dict:
    found = {}
    for s in strings:
        m = UA_VERSION_RE.match(s)
        if m:
            lib_key, version = m.group(1), m.group(2)
            if lib_key in UA_LIB_MAP:
                group, artifact = UA_LIB_MAP[lib_key]
                pkg_key = f"{group}:{artifact}"
                if pkg_key not in found:
                    found[pkg_key] = (group, artifact, version, f"dex:UA/{s}")
    return found


# ── DEX 클래스 존재 기반 탐지 ─────────────────────────────────────────────

def scan_dex_for_class_presence(strings: list[str]) -> list[dict]:
    string_set = set(strings)
    results = []
    seen_pkg = set()

    for entry in DEX_CLASS_PRESENCE:
        prefix   = entry["prefix"]
        group    = entry["group"]
        artifact = entry["artifact"]
        pkg_key  = f"{group}:{artifact}"
        if pkg_key in seen_pkg:
            continue
        if not any(s.startswith(prefix) for s in string_set):
            continue
        seen_pkg.add(pkg_key)
        results.append({
            "name":           artifact,
            "group":          group,
            "artifact":       artifact,
            "version":        None,
            "version_source": f"dex:class/{prefix.strip('L').rstrip('/')}",
            "type":           "static",
        })

    return results


# ── META-INF 추가 경로 탐지 ───────────────────────────────────────────────

def scan_metainf_extra(z: zipfile.ZipFile, names: list[str]) -> list[dict]:
    results = []

    # 1) 등록된 .version 경로 패턴 매칭
    for n in names:
        for pat, group, artifact in METAINF_EXTRA_PATHS:
            if not pat.search(n):
                continue
            try:
                version = z.read(n).decode("utf-8", errors="ignore").strip()
            except Exception:
                version = None
            results.append({
                "name":           artifact,
                "group":          group,
                "artifact":       artifact,
                "version":        version if is_valid_version(version or "") else None,
                "version_source": n,
                "type":           "static",
            })
            break

    # 2) META-INF/maven/<group>/<artifact>/pom.properties 스캔
    for n in names:
        if not n.startswith("META-INF/maven/") or not n.endswith("pom.properties"):
            continue
        parts = n.split("/")
        if len(parts) < 5:
            continue
        grp, art = parts[2], parts[3]
        if grp not in MAVEN_POM_GROUPS or art not in MAVEN_POM_GROUPS[grp]:
            continue
        try:
            props = parse_properties_file(z.read(n).decode("utf-8", errors="ignore"))
        except Exception:
            continue
        version = props.get("version")
        results.append({
            "name":           art,
            "group":          grp,
            "artifact":       art,
            "version":        version if is_valid_version(version or "") else None,
            "version_source": n,
            "type":           "static",
        })

    return results


# ── kotlin-tooling-metadata.json ──────────────────────────────────────────

def parse_kotlin_tooling_metadata(data: bytes) -> list[dict]:
    results = []
    try:
        meta = json.loads(data.decode("utf-8", errors="ignore"))
        kt_ver = meta.get("kotlinVersion")
        if kt_ver and is_valid_version(kt_ver):
            results.append({
                "name":           "kotlin-stdlib",
                "group":          "org.jetbrains.kotlin",
                "artifact":       "kotlin-stdlib",
                "version":        kt_ver,
                "version_source": "kotlin-tooling-metadata.json",
                "type":           "static",
            })
        for comp in meta.get("buildPlugins", []):
            if "android" in comp.get("plugin", "").lower():
                agp_ver = comp.get("version")
                if agp_ver and is_valid_version(agp_ver):
                    results.append({
                        "name":           "android-gradle-plugin",
                        "group":          "com.android.tools.build",
                        "artifact":       "gradle",
                        "version":        agp_ver,
                        "version_source": "kotlin-tooling-metadata.json",
                        "type":           "build_tool",
                    })
    except Exception:
        pass
    return results


# ── assets/ 설정파일 스캔 ─────────────────────────────────────────────────

def scan_assets_for_versions(z: zipfile.ZipFile, names: list[str]) -> list[dict]:
    results = []
    for n in names:
        if not n.startswith("assets/"):
            continue
        fname = Path(n).name
        if not any(fname.endswith(ext) for ext in [".json", ".properties", ".txt"]):
            continue
        try:
            content = z.read(n).decode("utf-8", errors="ignore")
        except Exception:
            continue
        for pat in ASSET_VERSION_PATTERNS:
            m = pat.search(content)
            if m and is_valid_version(m.group(1)):
                results.append({
                    "name":           fname,
                    "group":          None,
                    "artifact":       fname,
                    "version":        m.group(1),
                    "version_source": n,
                    "type":           "asset_config",
                })
                break
    return results


# ── .so strings 스캔 ──────────────────────────────────────────────────────

def scan_so_strings(z: zipfile.ZipFile, names: list[str]) -> list[dict]:
    results = []
    seen = set()

    # arm64-v8a 우선
    so_files = {}
    for n in names:
        if not (n.startswith("lib/") and n.endswith(".so")):
            continue
        so_name = Path(n).name
        abi = n.split("/")[1]
        if so_name not in so_files or abi == "arm64-v8a":
            so_files[so_name] = n

    for so_name, path in so_files.items():
        try:
            data = z.read(path)
        except Exception:
            continue

        strings = [s.decode("ascii", errors="ignore")
                   for s in re.findall(rb"[ -~]{4,}", data)]

        matched = False
        for so_pat, ver_pat, group, artifact in SO_KNOWN_LIBS:
            if not so_pat.search(so_name):
                continue
            for s in strings:
                m = ver_pat.search(s)
                if m and is_valid_version(m.group(1)):
                    key = f"so_str:{so_name}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "name":           so_name,
                            "group":          group,
                            "artifact":       artifact,
                            "version":        m.group(1),
                            "version_source": f"{path}[strings:{artifact}]",
                            "type":           "native",
                        })
                    matched = True
                    break
            if matched:
                break

        # known 미매칭 → 일반 "XXX version X.Y.Z" 패턴
        so_stem = so_name.replace(".so", "")
        if not matched and so_stem not in SO_GENERAL_SKIP:
            for s in strings:
                m = re.search(r"([\w][\w\-]+)\s+version\s+(\d+\.\d+[\.\d\-\w]*)", s)
                if not m:
                    continue
                lib_hint = m.group(1).lower()
                version  = m.group(2)
                if any(noise in lib_hint for noise in SO_NOISE_KEYWORDS):
                    continue
                try:
                    if int(version.split(".")[0]) >= 10:
                        continue
                except Exception:
                    continue
                if is_valid_version(version):
                    key = f"so_str:{so_name}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "name":           so_name,
                            "group":          None,
                            "artifact":       so_name,
                            "version":        version,
                            "version_source": f"{path}[strings:{m.group(1)}]",
                            "type":           "native",
                        })
                    break

    return results


# ── 메인 탐지 함수 ────────────────────────────────────────────────────────

def detect_libs_from_apk(apk_path: str) -> list[dict]:
    results = []
    seen = set()

    def add(entry: dict):
        key = f"{entry.get('group','_')}/{entry.get('artifact','_')}/{entry.get('version_source','_')}"
        if key in seen:
            return
        seen.add(key)
        results.append(entry)

    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()

        # 1. META-INF/*.version
        for n in names:
            if not n.startswith("META-INF/"):
                continue
            fname = Path(n).name
            if not fname.endswith(".version"):
                continue
            try:
                version = z.read(n).decode("utf-8", errors="ignore").strip()
            except Exception:
                continue
            group, artifact = parse_version_filename(fname)
            add({
                "name":           artifact,
                "group":          group,
                "artifact":       artifact,
                "version":        version if is_valid_version(version) else None,
                "version_source": f"META-INF/{fname}",
                "type":           "static",
            })

        # 2. *.properties
        for n in names:
            if not n.endswith(".properties"):
                continue
            fname = Path(n).name
            lib_name = fname.replace(".properties", "")
            try:
                content = z.read(n).decode("utf-8", errors="ignore")
            except Exception:
                continue
            props = parse_properties_file(content)
            if "token" in props and "version" not in props and "info.release" not in props:
                continue
            version = (props.get("version")
                       or props.get("Version")
                       or props.get("info.release")
                       or props.get("info.version")
                       or props.get("release")
                       or None)
            raw_group    = props.get("groupId") or props.get("group") or None
            group, artifact = resolve_maven_coords(lib_name, raw_group)
            add({
                "name":           lib_name,
                "group":          group,
                "artifact":       artifact,
                "version":        version if is_valid_version(str(version or "")) else None,
                "version_source": n,
                "type":           "static",
            })

        # 3. lib/*.so 파일명
        so_seen = set()
        so_entries = []
        for abi in ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]:
            for n in names:
                if not (n.startswith(f"lib/{abi}/") and n.endswith(".so")):
                    continue
                so_name = Path(n).name
                if so_name in so_seen:
                    continue
                so_seen.add(so_name)
                ver_match = re.search(r"[_v](\d+)[._](\d+)[._](\d+)", so_name)
                version = ".".join(ver_match.groups()) if ver_match else None
                so_entries.append({
                    "name":           so_name,
                    "group":          None,
                    "artifact":       so_name,
                    "version":        version,
                    "version_source": n,
                    "type":           "native",
                })
        for entry in so_entries:
            add(entry)

        # 4. kotlin-tooling-metadata.json
        if "kotlin-tooling-metadata.json" in names:
            try:
                for entry in parse_kotlin_tooling_metadata(z.read("kotlin-tooling-metadata.json")):
                    add(entry)
            except Exception:
                pass

        # 5. assets/ 설정파일
        for entry in scan_assets_for_versions(z, names):
            add(entry)

        # 6. .so strings
        for entry in scan_so_strings(z, names):
            so_name = entry["name"]
            existing = next(
                (r for r in results
                 if r["name"] == so_name and r["type"] == "native" and not r["version"]),
                None
            )
            if existing:
                existing["version"]        = entry["version"]
                existing["group"]          = entry.get("group") or existing["group"]
                existing["artifact"]       = entry.get("artifact") or existing["artifact"]
                existing["version_source"] = entry["version_source"]
            else:
                add(entry)

        # 7. classes.dex UA 버전 상수
        dex_files = [n for n in names if re.match(r"classes\d*\.dex$", n)]
        all_dex_strings = []
        for dex_name in dex_files:
            try:
                all_dex_strings.extend(extract_dex_strings(z.read(dex_name)))
            except Exception:
                pass

        for pkg_key, (group, artifact, version, source) in scan_dex_for_versions(all_dex_strings).items():
            add({
                "name":           artifact,
                "group":          group,
                "artifact":       artifact,
                "version":        version if is_valid_version(version) else None,
                "version_source": source,
                "type":           "static",
            })

        # 7-2. DEX 클래스 존재 기반 탐지
        for entry in scan_dex_for_class_presence(all_dex_strings):
            existing = next(
                (r for r in results
                 if r.get("group") == entry["group"] and r.get("artifact") == entry["artifact"]),
                None
            )
            if existing:
                if not existing["version"] and entry["version"]:
                    existing["version"]        = entry["version"]
                    existing["version_source"] = entry["version_source"]
            else:
                add(entry)

        # 8. META-INF 추가 경로 + Maven pom.properties
        for entry in scan_metainf_extra(z, names):
            existing = next(
                (r for r in results
                 if r.get("group") == entry["group"] and r.get("artifact") == entry["artifact"]),
                None
            )
            if existing:
                if not existing["version"] and entry["version"]:
                    existing["version"]        = entry["version"]
                    existing["version_source"] = entry["version_source"]
            else:
                add(entry)

    return results


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python lib_version_detect.py <apk_path> [output.json]")
        return

    apk_path    = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    libs = detect_libs_from_apk(apk_path)

    with_version    = [l for l in libs if l["version"]]
    without_version = [l for l in libs if not l["version"]]

    print(f"\n총 {len(libs)}개 라이브러리 탐지")
    print(f"  버전 확인:   {len(with_version)}개")
    print(f"  버전 미확인: {len(without_version)}개\n")

    print("=== 버전 확인된 라이브러리 ===")
    for lib in sorted(with_version, key=lambda x: (x["type"], x["name"])):
        tag = f"[{lib['type']}]"
        print(f"  {tag:<14} {lib['name']:<45} {lib['version']:<20} ({lib['version_source']})")

    print("\n=== 버전 미확인 (존재만 탐지) ===")
    for lib in sorted(without_version, key=lambda x: x["name"]):
        print(f"  {lib['name']:<50} ({lib['version_source']})")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(libs, f, ensure_ascii=False, indent=2)
        print(f"\n→ {output_path} 저장 완료")


if __name__ == "__main__":
    main()
