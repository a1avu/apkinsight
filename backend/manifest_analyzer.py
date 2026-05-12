import os
import sys
import json
import xml.etree.ElementTree as ET

# ============================================================
# 매니페스트 분석
# ============================================================

# 위험 권한 severity 기준:
# - 권한 선언 자체는 앱 기능상 정상일 수 있으므로 전체적으로 한 단계 낮춤
# - 기존 HIGH → MEDIUM: 민감 데이터 직접 접근 (연락처, SMS, 위치, 통화 등)
# - 기존 MEDIUM → LOW: 일반적인 하드웨어/상태 접근
# - 시스템 수준 권한 (INSTALL_PACKAGES, WRITE_SETTINGS 등) → MEDIUM 유지 (앱에서 거의 안 씀)
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":              ("연락처 읽기",             "MEDIUM"),
    "android.permission.WRITE_CONTACTS":             ("연락처 쓰기",             "MEDIUM"),
    "android.permission.READ_SMS":                   ("SMS 읽기",               "MEDIUM"),
    "android.permission.SEND_SMS":                   ("SMS 전송",               "MEDIUM"),
    "android.permission.RECEIVE_SMS":                ("SMS 수신",               "MEDIUM"),
    "android.permission.READ_MMS":                   ("MMS 읽기",               "MEDIUM"),
    "android.permission.RECEIVE_MMS":                ("MMS 수신",               "MEDIUM"),
    "android.permission.READ_CALL_LOG":              ("통화기록 읽기",            "MEDIUM"),
    "android.permission.WRITE_CALL_LOG":             ("통화기록 쓰기",            "MEDIUM"),
    "android.permission.PROCESS_OUTGOING_CALLS":     ("발신통화 처리",            "MEDIUM"),
    "android.permission.RECORD_AUDIO":               ("마이크 녹음",             "MEDIUM"),
    "android.permission.CAMERA":                     ("카메라 접근",             "LOW"),
    "android.permission.ACCESS_FINE_LOCATION":       ("정밀 위치",              "MEDIUM"),
    "android.permission.ACCESS_COARSE_LOCATION":     ("대략적 위치",             "LOW"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("백그라운드 위치",          "MEDIUM"),
    "android.permission.READ_EXTERNAL_STORAGE":      ("외부저장소 읽기",          "LOW"),
    "android.permission.WRITE_EXTERNAL_STORAGE":     ("외부저장소 쓰기",          "LOW"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":    ("외부저장소 관리",          "MEDIUM"),
    "android.permission.USE_BIOMETRIC":              ("생체인증",               "LOW"),
    "android.permission.USE_FINGERPRINT":            ("지문인증",               "LOW"),
    "android.permission.GET_ACCOUNTS":               ("계정목록 접근",           "LOW"),
    "android.permission.MANAGE_ACCOUNTS":            ("계정 관리",              "MEDIUM"),
    "android.permission.READ_PHONE_STATE":           ("전화상태 읽기",           "LOW"),
    "android.permission.READ_PHONE_NUMBERS":         ("전화번호 읽기",           "MEDIUM"),
    "android.permission.CALL_PHONE":                 ("전화 걸기",              "MEDIUM"),
    "android.permission.ANSWER_PHONE_CALLS":         ("전화 수신",              "MEDIUM"),
    "android.permission.ADD_VOICEMAIL":              ("음성메일 추가",           "LOW"),
    "android.permission.BIND_DEVICE_ADMIN":          ("기기 관리자",             "MEDIUM"),
    "android.permission.REQUEST_INSTALL_PACKAGES":   ("패키지 설치",             "MEDIUM"),
    "android.permission.SYSTEM_ALERT_WINDOW":        ("다른앱 위에 표시",         "MEDIUM"),
    "android.permission.CHANGE_NETWORK_STATE":       ("네트워크 상태 변경",        "LOW"),
    "android.permission.BLUETOOTH_ADMIN":            ("블루투스 관리",            "LOW"),
    "android.permission.CHANGE_WIFI_STATE":          ("WiFi 상태 변경",          "LOW"),
    "android.permission.ACCESS_WIFI_STATE":          ("WiFi 상태 읽기",          "LOW"),
    "android.permission.NFC":                        ("NFC 접근",               "LOW"),
    "android.permission.RECEIVE_BOOT_COMPLETED":     ("부팅완료 수신",            "LOW"),
    "android.permission.FOREGROUND_SERVICE":         ("포그라운드 서비스",         "LOW"),
    "android.permission.KILL_BACKGROUND_PROCESSES":  ("백그라운드 프로세스 종료",   "LOW"),
    "android.permission.READ_LOGS":                  ("시스템 로그 읽기",          "MEDIUM"),
    "android.permission.PACKAGE_USAGE_STATS":        ("앱 사용통계 접근",          "MEDIUM"),
    "android.permission.WRITE_SETTINGS":             ("시스템 설정 변경",          "MEDIUM"),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS":  ("파일시스템 마운트",          "MEDIUM"),
    "android.permission.INSTALL_PACKAGES":           ("패키지 직접 설치",          "MEDIUM"),
    "android.permission.DELETE_PACKAGES":            ("패키지 삭제",              "MEDIUM"),
    "android.permission.CLEAR_APP_CACHE":            ("앱 캐시 삭제",             "LOW"),
    "android.permission.BODY_SENSORS":               ("신체 센서 접근",            "MEDIUM"),
    "android.permission.ACTIVITY_RECOGNITION":       ("활동 인식",               "LOW"),
}


def _mf(category, cwe, owasp, severity, path, code):
    return {
        "source": "manifest",
        "category": category,
        "cwe": cwe,
        "owasp": owasp,
        "severity": severity,
        "file_path": path,
        "line": None,
        "code": code,
        "is_third_party": False,
    }


def analyze_manifest(manifest_path: str) -> list:
    findings = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[manifest] 파싱 실패: {e}")
        return findings

    ns = "http://schemas.android.com/apk/res/android"
    app = root.find("application")
    if app is None:
        return findings

    def attr(elem, name):
        return elem.get(f"{{{ns}}}{name}")

    # --------------------------------------------------------
    # application 속성
    # --------------------------------------------------------

    # HIGH: 릴리즈에 디버그 모드 — 직접적 공격 벡터
    if attr(app, "debuggable") == "true":
        findings.append(_mf("manifest_debuggable", "CWE-489",
            "M8: Security Misconfiguration", "HIGH", manifest_path,
            'android:debuggable="true" - 릴리즈 빌드에서 디버그 모드 활성화'))

    # MEDIUM: 기본값이 true라 오탐 많음, 단독으로 치명적이지 않음
    if attr(app, "allowBackup") == "true":
        findings.append(_mf("manifest_allow_backup", "CWE-530",
            "M9: Insecure Data Storage", "MEDIUM", manifest_path,
            'android:allowBackup="true" - ADB 백업으로 앱 데이터 추출 가능'))

    # HIGH: HTTP 평문 허용 — 네트워크 도청 직접 가능
    if attr(app, "usesCleartextTraffic") == "true":
        findings.append(_mf("manifest_cleartext_traffic", "CWE-319",
            "M5: Insecure Communication", "HIGH", manifest_path,
            'android:usesCleartextTraffic="true" - HTTP 평문 통신 허용'))

    # LOW: 미설정 자체는 취약점 아님, 정보 제공 목적
    if attr(app, "networkSecurityConfig") is None:
        findings.append(_mf("manifest_no_network_security_config", "CWE-295",
            "M5: Insecure Communication", "LOW", manifest_path,
            "android:networkSecurityConfig 미설정 - 네트워크 보안 정책 없음"))

    # HIGH: 테스트 빌드 배포 — 의도치 않은 기능 노출
    if attr(app, "testOnly") == "true":
        findings.append(_mf("manifest_test_only", "CWE-489",
            "M8: Security Misconfiguration", "HIGH", manifest_path,
            'android:testOnly="true" - 테스트 전용 빌드 배포됨'))

    # MEDIUM: 조건부 악용 가능
    if attr(app, "allowTaskReparenting") == "true":
        findings.append(_mf("manifest_task_reparenting", "CWE-200",
            "M1: Improper Platform Usage", "MEDIUM", manifest_path,
            'android:allowTaskReparenting="true" - 태스크 탈취 공격 가능'))

    # LOW: 실질적 위험 낮음
    if attr(app, "largeHeap") == "true":
        findings.append(_mf("manifest_large_heap", "CWE-400",
            "M8: Security Misconfiguration", "LOW", manifest_path,
            'android:largeHeap="true" - 메모리 내 민감 데이터 잔존 위험'))

    # --------------------------------------------------------
    # minSdkVersion
    # --------------------------------------------------------
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = attr(uses_sdk, "minSdkVersion") or "0"
        try:
            v = int(min_sdk)
            if v < 21:
                # HIGH: Android 5.0 미만 — 보안 패치 없는 구버전
                findings.append(_mf("manifest_low_minsdk", "CWE-1104",
                    "M8: Security Misconfiguration", "HIGH", manifest_path,
                    f'android:minSdkVersion="{min_sdk}" - Android 5.0 미만 지원 (보안 취약 버전)'))
            elif v < 24:
                # LOW: 오래됐지만 단독으론 취약점 아님
                findings.append(_mf("manifest_low_minsdk", "CWE-1104",
                    "M8: Security Misconfiguration", "LOW", manifest_path,
                    f'android:minSdkVersion="{min_sdk}" - Android 7.0 미만 지원'))
        except ValueError:
            pass

    # --------------------------------------------------------
    # exported 컴포넌트
    # severity 기준:
    #   provider exported + no permission → HIGH (데이터 직접 접근)
    #   provider_no_permission            → HIGH (읽기/쓰기 권한 없음)
    #   service exported                  → MEDIUM (기능 노출이나 데이터 직접 아님)
    #   activity/receiver exported        → LOW (대부분 딥링크/브로드캐스트 정상 설계)
    #   implicit exported (미명시)         → LOW (정보 제공 목적)
    # --------------------------------------------------------
    for tag in ["activity", "service", "receiver", "provider"]:
        for comp in app.findall(tag):
            name = attr(comp, "name") or "unknown"
            exported = attr(comp, "exported")
            permission = attr(comp, "permission")
            has_intent_filter = comp.find("intent-filter") is not None

            # 런처 액티비티 제외
            is_launcher = False
            for intent_filter in comp.findall("intent-filter"):
                for action in intent_filter.findall("action"):
                    if attr(action, "name") == "android.intent.action.MAIN":
                        is_launcher = True

            if exported == "true" and not permission and not is_launcher:
                if tag == "provider":
                    severity = "HIGH"
                elif tag == "service":
                    severity = "MEDIUM"
                else:  # activity, receiver
                    severity = "LOW"
                findings.append(_mf(f"manifest_exported_{tag}", "CWE-926",
                    "M1: Improper Platform Usage", severity, manifest_path,
                    f'<{tag} name="{name}" exported="true"> permission 없음 - 외부 앱 접근 가능'))

            # intent-filter 있는데 exported 미명시 — 정보 제공 목적
            if has_intent_filter and exported is None and not is_launcher:
                findings.append(_mf(f"manifest_implicit_exported_{tag}", "CWE-926",
                    "M1: Improper Platform Usage", "LOW", manifest_path,
                    f'<{tag} name="{name}"> intent-filter 있으나 exported 미명시'))

            # provider: readPermission / writePermission 없음 → HIGH 유지
            if tag == "provider" and exported == "true":
                if not attr(comp, "readPermission") and not attr(comp, "writePermission") and not permission:
                    findings.append(_mf("manifest_provider_no_permission", "CWE-284",
                        "M1: Improper Platform Usage", "HIGH", manifest_path,
                        f'<provider name="{name}"> 읽기/쓰기 권한 없이 exported'))

    # --------------------------------------------------------
    # 위험 권한 — 선언 자체는 정상일 수 있으므로 전체 한 단계 낮춤
    # --------------------------------------------------------
    for perm in root.findall("uses-permission"):
        perm_name = attr(perm, "name") or ""
        if perm_name in DANGEROUS_PERMISSIONS:
            desc, severity = DANGEROUS_PERMISSIONS[perm_name]
            findings.append(_mf("manifest_dangerous_permission", "CWE-250",
                "M1: Improper Platform Usage", severity, manifest_path,
                f'<uses-permission name="{perm_name}"/> ({desc})'))

    # --------------------------------------------------------
    # 커스텀 permission protectionLevel — LOW (정보 제공)
    # --------------------------------------------------------
    for perm in root.findall("permission"):
        perm_name = attr(perm, "name") or ""
        level = attr(perm, "protectionLevel") or ""
        if level in ("normal", "0", "") and perm_name:
            findings.append(_mf("manifest_weak_permission_level", "CWE-284",
                "M1: Improper Platform Usage", "LOW", manifest_path,
                f'<permission name="{perm_name}" protectionLevel="{level or "normal"}"> 낮은 보호 수준'))

    return findings


def find_manifest(start_dir: str):
    """
    지정된 디렉터리부터 상위 디렉터리를 거슬러 올라가며 AndroidManifest.xml 파일을 찾습니다.

    기존 구현은 `source_dir`의 한 단계 상위만 검색했기 때문에,
    패키지 이름을 기준으로 깊은 디렉터리로 이동한 경우 루트에 있는
    매니페스트를 찾지 못하는 문제가 있었습니다. 이를 해결하기 위해
    현재 위치를 기준으로 단계적으로 상위로 이동하면서
    `resources/AndroidManifest.xml` 또는 `AndroidManifest.xml`의 존재를 확인합니다.
    만약 끝까지 올라가도 찾지 못한다면, 마지막으로 시작 디렉터리의
    하위 트리를 순회하여 매니페스트를 검색합니다.

    :param start_dir: 검색을 시작할 기준 디렉터리 (보통 소스 코드 디렉터리)
    :return: 찾은 AndroidManifest.xml의 전체 경로, 없으면 None
    """

    curr_dir = os.path.abspath(start_dir)
    while True:
        candidate_resources = os.path.join(curr_dir, "resources", "AndroidManifest.xml")
        if os.path.exists(candidate_resources):
            return candidate_resources
        candidate = os.path.join(curr_dir, "AndroidManifest.xml")
        if os.path.exists(candidate):
            return candidate
        parent_dir = os.path.dirname(curr_dir)
        if parent_dir == curr_dir:
            break
        curr_dir = parent_dir

    for root_dir, dirs, files in os.walk(start_dir):
        for f in files:
            if f == "AndroidManifest.xml":
                return os.path.join(root_dir, f)
    return None


# ============================================================
# 엔트리포인트 (단독 실행용)
# ============================================================

def main(source_dir: str, output_path: str):
    manifest_path = find_manifest(source_dir)
    if not manifest_path:
        print("[manifest] AndroidManifest.xml 찾을 수 없음")
        return

    print(f"[manifest] 분석 중: {manifest_path}")
    findings = analyze_manifest(manifest_path)
    print(f"[manifest] 총 {len(findings)}개 발견")

    result = {
        "manifest_path": manifest_path,
        "total": len(findings),
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[manifest] 저장: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 manifest_analyzer.py <source_dir> <output.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])