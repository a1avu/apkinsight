import os
import json
import psycopg

# =========================
# 환경 변수 (docker-compose 기반)
# =========================
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "apkinsight")
DB_USER = os.getenv("DB_USER", "apkinsight")
DB_PASSWORD = os.getenv("DB_PASSWORD", "apkinsight123")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


# =========================
# 안전 변환 함수들
# =========================
def safe_int(v):
    if v is None:
        return None
    if v == "None" or v == "":
        return None
    try:
        return int(v)
    except:
        return None


def safe_bool(v):
    if v in [True, "true", "True", 1, "1"]:
        return True
    return False


def safe_str(v):
    if v is None:
        return None
    return str(v)


# =========================
# 위험 점수 산출 함수 (8주차)
# =========================
def calc_risk_score(results_to_send: dict, osv_data: dict) -> tuple[int, int, int, int]:
    """
    LLM/SAST 결과(HIGH/MEDIUM/LOW), 버전 미확인 경고, CVE findings 개수를
    지수 감쇠 방식으로 종합해 위험 점수를 산출합니다.

    공식:
      Risk = 100 × (1 - 0.955^HIGH × 0.985^MEDIUM × 0.998^(LOW+WARNING) × 0.28^CVE)

    Returns: (risk_score, high_cnt, medium_cnt, low_cnt)
    """
    high_cnt = medium_cnt = low_cnt = 0

    for group_name, result_list in results_to_send.items():
        if not isinstance(result_list, list):
            continue

        for r in result_list:
            if not isinstance(r, dict):
                continue

            # 기존 risk 필드가 비어 있는 경우 severity를 사용
            risk = str(r.get("risk") or r.get("severity") or "").upper()

            if risk == "HIGH":
                high_cnt += 1
            elif risk == "MEDIUM":
                medium_cnt += 1
            elif risk == "LOW":
                low_cnt += 1

    cve_cnt = 0
    warn_cnt = 0

    if isinstance(osv_data, dict):
        findings = osv_data.get("findings", [])
        warnings = osv_data.get("warnings", [])

        if isinstance(findings, list):
            cve_cnt = len(findings)

        if isinstance(warnings, list):
            warn_cnt = len(warnings)

    risk_score = int(
        100 * (
            1
            - (0.955 ** high_cnt)
            * (0.985 ** medium_cnt)
            * (0.998 ** (low_cnt + warn_cnt))
            * (0.28 ** cve_cnt)
        )
    )

    risk_score = max(0, min(risk_score, 100))

    return risk_score, high_cnt, medium_cnt, low_cnt

# =========================
# 메인 insert 함수
# =========================
def db_insert(
    apk_name: str,
    package_name: str | None,
    results_to_send: dict,
    libs: list | None = None,
    osv_data: dict | None = None,
) -> int:

    conn = psycopg.connect(DATABASE_URL)
    cur = conn.cursor()

    try:
        # =========================
        # 0. 위험 점수 산출
        # =========================
        risk_score, high_cnt, medium_cnt, low_cnt = calc_risk_score(
            results_to_send, osv_data or {}
        )

        # =========================
        # 1. analysis 저장
        # =========================
        cur.execute("""
            INSERT INTO analysis (apk_name, package_name, risk_score, risk_high, risk_medium, risk_low)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
        """, (
            safe_str(apk_name),
            safe_str(package_name),
            risk_score,
            high_cnt,
            medium_cnt,
            low_cnt,
        ))

        analysis_id = cur.fetchone()[0]

        # =========================
        # 2. 결과 저장
        # =========================
        for group_name, result_list in results_to_send.items():

            if not isinstance(result_list, list):
                continue

            for result in result_list:

                if not isinstance(result, dict):
                    continue

                source = result.get("source", group_name)

                cur.execute("""
                    INSERT INTO analysis_result (
                        analysis_id,
                        source,
                        category,
                        cwe,
                        owasp,
                        file_path,
                        line,
                        code,
                        is_third_party,
                        risk,
                        explanation,
                        fix
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    analysis_id,
                    safe_str(source),
                    safe_str(result.get("category")),
                    safe_str(result.get("cwe")),
                    safe_str(result.get("owasp")),
                    safe_str(result.get("file_path")),
                    safe_int(result.get("line")),
                    safe_str(result.get("code")),
                    safe_bool(result.get("is_third_party")),
                    safe_str(result.get("risk")),
                    safe_str(result.get("explanation")),
                    safe_str(result.get("fix"))
                ))

        # =========================
        # 3. libs 저장 (8주차)
        # =========================
        if libs:
            for lib in libs:
                if not isinstance(lib, dict):
                    continue
                cur.execute("""
                    INSERT INTO analysis_lib (analysis_id, name, version, lib_type, source)
                    VALUES (%s, %s, %s, %s, %s);
                """, (
                    analysis_id,
                    safe_str(lib.get("name") or lib.get("artifact") or lib.get("library")),
                    safe_str(lib.get("version")),
                    safe_str(lib.get("type")),
                    safe_str(lib.get("source") or lib.get("version_source")),
                ))

        # =========================
        # 4. osv findings / warnings 저장 (8주차)
        # =========================
        if osv_data:
            for f in osv_data.get("findings", []):
                if not isinstance(f, dict):
                    continue
                aliases = f.get("aliases", [])
                cur.execute("""
                    INSERT INTO analysis_osv_finding
                        (analysis_id, library, version, vuln_id, severity, aliases, summary, summary_ko, fixed_version)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (
                    analysis_id,
                    safe_str(f.get("library")),
                    safe_str(f.get("version")),
                    safe_str(f.get("vuln_id")),
                    safe_str(f.get("severity")),
                    safe_str(", ".join(aliases) if isinstance(aliases, list) else aliases),
                    safe_str(f.get("summary")),
                    safe_str(f.get("summary_ko")),
                    safe_str(f.get("fixed_version")),
                ))

            for w in osv_data.get("warnings", []):
                if not isinstance(w, dict):
                    continue
                aliases = w.get("aliases", [])
                summaries_ko = w.get("summaries_ko", [])
                cur.execute("""
                    INSERT INTO analysis_osv_warning
                        (analysis_id, library, vuln_count, fixed_version, aliases, summary_ko)
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (
                    analysis_id,
                    safe_str(w.get("library")),
                    safe_int(w.get("vuln_count") or len(aliases)),
                    safe_str(w.get("fixed_version")),
                    safe_str(", ".join(aliases) if isinstance(aliases, list) else aliases),
                    safe_str(
                        summaries_ko[0] if isinstance(summaries_ko, list) and summaries_ko
                        else safe_str(summaries_ko)
                    ),
                ))

        # =========================
        # 5. commit
        # =========================
        conn.commit()

        print(f"[+] DB 저장 완료: analysis_id={analysis_id}, risk_score={risk_score}")
        return analysis_id

    except Exception as e:
        conn.rollback()
        print(f"[!] DB 저장 중 오류 발생: {e}")
        raise

    finally:
        cur.close()
        conn.close()