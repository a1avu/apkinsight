import os
import psycopg

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "apkinsight")
DB_USER = os.getenv("DB_USER", "apkinsight")
DB_PASSWORD = os.getenv("DB_PASSWORD", "apkinsight123")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


def get_analysis_osv_from_db(analysis_id: int) -> dict | None:
    """
    (8주차) DB에 저장된 libs / osv findings / osv warnings를 조회합니다.
    파일 기반 /analysis/{id}/osv 엔드포인트를 이 함수로 대체합니다.
    """
    conn = psycopg.connect(DATABASE_URL)
    cur = conn.cursor()

    # libs
    cur.execute("""
        SELECT name, version, lib_type, source
        FROM analysis_lib
        WHERE analysis_id = %s
        ORDER BY id ASC;
    """, (analysis_id,))
    lib_rows = cur.fetchall()
    libs = [
        {"name": r[0], "version": r[1], "type": r[2], "source": r[3]}
        for r in lib_rows
    ]

    # osv findings
    cur.execute("""
        SELECT library, version, vuln_id, severity, aliases, summary, summary_ko, fixed_version
        FROM analysis_osv_finding
        WHERE analysis_id = %s
        ORDER BY id ASC;
    """, (analysis_id,))
    finding_rows = cur.fetchall()
    findings = [
        {
            "library": r[0], "version": r[1], "vuln_id": r[2],
            "severity": r[3],
            "aliases": r[4].split(", ") if r[4] else [],
            "summary": r[5], "summary_ko": r[6], "fixed_version": r[7],
        }
        for r in finding_rows
    ]

    # osv warnings
    cur.execute("""
        SELECT library, vuln_count, fixed_version, aliases, summary_ko
        FROM analysis_osv_warning
        WHERE analysis_id = %s
        ORDER BY id ASC;
    """, (analysis_id,))
    warning_rows = cur.fetchall()
    warnings = [
        {
            "library": r[0], "vuln_count": r[1],
            "fixed_version": r[2],
            "aliases": r[3].split(", ") if r[3] else [],
            "summaries_ko": [r[4]] if r[4] else [],
        }
        for r in warning_rows
    ]

    cur.close()
    conn.close()

    if not lib_rows and not finding_rows and not warning_rows:
        return None  # DB에 데이터 없음 → 파일 fallback 신호

    return {"libs": libs, "osv": {"findings": findings, "warnings": warnings}}


def get_analysis_list(): #여태까지 분석된 apk 목록을 보여줍니다.
    conn = psycopg.connect(DATABASE_URL)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, apk_name, package_name, created_at, risk_score, risk_high, risk_medium, risk_low
        FROM analysis
        ORDER BY id DESC;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row[0],
            "apk_name": row[1],
            "package_name": row[2],
            "created_at": row[3].isoformat() if row[3] else None,
            "risk_score": row[4],
            "risk_high": row[5],
            "risk_medium": row[6],
            "risk_low": row[7],
        })

    return result


def get_analysis_detail(analysis_id: int): #특정 분석에 대한 전체적인 결과를 보여줍니다.
    conn = psycopg.connect(DATABASE_URL)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, apk_name, package_name, created_at, risk_score, risk_high, risk_medium, risk_low
        FROM analysis
        WHERE id = %s;
    """, (analysis_id,))
    analysis_row = cur.fetchone()

    if analysis_row is None:
        cur.close()
        conn.close()
        return None

    cur.execute("""
        SELECT
            id,
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
        FROM analysis_result
        WHERE analysis_id = %s
        ORDER BY id ASC;
    """, (analysis_id,))
    result_rows = cur.fetchall()

    cur.close()
    conn.close()

    results = []
    for row in result_rows:
        results.append({
            "id": row[0],
            "source": row[1],
            "category": row[2],
            "cwe": row[3],
            "owasp": row[4],
            "file_path": row[5],
            "line": row[6],
            "code": row[7],
            "is_third_party": row[8],
            "risk": row[9],
            "explanation": row[10],
            "fix": row[11]
        })

    return {
        "id": analysis_row[0],
        "apk_name": analysis_row[1],
        "package_name": analysis_row[2],
        "created_at": analysis_row[3].isoformat() if analysis_row[3] else None,
        "risk_score": analysis_row[4],
        "risk_high": analysis_row[5],
        "risk_medium": analysis_row[6],
        "risk_low": analysis_row[7],
        "results": results
    }