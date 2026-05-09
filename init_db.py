#db에 테이블이 없으면 스스로스스로스스로스스로스스로생성하는 프로그램입니다.
import psycopg

def init_db():
    conn = psycopg.connect(
        "postgresql://apkinsight:apkinsight123@db:5432/apkinsight"
    )
    cur = conn.cursor()

    # analysis 테이블 (8주차: risk_score 컬럼 추가)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis (
        id SERIAL PRIMARY KEY,
        apk_name TEXT,
        package_name TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        risk_score INTEGER DEFAULT 0,
        risk_high INTEGER DEFAULT 0,
        risk_medium INTEGER DEFAULT 0,
        risk_low INTEGER DEFAULT 0
    );
    """)

    # analysis_result 테이블
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis_result (
        id SERIAL PRIMARY KEY,
        analysis_id INTEGER REFERENCES analysis(id) ON DELETE CASCADE,
        source TEXT,
        category TEXT,
        cwe TEXT,
        owasp TEXT,
        file_path TEXT,
        line INTEGER,
        code TEXT,
        is_third_party BOOLEAN,
        risk TEXT,
        explanation TEXT,
        fix TEXT
    );
    """)

    # 기존 DB에 fix 컬럼 없으면 추가 (마이그레이션)
    cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='analysis_result' AND column_name='fix'
        ) THEN
            ALTER TABLE analysis_result ADD COLUMN fix TEXT;
        END IF;
    END$$;
    """)

    # ── 8주차 신규 ──────────────────────────────────────────
    # libs 테이블: 탐지된 써드파티 라이브러리 목록
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis_lib (
        id SERIAL PRIMARY KEY,
        analysis_id INTEGER REFERENCES analysis(id) ON DELETE CASCADE,
        name TEXT,
        version TEXT,
        lib_type TEXT,
        source TEXT
    );
    """)

    # osv findings 테이블: CVE가 확인된 항목
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis_osv_finding (
        id SERIAL PRIMARY KEY,
        analysis_id INTEGER REFERENCES analysis(id) ON DELETE CASCADE,
        library TEXT,
        version TEXT,
        vuln_id TEXT,
        severity TEXT,
        aliases TEXT,
        summary TEXT,
        summary_ko TEXT,
        fixed_version TEXT
    );
    """)

    # osv warnings 테이블: 버전 미확인 CVE 경고
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis_osv_warning (
        id SERIAL PRIMARY KEY,
        analysis_id INTEGER REFERENCES analysis(id) ON DELETE CASCADE,
        library TEXT,
        vuln_count INTEGER,
        fixed_version TEXT,
        aliases TEXT,
        summary_ko TEXT
    );
    """)
    # ────────────────────────────────────────────────────────

    # 인덱스도 같이 (없으면 생성)
    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_analysis_package
    ON analysis(package_name);
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_result_analysis_id
    ON analysis_result(analysis_id);
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_result_risk
    ON analysis_result(risk);
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_lib_analysis_id
    ON analysis_lib(analysis_id);
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_osv_finding_analysis_id
    ON analysis_osv_finding(analysis_id);
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_osv_warning_analysis_id
    ON analysis_osv_warning(analysis_id);
    """)

    conn.commit()
    cur.close()
    conn.close()