
import os
from sqlalchemy import create_engine, text
 
# 🔥 도커 환경변수에서 가져오기
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
 
# DB 연결 문자열
DATABASE_URL = f"postgresql+psycopg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
 
engine = create_engine(DATABASE_URL)
 
 
def delete_analysis(analysis_id: int):
    """
    특정 분석 데이터 삭제
    """
 
    with engine.connect() as conn:
        with conn.begin():
 
            # 결과 먼저 삭제 (FK 제약 때문에 자식 먼저)
            conn.execute(
                text("DELETE FROM analysis_result WHERE analysis_id = :id"),
                {"id": analysis_id}
            )
 
            # 부모 삭제
            conn.execute(
                text("DELETE FROM analysis WHERE id = :id"),
                {"id": analysis_id}
            )