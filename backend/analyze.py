"""
이 모듈은 FastAPI를 이용해 APK 파일을 받아 순차적으로 보안 분석을 수행하는 도구입니다.

업로드된 APK는 컨테이너의 `/input` 디렉터리에 임시 저장된 뒤, JADX를 사용해 디컴파일됩니다.
이 과정에서 `AndroidManifest.xml`을 파싱하여 패키지명을 추출하고, 이를 기반으로
개발자가 직접 작성한 소스 코드 디렉터리를 정확히 지정합니다. 이렇게 지정된 디렉터리에만
분석 도구들을 적용함으로써 써드파티 라이브러리로 인한 노이즈를 줄이고자 합니다.

전체 플로우는 다음과 같습니다:
1. FastAPI 엔드포인트(`/analyze`)로 APK 업로드를 수신하고 임시 저장합니다.
2. `main` 함수에서 JADX를 호출하여 APK를 디컴파일합니다.
3. 매니페스트에서 패키지명을 추출하여 소스 코드 디렉터리를 설정합니다.
4. APKLeaks로 하드코딩된 비밀 값 등을 추출하고, `grep_apkleaks.py`에서 이 값들이 실제 코드에
   등장하는 위치를 검색합니다.
5. MobSFScan(`mobsfscan`)으로 코드 전반을 스캔합니다.
6. 사용자 정의 패턴을 이용해 코드와 매니페스트를 스캔합니다(`grep_custom.py`).
7. `merge.py`에서 서로 다른 결과를 병합하고 써드파티 코드와 자체 코드 결과를 분리합니다.
8. 필요 시 Next.js 서버로 분석 결과를 전송합니다.

각 단계는 콘솔에 진행 상황을 출력하며, 오류 발생 시 해당 메시지를 출력합니다.
"""

from subprocess import run
import sys
import os
from pydantic import BaseModel
import uvicorn  # FastAPI 서버 실행을 위해 필요
import shutil
import requests
import json
import xml.etree.ElementTree as ET  # 매니페스트(XML) 파싱에 사용
#다른 포트에서 열린 프론트도 통신이 가능하게 해줍니다. 
from fastapi import FastAPI, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import HTTPException

from lib_version_detect import detect_libs_from_apk
from osv_lookup import run_osv_scan, run_osv_scan_unknown
from init_db import init_db #db 테이블이 없는 상태일때 알아서 생성
from db_insert import db_insert #json을 메모리에 올리는게 있으니까 그거 기반으로 디비에 삽입
from db_select import get_analysis_list    #분석 목록 반환받는 함수
from db_select import get_analysis_detail  #하나의 분석 전체 결과를 보는 함수
from db_select import get_analysis_osv_from_db  # 8주차: DB 기반 OSV 조회
from db_delete import delete_analysis # db 삭제 함수
init_db() #테이블없을때알아서잘만들어요기특해요

app = FastAPI()


# 모든 origin 허용 이러면 다른 포트나 파일에서도 작동 가능
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
#status 는 idle, queing_jadx, queing_apkleaks, queing_mobfscan, queing_finalize
#순차적으로 대기, 소스코드 추출 중, 하드코딩 문자열 탐색 중, 보안 취약점 탐색 중, 파일 정리 중
status = "idle"
status_message = ""
status_log: list[str] = []

#일 끝나고 json 전송하는 용도입니다.
latest_result = {
    "apk_name": "",
    "data": {
        "custom": [],
        "third_party": []
    }
}
@app.get("/status")
async def get_status():
    return {"status": status, "message": status_message, "log": list(status_log)}

@app.get("/result")
async def get_result():
    global status, latest_result

    if status != "done":
        return {"status": status, "data": None}

    result = latest_result
    status = "idle"
    latest_result = {}

    return result

@app.get("/analysis/list")
def analysis_list():
    return get_analysis_list()

@app.get("/analysis/{analysis_id}/osv")
def get_analysis_osv(analysis_id: int):
    # 8주차: DB 우선 조회, 없으면 파일 fallback
    db_result = get_analysis_osv_from_db(analysis_id)
    if db_result is not None:
        return db_result

    # fallback: 구버전 분석 결과는 파일에서 읽기
    detail = get_analysis_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="not found")
    apk_name = detail["apk_name"]
    osv_path  = f"/output/{apk_name}/{apk_name}_osv.json"
    libs_path = f"/output/{apk_name}/{apk_name}_libs.json"
    osv  = json.load(open(osv_path,  encoding="utf-8")) if os.path.exists(osv_path)  else {"findings": [], "warnings": []}
    libs = json.load(open(libs_path, encoding="utf-8")) if os.path.exists(libs_path) else []
    return {"osv": osv, "libs": libs}

@app.get("/analysis/{analysis_id}")
def analysis_detail(analysis_id: int):
    result = get_analysis_detail(analysis_id)
    if result is None:
        return {"error": "not found"}
    return result

@app.delete("/analysis/{analysis_id}")
async def delete_analysis_endpoint(analysis_id: int):
    try:
        # 삭제 전에 apk_name 먼저 조회
        detail = get_analysis_detail(analysis_id)
        apk_name = detail["apk_name"] if detail else None

        # DB 삭제
        delete_analysis(analysis_id)

        # output 폴더 삭제
        if apk_name:
            work_dir = f"/output/{apk_name}"
            if os.path.exists(work_dir):
                shutil.rmtree(work_dir)
                print(f"[*] output 폴더 삭제: {work_dir}")

        return {"status": "success", "message": f"Analysis {analysis_id} deleted."}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"DB 삭제 작업 중 오류 발생: {str(e)}"
        )

# 2. 요청 데이터를 받을 클래스 정의
class AnalysisRequest(BaseModel):
    """
    (미사용) 예시로 남겨둔 요청용 Pydantic 모델입니다.

    현재 구현에서는 업로드된 파일만 처리하므로 사용되지 않습니다. 향후 확장 시
    필요에 따라 JSON body로 경로 등을 받을 수 있습니다.
    """
    path: str

# 3. API 엔드포인트 등록
# 03.24 ++) 여기에 llm이랑 api도 같이 보냄
@app.post("/analyze")
async def start_analysis(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    llm_provider: str = Form(...),
    api_key: str = Form("")
):
    """
    업로드된 APK 파일을 비동기로 분석하는 엔드포인트입니다.

    클라이언트는 multipart/form-data 형식으로 APK를 전송하며, 서버는 이를 `/input`에
    저장한 뒤 `main` 함수를 백그라운드 작업으로 실행합니다. 호출자는 즉시 응답을
    수신하고, 실제 분석은 백그라운드에서 진행됩니다.
    """
    global status, status_message

    if status not in ("idle", "error"):
        return {"error": "analysis already running"} #프로세스를 두 번 요청해서 꼬이게 하지 않게 방지
    global latest_result
    latest_result = {} #혹시 몰라 한 번 더 갈아버리고 갑니다.
    # 1. 임시 저장 경로 구성: 컨테이너 내 /input 디렉터리를 기준으로 함
    temp_path = f"/input/{file.filename}"
    # 2. 스트림을 통해 업로드된 파일을 디스크에 저장
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    # 3. 저장된 경로를 main 함수에 전달하여 비동기 처리 등록
    # 03.24 ++) 여기도 수정함
    background_tasks.add_task(main, temp_path, llm_provider, api_key)
    return {"status": "started", "fileName": file.filename}

def get_package_name_from_manifest(jadx_out: str) -> str | None:
    """
    디컴파일된 결과에서 패키지명을 읽어 직접 작성한 소스 코드 경로를 계산합니다.

    매니페스트 파일은 일반적으로 `resources/AndroidManifest.xml`에 위치합니다. 존재하지
    않을 경우 `None`을 반환하여 전체 `sources` 디렉터리를 사용할 수 있도록 합니다.

    :param jadx_out: jadx가 생성한 최상위 출력 디렉터리
    :return: 패키지명(`com.example.app` 형태) 또는 찾지 못한 경우 None
    """
    manifest_path = os.path.join(jadx_out, "resources", "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return None
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    return root.attrib.get("package")

def fix_permissions(path: str) -> None:
    """
    디렉터리와 그 안의 파일 권한을 수정합니다.

    Docker 컨테이너에서 생성된 파일은 기본적으로 root 권한을 가질 수 있기 때문에,
    호스트에서 결과를 읽거나 삭제할 수 있도록 디렉터리는 755, 파일은 644 권한을
    부여합니다.

    :param path: 권한을 수정할 최상위 디렉터리
    """
    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)

# 03.24 ++)llm들의 api키가 맞는지 미리 확인하는 코드
def validate_llm_connection(llm_provider: str, api_key: str) -> bool:
    print(f"[*] 검증 시작: {llm_provider}, key={api_key[:4]}...")
    try:
        if llm_provider == "ollama":
            res = requests.get(
                "https://2171255capstone.iptime.org:8443/health",
                headers={"x-api-key": api_key},
                verify=False,
                timeout=60
            )
            return res.status_code == 200
        elif llm_provider == "gemini":
            res = requests.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": "hi"}]}]},
                timeout=60
            )
            return res.status_code == 200
    except Exception:
        return False
    return False

def main(apk_path, llm_provider, api_key) -> None:
    """
    APK 파일 하나에 대해 전체 분석 파이프라인을 실행하는 함수입니다.
    :param apk_path: 분석 대상 APK 파일의 절대 경로
    """
    
    global status, status_message, status_log
    status_log = []
    status_message = "대기 중..."
    status_log.append(status_message)
    # 03.24 ++) 각각의 api키 검증 로직
    if not validate_llm_connection(llm_provider, api_key):
        print("[!] API 키 검증 실패")
        status_message = "API 키 검증 실패 — 키를 확인하세요"
        status_log.append(status_message)
        status = "error"
        return

    # 절대 경로로 변환 후 기본 변수 설정
    apk_path = os.path.abspath(apk_path)
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    output_dir = "/output"  # 컨테이너 내 결과 저장 루트
    work_dir = os.path.join(output_dir, apk_name)  # APK 이름별로 하위 디렉터리 생성
    jadx_out = os.path.join(work_dir, "jadx_out")  # JADX 출력 디렉터리
    # source_dir는 패키지명 파싱 이후에 결정함

    os.makedirs(jadx_out, exist_ok=True)

    # 1. JADX 디컴파일
    status = "queing_jadx"
    status_message = "JADX 디컴파일 중..."
    status_log.append(status_message)
    print(f"\n[1/7] JADX 디컴파일 중...")
    run(["jadx", "-d", jadx_out, apk_path])

    # 2. 라이브러리 버전 탐지 + OSV CVE 조회
    print(f"\n[2/7] 라이브러리 버전 탐지 중...")
    status = "queing_lib_detect"
    status_message = "라이브러리 버전 탐지 중..."
    status_log.append(status_message)
    libs_out = os.path.join(work_dir, f"{apk_name}_libs.json")
    osv_out  = os.path.join(work_dir, f"{apk_name}_osv.json")
    try:
        libs = detect_libs_from_apk(apk_path)
        with open(libs_out, "w", encoding="utf-8") as f:
            json.dump(libs, f, ensure_ascii=False, indent=2)
        print(f"[*] 라이브러리 {len(libs)}개 탐지 → {libs_out}")

        print(f"\n[3/7] OSV CVE 조회 중...")
        status = "queing_osv"
        status_message = "OSV CVE 조회 중..."
        status_log.append(status_message)
        findings = run_osv_scan(libs)
        warnings = run_osv_scan_unknown(libs)
        osv_result = {"findings": findings, "warnings": warnings}
        with open(osv_out, "w", encoding="utf-8") as f:
            json.dump(osv_result, f, ensure_ascii=False, indent=2)
        print(f"[*] CVE {len(findings)}건 / 버전미확인 경고 {len(warnings)}건 → {osv_out}")
    except Exception as e:
        print(f"[!] 라이브러리 분석 실패: {e}")

    # 3. 매니페스트에서 패키지명 추출
    package_name = get_package_name_from_manifest(jadx_out)
    if package_name:
        # 패키지명을 점(.)을 기준으로 분리하여 경로로 변환
        source_dir = os.path.join(jadx_out, "sources", *package_name.split("."))
        print("[*] package:", package_name)
        print("[*] source_dir:", source_dir)
    else:
        # 패키지명을 찾지 못하면 전체 sources 디렉터리를 사용
        source_dir = os.path.join(jadx_out, "sources")
        print("써드파티 필터에 실패했습니다. 과도한 데이터가 반환되니 주의하십시오")
        print("third_party filter failed")  # 한글 깨짐을 대비해 영어 병기

    # APKLeaks 관련 내용 삭제

    # 4. mobsfscan 실행
    print(f"\n[4/7] mobsfscan 실행 중...")
    status = "queing_mobfscan"
    status_message = "[4/7] mobsfscan 실행 중..."
    status_log.append(status_message)
    mobsf_out = os.path.join(work_dir, f"{apk_name}_mobsfscan.json")
    run(["mobsfscan", "--json", "-o", mobsf_out, source_dir])

    # 5. custom grep 실행
    print(f"\n[5/7] custom grep 실행 중...")
    status = "queing_custom_grep"
    status_message = "[5/7] custom grep 실행 중..."
    status_log.append(status_message)
    custom_out = os.path.join(work_dir, f"{apk_name}_custom.json")
    if os.path.exists(source_dir):
        run(["python3", "/app/grep_custom.py", source_dir, custom_out, "/app/patterns.json"])
    else:
        print("[!] 소스 디렉토리 없음, custom grep 스킵")

    # 6. merge.py 실행
    print(f"\n[6/7] merge 실행 중...")
    status = "queing_merge"
    status_message = "[6/7] merge 실행 중..."
    status_log.append(status_message)
    
    if os.path.exists(mobsf_out) and os.path.exists(custom_out):
        run(["python3", "/app/merge.py", mobsf_out, custom_out])
    elif  os.path.exists(mobsf_out):
        # custom 결과가 없으면 두 파일만 병합
        run(["python3", "/app/merge.py", mobsf_out])
    else:
        print("[!] 필수 결과 없음, merge 스킵")
    
    # 기존 llm_out_path
    merge_out = os.path.join(work_dir, f"{apk_name}_merge.json")
    
    # 7. AI 분석
    print("[7/7] AI 분석 실행중")
    status = "queing_AI"
    status_message = "[7/7] AI 분석 실행중"
    status_log.append(status_message)
    if llm_provider == "gemini" and os.path.exists(merge_out):
        run(["python3", "/app/gemini_api.py", merge_out, api_key])
    elif llm_provider == "ollama" and os.path.exists(mobsf_out):
        run(["python3", "/app/ollama_client.py", merge_out, api_key])

    # 7. 권한 수정: 호스트에서 파일 접근 가능하도록 권한 조정
    print(f"\n[*] 파일 권한 수정 중...")
    status_message = "파일 권한 수정 중..."
    fix_permissions(work_dir)

    # 8. 완료 메시지 및 결과 목록 출력
    print(f"\n[완료] 결과 디렉토리: {work_dir}")
    for f in os.listdir(work_dir):
        fpath = os.path.join(work_dir, f)
        if os.path.isfile(fpath):
            print(f"  - {f}")

    # 9. 결과 메모리 저장: 현재는 FastAPI 내부 메모리에 최종 결과를 보관
    
    llm_out_path = os.path.join(work_dir, f"{apk_name}_llm.json")
    tp_final_path = os.path.join(work_dir, f"{apk_name}_final_third_party.json")
    results_to_send: dict[str, dict] = {}
    try:
        # custom 결과 로드
        if os.path.exists(llm_out_path):
            with open(llm_out_path, "r", encoding="utf-8") as f:
                results_to_send["custom"] = json.load(f)
        elif os.path.exists(merge_out):
            with open(merge_out, "r", encoding="utf-8") as f:
                # AI 결과는 없지만, 원본 탐지 데이터라도 채워넣음
                merged = json.load(f)
            # severity → risk 로 복사해서 덮어쓰기
                for item in merged:
                    if "risk" not in item or not item["risk"]:
                        item["risk"] = item.get("severity", "")
                        results_to_send["custom"] = merged    #ai 실패 시 냅다 덮어씌우겠습니다.  
                        #results_to_send["custom"] = json.load(f) 
                print("[!] AI 서버 응답 없음: 원본 merge 데이터를 대신 저장합니다.")

        # third-party 결과 로드
        if os.path.exists(tp_final_path):
            with open(tp_final_path, "r", encoding="utf-8") as f:
                results_to_send["third_party"] = json.load(f)

        # 메모리에 최종 결과 저장
        if results_to_send:
            print(f"[*] 결과를 메모리에 저장 중... (항목: {list(results_to_send.keys())})")

            osv_data_mem = json.load(open(osv_out, encoding="utf-8")) if os.path.exists(osv_out) else {}

            # 8주차: 위험 점수 산출 (메모리 결과에도 포함)
            from db_insert import calc_risk_score
            risk_score, risk_high, risk_medium, risk_low = calc_risk_score(results_to_send, osv_data_mem)

            payload = {
                "apk_name": apk_name,
                "risk_score":  risk_score,
                "risk_high":   risk_high,
                "risk_medium": risk_medium,
                "risk_low":    risk_low,
                "data": results_to_send,
                "libs": json.load(open(libs_out, encoding="utf-8")) if os.path.exists(libs_out) else [],
                "osv":  osv_data_mem,
            }

            global latest_result
            latest_result = payload

            print("[+] 결과 저장 성공!")
            status = "done"
            status_message = "결과 저장 성공!"
            status_log.append(status_message)
            #여따가 디비 저장 넣을게요
            #db에 결과를 영구 저장
            try:
                #굳이 아래처럼 분석 고유번호 저장할 필요가 당장은 없긴 한데 나중에 쓸 수도 있고 디버깅 할 때도 좋아서 이렇게 할게요
                analysis_id = db_insert(
                    apk_name,
                    package_name,
                    results_to_send,
                    libs=json.load(open(libs_out, encoding="utf-8")) if os.path.exists(libs_out) else None,
                    osv_data=json.load(open(osv_out, encoding="utf-8")) if os.path.exists(osv_out) else None,
                )
                print(f"[+] DB 저장 성공! analysis_id={analysis_id}")
            except Exception as e:
                print(f"[!] DB 저장 실패: {e}")
        else:
            print("[!] 저장할 분류 파일이 없습니다.")
            status = "error"
    except Exception as e:
        print(f"[!] 결과 저장 중 오류 발생: {e}")
        status = "error"

@app.get("/report/{analysis_id}")
def generate_report(analysis_id: int):
    """PDF 보고서를 생성하여 반환합니다. 실제 생성 로직은 pdf_report.py에 있습니다."""
    from fastapi.responses import StreamingResponse
    from pdf_report import build_pdf

    detail = get_analysis_detail(analysis_id)
    if not detail:
        raise HTTPException(status_code=404, detail="not found")

    db_result = get_analysis_osv_from_db(analysis_id)
    osv_payload = db_result if db_result else {"libs": [], "osv": {"findings": [], "warnings": []}}

    buf = build_pdf(detail, osv_payload)
    safe_name = detail.get("apk_name", "report").replace(" ", "_")
    return StreamingResponse(buf, media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename={safe_name}_report.pdf"
    })

# 03.24 ++)이제 localhost:8000 에 들어가면 해당 서비스 이용 가능
# `/front` 폴더를 정적 서빙
from fastapi.responses import RedirectResponse
app.mount("/", StaticFiles(directory="/app/front-react/dist", html=True), name="front")
# 루트 접근 시 메인 페이지로 서버 기반 리다이렉트
@app.get("/", include_in_schema=False)
async def serve_frontend():
    return RedirectResponse(url="/front/00-upload-scan.html", status_code=302)

if __name__ == "__main__":
    # 서버 실행 (도커 내부 8000 포트)
    uvicorn.run(app, host="0.0.0.0", port=8000)