"""
PDF 보고서 생성 모듈
reportlab을 사용해 APK 분석 결과를 PDF로 생성합니다.
"""

import io
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


def _register_korean_font():
    """NanumGothic 폰트를 등록하고 폰트명을 반환합니다."""
    normal_path = "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"
    bold_path   = "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"

    if not os.path.exists(normal_path):
        return "Helvetica"

    # 이미 등록된 경우 재등록 방지
    if "NanumGothic" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("NanumGothic", normal_path))
        if os.path.exists(bold_path):
            pdfmetrics.registerFont(TTFont("NanumGothic-Bold", bold_path))
        else:
            pdfmetrics.registerFont(TTFont("NanumGothic-Bold", normal_path))
        pdfmetrics.registerFontFamily(
            "NanumGothic",
            normal="NanumGothic",
            bold="NanumGothic-Bold",
            italic="NanumGothic",
            boldItalic="NanumGothic-Bold",
        )

    return "NanumGothic"


def _make_styles(kf):
    """ParagraphStyle 딕셔너리를 반환합니다. 부모 스타일 상속 없이 직접 정의."""
    return {
        "h1": ParagraphStyle(
            "h1", fontName=kf, fontSize=17, leading=22,
            spaceAfter=6, textColor=colors.HexColor("#0f172a"),
        ),
        "h2": ParagraphStyle(
            "h2", fontName=kf, fontSize=12, leading=16,
            spaceAfter=4, spaceBefore=12, textColor=colors.HexColor("#1d4ed8"),
        ),
        "body": ParagraphStyle(
            "body", fontName=kf, fontSize=9, leading=14,
            textColor=colors.HexColor("#334155"),
        ),
        "small": ParagraphStyle(
            "small", fontName=kf, fontSize=8, leading=12,
            textColor=colors.HexColor("#64748b"),
        ),
        "cell": ParagraphStyle(
            "cell", fontName=kf, fontSize=8, leading=11,
            textColor=colors.HexColor("#334155"), wordWrap="CJK",
        ),
        "cell_hdr": ParagraphStyle(
            "cell_hdr", fontName=kf, fontSize=8, leading=11,
            textColor=colors.white, wordWrap="CJK",
        ),
    }


def _base_table_style(header_bg):
    """모든 테이블에 공통으로 적용되는 TableStyle 목록을 반환합니다."""
    return [
        ("BACKGROUND",    (0, 0), (-1, 0),  header_bg),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
    ]


def build_pdf(detail: dict, osv_payload: dict) -> io.BytesIO:
    """분석 결과를 받아 PDF BytesIO를 반환합니다."""
    kf = _register_korean_font()
    st = _make_styles(kf)

    libs     = osv_payload.get("libs", [])
    findings = osv_payload.get("osv", {}).get("findings", [])
    warnings = osv_payload.get("osv", {}).get("warnings", [])

    results    = detail.get("results", [])
    own        = [r for r in results if not r.get("is_third_party")]
    apk_name   = detail.get("apk_name", "unknown")
    pkg_name   = detail.get("package_name", "-")
    risk_score = detail.get("risk_score", 0)
    risk_high  = detail.get("risk_high", 0)
    risk_med   = detail.get("risk_medium", 0)
    risk_low   = detail.get("risk_low", 0)
    created_at = str(detail.get("created_at", "-"))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=18*mm, leftMargin=18*mm,
        topMargin=16*mm, bottomMargin=16*mm,
    )

    def P(text, style_key="body"):
        return Paragraph(text, st[style_key])

    def risk_color(r):
        r = str(r).upper()
        if r == "CRITICAL": return colors.HexColor("#991b1b")
        if r == "HIGH":     return colors.HexColor("#c2410c")
        if r == "MEDIUM":   return colors.HexColor("#92400e")
        return colors.HexColor("#166534")

    story = []

    # ── 제목 ────────────────────────────────────────────
    story.append(P("APK 보안 분석 보고서", "h1"))
    story.append(P(
        f"APK: {apk_name}  |  패키지: {pkg_name}  |  분석 시각: {created_at}",
        "small",
    ))
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=colors.HexColor("#e2e8f0"), spaceAfter=10,
    ))

    # ── 위험 점수 요약 ───────────────────────────────────
    story.append(P("위험 점수 요약", "h2"))
    hdr = [P(h, "cell_hdr") for h in
           ["위험 점수", "HIGH", "MEDIUM", "LOW", "라이브러리", "CVE 발견", "버전미확인 경고"]]
    row = [P(str(v), "cell") for v in
           [risk_score, risk_high, risk_med, risk_low, len(libs), len(findings), len(warnings)]]
    sum_table = Table([hdr, row], colWidths=[25*mm]*7)
    sum_table.setStyle(TableStyle([
        *_base_table_style(colors.HexColor("#1d4ed8")),
        ("ALIGN",           (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS",  (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 10))

    # ── 소스코드 취약점 ──────────────────────────────────
    story.append(P(f"소스코드 취약점 ({len(own)}건)", "h2"))
    if own:
        vuln_hdr = [P(h, "cell_hdr") for h in ["위험도", "CWE", "카테고리", "파일", "Line"]]
        vuln_rows = []
        for v in own:
            fp = str(v.get("file_path", "-"))
            fp_short = fp.split("/")[-1] if "/" in fp else fp
            rc = risk_color(v.get("risk", ""))
            risk_cell = Paragraph(str(v.get("risk", "-")), ParagraphStyle(
                "rc", fontName=kf, fontSize=8, leading=11,
                textColor=rc, wordWrap="CJK",
            ))
            vuln_rows.append([
                risk_cell,
                P(str(v.get("cwe", "-")), "cell"),
                P(str(v.get("category", "-"))[:45], "cell"),
                P(fp_short[:35], "cell"),
                P(str(v.get("line", "-")), "cell"),
            ])
        vuln_table = Table(
            [vuln_hdr] + vuln_rows,
            colWidths=[18*mm, 22*mm, 58*mm, 52*mm, 12*mm],
        )
        vuln_table.setStyle(TableStyle([
            *_base_table_style(colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff7ed"), colors.white]),
        ]))
        story.append(vuln_table)
    else:
        story.append(P("소스코드 취약점이 없습니다.", "body"))
    story.append(Spacer(1, 8))

    # ── CVE 발견 항목 ────────────────────────────────────
    if findings:
        story.append(P(f"CVE 발견 항목 ({len(findings)}건)", "h2"))
        cve_hdr = [P(h, "cell_hdr") for h in ["라이브러리", "버전", "CVE ID", "심각도", "요약"]]
        cve_rows = []
        for f in findings:
            sc = risk_color(f.get("severity", ""))
            sev_cell = Paragraph(str(f.get("severity", "-")), ParagraphStyle(
                "sc", fontName=kf, fontSize=8, leading=11,
                textColor=sc, wordWrap="CJK",
            ))
            summary = str(f.get("summary_ko") or f.get("summary", "-"))
            cve_rows.append([
                P(str(f.get("library", "-"))[:30], "cell"),
                P(str(f.get("version", "-")), "cell"),
                P(str(f.get("vuln_id", "-")), "cell"),
                sev_cell,
                P(summary[:60], "cell"),
            ])
        cve_table = Table(
            [cve_hdr] + cve_rows,
            colWidths=[42*mm, 18*mm, 28*mm, 16*mm, 63*mm],
        )
        cve_table.setStyle(TableStyle([
            *_base_table_style(colors.HexColor("#dc2626")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fef2f2"), colors.white]),
        ]))
        story.append(cve_table)
        story.append(Spacer(1, 8))

    # ── 버전 미확인 경고 ─────────────────────────────────
    if warnings:
        story.append(P(f"버전 미확인 경고 ({len(warnings)}건)", "h2"))
        warn_hdr = [P(h, "cell_hdr") for h in ["라이브러리", "CVE 수", "수정 버전", "요약"]]
        warn_rows = []
        for w in warnings:
            summaries = w.get("summaries_ko") or []
            summary_text = " / ".join(str(s) for s in summaries[:3])
            warn_rows.append([
                P(str(w.get("library", "-"))[:30], "cell"),
                P(str(w.get("vuln_count", "-")), "cell"),
                P(str(w.get("fixed_version", "-")), "cell"),
                P(summary_text[:80], "cell"),
            ])
        warn_table = Table(
            [warn_hdr] + warn_rows,
            colWidths=[45*mm, 15*mm, 25*mm, 82*mm],
        )
        warn_table.setStyle(TableStyle([
            *_base_table_style(colors.HexColor("#d97706")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fefce8"), colors.white]),
        ]))
        story.append(warn_table)
        story.append(Spacer(1, 8))

    # ── 탐지된 라이브러리 ────────────────────────────────
    if libs:
        story.append(P(f"탐지된 써드파티 라이브러리 ({len(libs)}개)", "h2"))
        lib_hdr = [P(h, "cell_hdr") for h in ["라이브러리", "버전", "타입", "소스"]]
        lib_rows = []
        for l in libs[:50]:
            lib_rows.append([
                P(str(l.get("name", "-"))[:35], "cell"),
                P(str(l.get("version") or "미확인"), "cell"),
                P(str(l.get("type") or l.get("lib_type", "-")), "cell"),
                P(str(l.get("source", "-"))[:30], "cell"),
            ])
        lib_table = Table(
            [lib_hdr] + lib_rows,
            colWidths=[60*mm, 25*mm, 22*mm, 45*mm],
        )
        lib_table.setStyle(TableStyle([
            *_base_table_style(colors.HexColor("#475569")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ]))
        story.append(lib_table)

    doc.build(story)
    buf.seek(0)
    return buf
