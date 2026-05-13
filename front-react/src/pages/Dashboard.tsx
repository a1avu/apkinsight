import { useState, useEffect } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { getAnalysisList, getAnalysis, getAnalysisOsv } from '@/api/api'
import DarkModeToggle from '@/components/DarkModeToggle'
import { useDarkMode } from '@/hooks/useDarkMode'

// ─────────────────────── Types ───────────────────────

interface ListItem {
  id: string | number
  risk_score?: number
  risk_high?: number
  risk_medium?: number
  risk_low?: number
}

interface ResultItem {
  risk?: string
  category?: string
  file_path?: string
  line?: number | string
  is_third_party?: boolean
  owasp?: string
}

interface AnalysisDetail {
  id?: string | number
  apk_name?: string
  package_name?: string
  created_at?: string
  results?: ResultItem[]
  risk_score?: number
  risk_high?: number
  risk_medium?: number
  risk_low?: number
  error?: string
}

interface OsvLib { name: string; version?: string }
interface OsvFinding { library: string; severity: string }
interface OsvWarning { library: string }
interface OsvData {
  libs?: OsvLib[]
  osv?: { findings?: OsvFinding[]; warnings?: OsvWarning[] }
}

interface Top5Item { label: string; count: number; pct: string }
interface OwaspItem {
  label: string; mNum: string; short: string
  count: number; pct: string; color: string; idx: number
}
interface SummaryRow { icon: string; label: string; val: string; isPackage?: boolean }

interface DashData {
  apkName: string
  packageName: string
  createdAt: string
  score: number
  highCnt: number
  mediumCnt: number
  lowCnt: number
  tpCnt: number
  top5: Top5Item[]
  owasp: OwaspItem[]
  summary: SummaryRow[]
  detail: AnalysisDetail
}

// ─────────────────────── Constants ───────────────────────

const BASE_URL = 'http://localhost:8000'

const OWASP_PALETTE = [
  '#f97316','#06b6d4','#8b5cf6','#ef4444','#3b82f6',
  '#ec4899','#64748b','#f59e0b','#22c55e','#14b8a6',
]
const TOP5_COLORS = ['#ef4444','#f97316','#f59e0b','#22c55e','#8b5cf6']

const OWASP_ALL: [string, string][] = [
  ['M1',  'M1: Improper Credential Usage'],
  ['M2',  'M2: Inadequate Supply Chain Security'],
  ['M3',  'M3: Insecure Authentication/Authorization'],
  ['M4',  'M4: Insufficient Input/Output Validation'],
  ['M5',  'M5: Insecure Communication'],
  ['M6',  'M6: Inadequate Privacy Controls'],
  ['M7',  'M7: Insufficient Binary Protections'],
  ['M8',  'M8: Security Misconfiguration'],
  ['M9',  'M9: Insecure Data Storage'],
  ['M10', 'M10: Insufficient Cryptography'],
]

const OWASP_2016: Record<string, string> = {
  'M1: Improper Platform Usage':   'M4: Insufficient Input/Output Validation',
  'M2: Insecure Data Storage':     'M9: Insecure Data Storage',
  'M3: Insecure Communication':    'M5: Insecure Communication',
  'M4: Insecure Authentication':   'M3: Insecure Authentication/Authorization',
  'M5: Insufficient Cryptography': 'M10: Insufficient Cryptography',
  'M6: Insecure Authorization':    'M3: Insecure Authentication/Authorization',
  'M7: Client Code Quality':       'M4: Insufficient Input/Output Validation',
  'M8: Code Tampering':            'M7: Insufficient Binary Protections',
  'M9: Reverse Engineering':       'M7: Insufficient Binary Protections',
  'M10: Extraneous Functionality': 'M8: Security Misconfiguration',
  'M3: Insecure Authentication':   'M3: Insecure Authentication/Authorization',
}

const CAT_LABELS: Record<string, string> = {
  android_certificate_pinning:     '인증서 피닝 미적용',
  android_certificate_transparency:'인증서 투명성 미적용',
  android_detect_tapjacking:       '탭재킹 방어 미적용',
  android_prevent_screenshot:      '스크린샷 방지 미적용',
  android_root_detection:          '루팅 감지 미적용',
  android_safetynet_api:           'SafetyNet API 미사용',
  log_sensitive_info:              '민감한 정보 노출',
  debug_stacktrace:                '디버그 스택트레이스',
  hardcoded_secret:                '하드코딩된 비밀값',
  insecure_random:                 '안전하지 않은 난수',
  weak_crypto:                     '취약한 암호화',
  sql_injection:                   'SQL 인젝션',
  dynamic_code_loading:            '동적 코드 로딩',
  reflection_usage:                '리플렉션 사용',
  dynamic_broadcast_receiver:      '동적 브로드캐스트 리시버',
  insecure_http:                   '비보안 HTTP 사용',
  manifest_dangerous_permission:   '위험 권한',
  manifest_exported_receiver:      '노출된 수신기',
  manifest_exported_provider:      '노출된 제공자',
  manifest_provider_no_permission: '권한 없는 제공자',
  manifest_exported_activity:      '노출된 액티비티',
  manifest_exported_service:       '노출된 서비스',
  manifest_cleartext_traffic:      '평문 트래픽 허용',
  manifest_allow_backup:           '백업 허용',
}

// ─────────────────────── Pure helpers ───────────────────────

function catLabel(c: string) { return CAT_LABELS[c] || c }
function normalizeOwasp(raw: string) { return OWASP_2016[raw] || raw }

function getRiskInfo(score: number) {
  if (score >= 65) return { color: '#dc2626', label: '위험',      desc: '앱 보안 상태가 위험합니다.\n즉시 개선이 필요합니다.' }
  if (score >= 40) return { color: '#ea580c', label: '중간 위험', desc: '일부 취약점 개선이 필요합니다.' }
  return               { color: '#16a34a', label: '양호',      desc: '보안 상태가 양호합니다.' }
}

function sparkPts(vals: number[], W = 70, H = 32): string {
  const mn = Math.min(...vals), mx = Math.max(...vals), rng = mx - mn || 1
  return vals.map((v, i) =>
    `${(i / (vals.length - 1)) * W},${H - ((v - mn) / rng) * H * 0.78 - H * 0.08}`
  ).join(' ')
}

// ─────────────────────── Data processing ───────────────────────

function processData(data: AnalysisDetail, osvData: OsvData | null): DashData {
  const all  = data.results || []
  const own  = all.filter(r => !r.is_third_party)
  const libs = osvData?.libs || []
  const osv  = osvData?.osv  || { findings: [], warnings: [] }

  const highCnt   = data.risk_high   ?? own.filter(r => (r.risk || '').toUpperCase() === 'HIGH').length
  const mediumCnt = data.risk_medium ?? own.filter(r => (r.risk || '').toUpperCase() === 'MEDIUM').length
  const lowCnt    = data.risk_low    ?? own.filter(r => ['LOW','INFO'].includes((r.risk||'').toUpperCase())).length
  const tpCnt     = libs.length || all.filter(r => r.is_third_party).length
  const score     = data.risk_score  ?? Math.min(100, highCnt * 10 + mediumCnt * 5 + lowCnt)

  // TOP 5 vulnerability types
  const catMap: Record<string, number> = {}
  own.forEach(r => { const c = r.category || 'unknown'; catMap[c] = (catMap[c] || 0) + 1 })
  const totOwn = own.length || 1
  const top5: Top5Item[] = Object.entries(catMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([n, c]) => ({ label: catLabel(n), count: c, pct: `${(c / totOwn * 100).toFixed(1)}%` }))

  // OWASP distribution (normalise 2016→2024)
  const owMap: Record<string, number> = {}
  own.forEach(r => { const o = normalizeOwasp(r.owasp || 'Unknown'); owMap[o] = (owMap[o] || 0) + 1 })
  const owTotal = Object.values(owMap).reduce((s, v) => s + v, 0) || 1
  const owasp: OwaspItem[] = OWASP_ALL.map(([m, label], idx) => {
    const cnt = Object.entries(owMap)
      .filter(([k]) => k.startsWith(m + ':') || k === label)
      .reduce((s, [, v]) => s + v, 0)
    return {
      label,
      mNum: label.match(/^(M\d+)/)?.[1] || '',
      short: label.replace(/^M\d+:\s*/, ''),
      count: cnt,
      pct: `${(cnt / owTotal * 100).toFixed(1)}%`,
      color: OWASP_PALETTE[idx],
      idx,
    }
  })

  const cveCount  = (osv.findings  || []).length
  const warnCount = (osv.warnings  || []).length

  const summary: SummaryRow[] = [
    { icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',  label: '패키지명',    val: data.package_name || '-', isPackage: true },
    { icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',                                                                                     label: '취약점 (자체)', val: `${own.length}건` },
    { icon: 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10',                                                                      label: '라이브러리',  val: `${tpCnt}개` },
    { icon: 'M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z',                       label: 'CVE 확인',   val: cveCount  > 0 ? `${cveCount}건`  : '없음' },
    { icon: 'M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z',                       label: '버전 미확인', val: warnCount > 0 ? `${warnCount}건` : '없음' },
    { icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', label: '위험 점수', val: `${score}점` },
  ]

  return {
    apkName:     data.apk_name || '-',
    packageName: data.package_name ? `(${data.package_name})` : '',
    createdAt:   data.created_at ? new Date(data.created_at).toLocaleString('ko-KR') : '-',
    score, highCnt, mediumCnt, lowCnt, tpCnt,
    top5, owasp, summary,
    detail: data,
  }
}

// ─────────────────────── Sub-components ───────────────────────

function Sparkline({ vals, color }: { vals: number[]; color: string }) {
  return (
    <svg width={70} height={32} className="absolute bottom-2.5 right-2.5 opacity-65 pointer-events-none">
      <polyline points={sparkPts(vals)} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

function RiskRing({ score }: { score: number }) {
  const [offset, setOffset] = useState(289)
  const { color, label, desc } = getRiskInfo(score)

  useEffect(() => {
    const t = setTimeout(() => setOffset(289 - (289 * score / 100)), 80)
    return () => clearTimeout(t)
  }, [score])

  return (
    <div className="flex flex-col items-center justify-center w-[260px] flex-shrink-0 pr-5 border-r border-[#f1f5f9]">
      <div className="relative w-[110px] h-[110px]">
        <svg width="110" height="110" viewBox="0 0 110 110" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="55" cy="55" r="46" fill="none" stroke="#fee2e2" strokeWidth="10"/>
          <circle
            cx="55" cy="55" r="46"
            fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray="289" strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset .9s cubic-bezier(.4,0,.2,1)', filter: 'drop-shadow(0 0 5px rgba(220,38,38,.35))' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-[28px] font-black leading-none tracking-tight" style={{ color }}>{score}</span>
          <span className="text-[10px] text-[#94a3b8] font-medium">/100</span>
        </div>
      </div>
      <div className="mt-3 text-center">
        <p className="text-[10px] text-[#94a3b8] font-semibold tracking-[.05em] mb-1">보안 점수</p>
        <p className="text-[15px] font-extrabold tracking-tight" style={{ color }}>{label}</p>
        <p className="text-[11px] text-[#64748b] mt-1 leading-[1.55] whitespace-pre-line">{desc}</p>
        <Link to="/analysis" className="text-[11px] text-[#1d4ed8] font-semibold no-underline inline-flex items-center gap-[3px] mt-2 hover:opacity-80 transition-opacity">
          상세 보기
          <svg width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M5 12h14m-7-7 7 7-7 7"/></svg>
        </Link>
      </div>
    </div>
  )
}

function StatCard({
  label, count, sub, color, bg, border, spark, sparkColor,
}: {
  label: string; count: number; sub: string
  color: string; bg: string; border: string
  spark: number[]; sparkColor: string
}) {
  return (
    <div className="rounded-[10px] p-[13px] border relative overflow-hidden" style={{ background: bg, borderColor: border }}>
      <p className="text-[10px] font-bold tracking-[.08em] mb-1.5" style={{ color }}>{label}</p>
      <p className="text-[34px] font-black leading-none tracking-tight" style={{ color: sparkColor }}>{count}</p>
      <p className="text-[11px] mt-1.5 font-medium" style={{ color: sparkColor }}>{sub}</p>
      <Sparkline vals={spark} color={sparkColor}/>
    </div>
  )
}

function Top5Chart({ items }: { items: Top5Item[] }) {
  if (!items.length) return (
    <p className="text-[12px] text-[#94a3b8] text-center py-8">데이터 없음</p>
  )
  const maxCnt  = Math.max(...items.map(i => i.count))
  const axisMax = Math.max(Math.ceil(maxCnt / 5) * 5, 5)
  const LW = 148

  const step = axisMax <= 10 ? Math.ceil(axisMax / 2) : 5
  const ticks: number[] = []
  for (let v = 0; v <= axisMax; v += step) ticks.push(v)
  if (ticks[ticks.length - 1] !== axisMax) ticks.push(axisMax)

  return (
    <div className="flex flex-col gap-0">
      {items.map((item, i) => (
        <div key={i} className="flex items-center gap-2.5 min-h-[58px] py-1">
          <div className="flex items-start gap-[9px] flex-shrink-0" style={{ width: LW }}>
            <div className="w-3.5 h-3.5 rounded-[4px] flex-shrink-0 mt-[3px]" style={{ background: TOP5_COLORS[i] }}/>
            <span className="text-[12.5px] text-[#334155] font-medium leading-[1.4] break-words">{item.label}</span>
          </div>
          <div className="flex-1 h-[30px] bg-[#eef2ff] rounded-full overflow-hidden min-w-0">
            <div
              className="h-full rounded-full"
              style={{ width: `${Math.round(item.count / axisMax * 100)}%`, background: TOP5_COLORS[i], transition: 'width .8s cubic-bezier(.4,0,.2,1)' }}
            />
          </div>
          <span className="w-7 text-[16px] font-extrabold text-[#0f172a] text-right flex-shrink-0">{item.count}</span>
          <span className="w-[52px] text-[12px] text-[#94a3b8] flex-shrink-0">({item.pct})</span>
        </div>
      ))}

      {/* X-axis */}
      <div className="flex gap-2.5 mt-auto pt-2">
        <div className="flex-shrink-0" style={{ width: LW }}/>
        <div className="flex-1 relative border-t-2 border-[#dbe3f0] h-[30px] min-w-0">
          {ticks.map((v, j) => {
            const pos = v / axisMax * 100
            const style: React.CSSProperties =
              j === 0             ? { left: 0 } :
              j === ticks.length - 1 ? { right: 0 } :
              { left: `${pos}%`, transform: 'translateX(-50%)' }
            return <span key={v} className="absolute top-[7px] text-[11.5px] text-[#94a3b8]" style={style}>{v}</span>
          })}
        </div>
        <div className="w-7 flex-shrink-0"/>
        <div className="w-[52px] flex-shrink-0"/>
      </div>
    </div>
  )
}

function OwaspDonut({ items }: { items: OwaspItem[] }) {
  const cx = 85, cy = 85, r = 52, sw = 22
  const C = 2 * Math.PI * r
  const total = items.reduce((s, x) => s + x.count, 0)

  // Pre-compute arc segments
  let acc = 0
  const segments: Array<{ color: string; len: number; rotate: number }> = []
  items.forEach(item => {
    if (!item.count) return
    const f = item.count / total
    segments.push({ color: item.color, len: f * C, rotate: -90 + acc * 360 })
    acc += f
  })

  const sorted = [...items].sort((a, b) => b.count - a.count)

  return (
    <div className="flex gap-7 items-stretch flex-1 min-h-0">
      {/* Donut SVG */}
      <div className="relative flex-shrink-0 w-[170px] h-[170px] self-center">
        <svg width="170" height="170" viewBox="0 0 170 170">
          {total === 0 ? (
            <circle cx={cx} cy={cy} r={r} fill="none" stroke="#e2e8f0" strokeWidth={sw}/>
          ) : (
            segments.map((seg, i) => (
              <circle
                key={i}
                cx={cx} cy={cy} r={r}
                fill="none" stroke={seg.color} strokeWidth={sw}
                strokeDasharray={`${seg.len} ${C}`}
                strokeDashoffset={0}
                transform={`rotate(${seg.rotate} ${cx} ${cy})`}
              />
            ))
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-[9.5px] text-[#94a3b8] font-semibold tracking-[.06em]">TOTAL</span>
          <span className="text-[26px] font-black text-[#0f172a] leading-[1.1] tracking-tight">{total || '-'}</span>
          <span className="text-[9.5px] text-[#94a3b8] mt-0.5">취약점</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex-1 min-w-0 flex flex-col gap-[9px] justify-center">
        {sorted.map(item => (
          <div key={item.idx} className="flex items-center gap-2">
            <div className="w-[9px] h-[9px] rounded-full flex-shrink-0" style={{ background: item.color }}/>
            <span className="text-[10.5px] text-[#64748b] font-bold flex-shrink-0 min-w-[26px]">{item.mNum}</span>
            <span className="text-[11px] text-[#334155] flex-1 overflow-hidden text-ellipsis whitespace-nowrap" title={item.short}>{item.short}</span>
            <span className="text-[12px] font-bold text-[#0f172a] flex-shrink-0 min-w-[20px] text-right">{item.count}</span>
            <span className="text-[10.5px] text-[#94a3b8] flex-shrink-0 min-w-[44px] text-right">{item.pct}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────── Navbar (shared) ───────────────────────

function Navbar({ active }: { active: string }) {
  const navigate = useNavigate()
  const isDark = useDarkMode()
  const navLinks = [
    { to: '/',          label: '스캔' },
    { to: '/dashboard', label: '대시보드' },
    { to: '/scans',     label: '최근 분석' },
    { to: '/analysis',  label: '상세 분석' },
  ]
  return (
    <nav className="bg-white border-b border-[#e5e9f0] h-[52px] px-[22px] sticky top-0 z-50 shadow-[0_1px_3px_rgba(0,0,0,.04)] flex items-center justify-between">
      <div className="flex items-center gap-7">
        <div className="flex items-center">
          <img src={isDark ? '/apkinsight_dark.png' : '/apkinsight.png'} className="w-[50px] h-[50px] rounded-[7px] object-contain flex-shrink-0" alt="APKInsight"/>
          <span className="text-[14px] font-extrabold text-[#0f172a] tracking-tight">
            APK<span className="text-[#1d4ed8]">Insight</span>
          </span>
        </div>
        <div className="flex items-center gap-0.5">
          {navLinks.map(({ to, label }) => (
            <Link
              key={to}
              to={to}
              className={cn(
                'px-[13px] py-[6px] rounded-[6px] text-[13px] font-medium no-underline transition-colors',
                active === label
                  ? 'text-[#1d4ed8] bg-[#e8f0fe] font-semibold'
                  : 'text-[#64748b] hover:bg-slate-100 hover:text-[#334155]',
              )}
            >
              {label}
            </Link>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-2.5">
          <DarkModeToggle />
        <Button
          size="sm"
          className="bg-[#1d4ed8] hover:bg-[#1e40af] text-white text-[12px] font-semibold gap-[5px] h-8"
          onClick={() => navigate('/')}
        >
          <svg width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M12 4v16m8-8H4"/></svg>
          새 스캔
        </Button>
      </div>
    </nav>
  )
}

// ─────────────────────── Main page ───────────────────────

export default function Dashboard() {
  const [searchParams] = useSearchParams()
  const [loading,  setLoading]  = useState(true)
  const [dashData, setDashData] = useState<DashData | null>(null)

  useEffect(() => {
    const urlId = searchParams.get('id') || sessionStorage.getItem('apkscan_latest_id')
    ;(async () => {
      try {
        const listRaw  = await getAnalysisList()
        const list     = listRaw as ListItem[]
        const targetId = urlId ? String(urlId) : (list.length > 0 ? String(list[0].id) : null)
        const listEntry = list.find(e => String(e.id) === targetId) || list[0] || null

        if (!targetId) return

        const [detailRaw, osvRaw] = await Promise.all([
          getAnalysis(targetId),
          getAnalysisOsv(targetId).catch(() => null),
        ])
        const detail = detailRaw as AnalysisDetail
        const osv    = osvRaw    as OsvData | null

        if (detail.error) return

        // Merge DB pre-computed counts into detail
        if (listEntry) {
          detail.risk_score  = listEntry.risk_score
          detail.risk_high   = listEntry.risk_high
          detail.risk_medium = listEntry.risk_medium
          detail.risk_low    = listEntry.risk_low
        }

        setDashData(processData(detail, osv))
      } catch (_) {
        // leave dashData null → show empty state
      } finally {
        setLoading(false)
      }
    })()
  }, [searchParams])

  // ── Download handlers ──────────────────────────────────────

  const handleDownloadReport = async () => {
    const id      = dashData?.detail.id
    const apkName = dashData?.apkName || 'report'
    if (!id) return
    try {
      const res = await fetch(`${BASE_URL}/report/${id}`)
      if (!res.ok) throw new Error('서버 오류')
      const blob = await res.blob()
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `${apkName}_report.pdf`,
      })
      a.click()
      URL.revokeObjectURL(a.href)
    } catch (e) {
      alert(`보고서 생성에 실패했습니다: ${e instanceof Error ? e.message : ''}`)
    }
  }

  const handleDownloadJSON = async () => {
    if (!dashData) return
    const apkName = dashData.apkName || 'result'
    const id      = dashData.detail.id

    // LLM JSON
    const llmA = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([JSON.stringify(dashData.detail, null, 2)], { type: 'application/json' })),
      download: `${apkName}_llm.json`,
    })
    llmA.click()

    // OSV JSON
    if (id) {
      try {
        const osv = await getAnalysisOsv(String(id))
        const osvA = Object.assign(document.createElement('a'), {
          href: URL.createObjectURL(new Blob([JSON.stringify(osv, null, 2)], { type: 'application/json' })),
          download: `${apkName}_osv.json`,
        })
        setTimeout(() => osvA.click(), 300)
      } catch (_) {}
    }
  }

  // ── Loading / empty states ─────────────────────────────────

  if (loading) {
    return (
      <div className="min-h-screen bg-[#f1f3f6]" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
        <Navbar active="대시보드"/>
        <div className="flex items-center justify-center h-[calc(100vh-52px)]">
          <div className="w-8 h-8 border-4 border-blue-200 border-t-blue-500 rounded-full animate-spin"/>
        </div>
      </div>
    )
  }

  if (!dashData) {
    return (
      <div className="min-h-screen bg-[#f1f3f6]" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
        <Navbar active="대시보드"/>
        <div className="flex flex-col items-center justify-center h-[calc(100vh-52px)] gap-3">
          <p className="text-[14px] text-[#64748b]">분석 데이터를 불러올 수 없습니다.</p>
          <Link to="/" className="text-[13px] text-[#1d4ed8] font-semibold no-underline hover:underline">← 스캔 페이지로</Link>
        </div>
      </div>
    )
  }

  const { apkName, packageName, createdAt, score, highCnt, mediumCnt, lowCnt, tpCnt, top5, owasp, summary } = dashData
  const spark = {
    high:   [3, 5, 4, 6, 5, 7, highCnt],
    medium: [15, 13, 14, 12, 15, 12, mediumCnt],
    low:    [22, 24, 26, 23, 27, 26, lowCnt],
    tp:     [20, 21, 22, 22, 23, 24, tpCnt],
  }
  const card = 'bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_14px_rgba(0,0,0,.05)] border border-[#e5eaf2]'

  // ── Render ─────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#f1f3f6] text-[#1e293b] text-[13px]" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>
      <Navbar active="대시보드"/>

      <div className="p-5">

        {/* ── APK meta bar ── */}
        <div className={cn(card, 'px-[18px] py-3.5 mb-4 flex items-center justify-between gap-3 flex-wrap')}>
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-blue-50 rounded-[8px] flex items-center justify-center border border-blue-100 flex-shrink-0">
              <svg width="18" height="18" fill="none" stroke="#3b82f6" strokeWidth="1.8" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/>
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[14px] font-bold text-[#0f172a]">{apkName}</span>
                <span className="bg-blue-100 text-blue-800 text-[10px] font-bold px-[7px] py-[2px] rounded-[4px] border border-blue-200">Android</span>
                {packageName && <span className="text-[12px] text-[#64748b]">{packageName}</span>}
              </div>
              <p className="text-[11px] text-[#94a3b8] mt-0.5">스캔 일시 <span className="font-medium">{createdAt}</span></p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {[
              { label: '보고서 다운로드', icon: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4', onClick: handleDownloadReport },
              { label: 'JSON',           icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',                          onClick: handleDownloadJSON },
            ].map(({ label, icon, onClick }) => (
              <button
                key={label}
                className="bg-[#f8fafc] text-[#475569] border border-[#e2e8f0] rounded-[7px] px-3 py-[6px] text-[12px] font-medium cursor-pointer hover:bg-[#f1f5f9] hover:border-[#cbd5e0] transition-colors inline-flex items-center gap-[5px]"
                onClick={onClick}
              >
                <svg width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d={icon}/>
                </svg>
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* ── ROW 1: Score ring + stat cards  |  Analysis summary ── */}
        <div className="grid grid-cols-[1fr_270px] gap-[13px] mb-[14px]">

          {/* Left card */}
          <div className={cn(card, 'p-[18px]')}>
            <div className="flex gap-5 items-stretch w-full h-full">

              <RiskRing score={score}/>

              {/* 2×2 stat cards */}
              <div className="flex-1 min-w-0 grid grid-cols-2 grid-rows-2 gap-[11px]">
                <StatCard label="HIGH"   count={highCnt}   sub="신속 대응 필요"    color="#c2410c" bg="linear-gradient(135deg,#fff7ed,#fff3e4)" border="#fbbf7a" spark={spark.high}   sparkColor="#ea580c"/>
                <StatCard label="MEDIUM" count={mediumCnt} sub="영향 내 처리 권장"  color="#92400e" bg="linear-gradient(135deg,#fffbeb,#fef9d9)" border="#fcd34d" spark={spark.medium} sparkColor="#d97706"/>
                <StatCard label="LOW"    count={lowCnt}    sub="모니터링 권장"     color="#166534" bg="linear-gradient(135deg,#f0fdf4,#e8faf0)" border="#86efac" spark={spark.low}    sparkColor="#16a34a"/>
                <StatCard label="써드파티"  count={tpCnt}     sub="발견된 구성 요소"  color="#64748b" bg="linear-gradient(135deg,#faf5ff,#f3e8ff)" border="#d8b4fe" spark={spark.tp}     sparkColor="#7c3aed"/>
              </div>
            </div>
          </div>

          {/* Right card: 분석 요약 */}
          <div className={cn(card, 'p-4')}>
            <p className="text-[13px] font-bold text-[#0f172a] mb-3.5 tracking-tight">분석 요약</p>
            <div className="flex flex-col gap-2.5">
              {summary.map((row, i) => (
                <div
                  key={i}
                  className={cn(
                    'flex justify-between',
                    row.isPackage ? 'items-start' : 'items-center',
                    i < summary.length - 1 && 'pb-2.5 border-b border-[#f8fafc]',
                  )}
                >
                  <div className="flex items-center gap-[9px] flex-shrink-0">
                    <div className="w-[26px] h-[26px] bg-[#f1f5f9] rounded-[6px] flex items-center justify-center flex-shrink-0">
                      <svg width="13" height="13" fill="none" stroke="#64748b" strokeWidth="2" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d={row.icon}/>
                      </svg>
                    </div>
                    <span className="text-[12.5px] text-[#64748b]">{row.label}</span>
                  </div>
                  <span
                    className={cn('font-bold', row.isPackage
                      ? 'text-[11px] text-[#1d4ed8] break-all text-right max-w-[140px] whitespace-normal leading-[1.4]'
                      : 'text-[13px] text-[#334155]'
                    )}
                  >
                    {row.val}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── ROW 2: TOP 5  |  OWASP doughnut ── */}
        <div className="grid grid-cols-2 gap-[13px]">

          <div className={cn(card, 'px-5 py-[18px]')}>
            <p className="text-[13px] font-bold text-[#0f172a] mb-4 tracking-tight">취약점 유형 TOP 5</p>
            <Top5Chart items={top5}/>
          </div>

          <div className={cn(card, 'px-5 py-[18px] flex flex-col')}>
            <p className="text-[13px] font-bold text-[#0f172a] mb-3.5 tracking-tight flex-shrink-0">OWASP Top 10</p>
            <OwaspDonut items={owasp}/>
          </div>

        </div>
      </div>
    </div>
  )
}
