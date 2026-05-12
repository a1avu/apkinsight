import { useEffect, useRef, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import hljs from 'highlight.js/lib/core'
import java from 'highlight.js/lib/languages/java'
import xml from 'highlight.js/lib/languages/xml'
import 'highlight.js/styles/atom-one-light.css'
import { getAnalysis, getAnalysisList, getAnalysisOsv } from '@/api/api'
import DarkModeToggle from '@/components/DarkModeToggle'
import { useDarkMode } from '@/hooks/useDarkMode'

hljs.registerLanguage('java', java)
hljs.registerLanguage('xml', xml)

/* ── Types ── */
interface ListEntry {
  id: number | string
  risk_score?: number
  risk_high?: number
  risk_medium?: number
  risk_low?: number
  apk_name?: string
  package_name?: string
  created_at?: string
}

interface RawResult {
  id: number
  category?: string
  cwe?: string
  owasp?: string
  file_path?: string
  line?: number
  code?: string
  risk?: string
  explanation?: string
  fix?: string
  source?: string
  is_third_party?: boolean
}

interface RawAnalysis {
  id?: number | string
  apk_name?: string
  package_name?: string
  created_at?: string
  results?: RawResult[]
  error?: string
}

interface VulnItem {
  id: number
  category: string
  cwe: string
  owasp: string
  file_path: string
  line: number
  code: string
  risk: 'HIGH' | 'MEDIUM' | 'LOW'
  explanation: string
  fix: string
  source: string
}

interface LibItem {
  name: string
  version: string | null
  type: string
  source: string
}

interface OsvFinding {
  library: string
  version: string
  vuln_id: string
  severity: string
  summary?: string
  summary_ko?: string
  fixed_version?: string
}

interface OsvWarning {
  library: string
  vuln_count: number
  fixed_version?: string
  summaries_ko?: string[]
}

interface OsvPayload {
  libs?: Array<{ name?: string; library?: string; version?: string | null; type?: string; lib_type?: string; source?: string }>
  osv?: { findings?: OsvFinding[]; warnings?: OsvWarning[] }
}

interface AppData {
  analysis: RawAnalysis | null
  vulns: VulnItem[]
  libs: LibItem[]
  osv_findings: OsvFinding[]
  osv_warnings: OsvWarning[]
}

/* ── Helpers ── */
function scoreMeta(score: number) {
  if (score >= 70) return { label: '높은 위험', desc: '즉시 조치 필요', color: '#dc2626', track: '#fee2e2', grad: 'linear-gradient(90deg,#dc2626,#ef4444)' }
  if (score >= 40) return { label: '중간 위험', desc: '우선 순위 기반 조치 권장', color: '#d97706', track: '#fef3c7', grad: 'linear-gradient(90deg,#f59e0b,#fbbf24)' }
  return { label: '낮은 위험', desc: '정기 점검 권장', color: '#16a34a', track: '#dcfce7', grad: 'linear-gradient(90deg,#16a34a,#22c55e)' }
}

function getRiskSnapshot(listEntry: ListEntry | null, vulns: VulnItem[], findings: OsvFinding[]) {
  const high = Number(listEntry?.risk_high ?? vulns.filter(v => v.risk === 'HIGH').length)
  const medium = Number(listEntry?.risk_medium ?? vulns.filter(v => v.risk === 'MEDIUM').length)
  const low = Number(listEntry?.risk_low ?? vulns.filter(v => v.risk === 'LOW').length)
  const fallback = Math.min(100, high * 10 + medium * 5 + low + findings.reduce((s, f) => {
    const sev = String(f?.severity || '').toUpperCase()
    return s + (sev === 'CRITICAL' || sev === 'HIGH' ? 8 : 3)
  }, 0))
  return { score: Number(listEntry?.risk_score ?? fallback), high, medium, low }
}

function formatDT(v?: string) {
  if (!v) return '-'
  try { return new Date(v).toLocaleString('ko-KR') } catch { return v }
}

function normalizeData(detail: RawAnalysis, osvPayload: OsvPayload): AppData {
  const results = Array.isArray(detail?.results) ? detail.results : []
  return {
    analysis: detail,
    vulns: results.filter(r => !r.is_third_party).map(r => ({
      id: r.id,
      category: r.category || '-',
      cwe: r.cwe || '-',
      owasp: r.owasp || '-',
      file_path: r.file_path || '-',
      line: r.line || 0,
      code: r.code || '',
      risk: (String(r.risk || 'LOW').toUpperCase() as 'HIGH' | 'MEDIUM' | 'LOW'),
      explanation: r.explanation || '-',
      fix: r.fix || '',
      source: r.source || '-',
    })),
    libs: Array.isArray(osvPayload?.libs) ? osvPayload.libs.map(l => ({
      name: l.name || l.library || '-',
      version: l.version ?? null,
      type: l.type || l.lib_type || '-',
      source: l.source || '-',
    })) : [],
    osv_findings: Array.isArray(osvPayload?.osv?.findings) ? osvPayload.osv.findings : [],
    osv_warnings: Array.isArray(osvPayload?.osv?.warnings) ? osvPayload.osv.warnings : [],
  }
}

function countBy(items: VulnItem[], key: keyof VulnItem): [string, number][] {
  const map = new Map<string, number>()
  items.forEach(v => {
    const name = String(v[key] || '').trim()
    if (!name || name === '-') return
    map.set(name, (map.get(name) || 0) + 1)
  })
  return Array.from(map.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5)
}

/* ── Sub-components ── */
const RISK_BADGE_MAP: Record<string, string> = {
  CRITICAL: 'bg-red-50 text-red-800 border border-red-300',
  HIGH: 'bg-orange-50 text-orange-700 border border-orange-300',
  MEDIUM: 'bg-yellow-50 text-yellow-700 border border-yellow-300',
  LOW: 'bg-green-50 text-green-700 border border-green-300',
  INFO: 'bg-sky-50 text-sky-700 border border-sky-300',
}

function RiskBadge({ level, small }: { level: string; small?: boolean }) {
  const cls = RISK_BADGE_MAP[level] || RISK_BADGE_MAP['INFO']
  return (
    <span className={`inline-block rounded-[5px] font-bold tracking-wide whitespace-nowrap ${small ? 'text-[9.5px] px-1.5 py-0' : 'text-[10.5px] px-2 py-0.5'} ${cls}`}>
      {level}
    </span>
  )
}

function CodeBlock({ code, lang = 'java' }: { code: string; lang?: string }) {
  const ref = useRef<HTMLPreElement>(null)
  useEffect(() => {
    if (!ref.current) return
    const el = ref.current.querySelector('code')
    if (!el) return
    el.removeAttribute('data-highlighted')
    try {
      const result = hljs.highlight(code, { language: lang, ignoreIllegals: true })
      el.innerHTML = result.value
    } catch {
      el.textContent = code
    }
  }, [code, lang])
  return (
    <pre ref={ref} className="hljs rounded-lg text-[11.5px] leading-[1.75] p-[14px_16px] border border-slate-200 bg-slate-50 overflow-x-auto m-0">
      <code className={`language-${lang}`}>{code}</code>
    </pre>
  )
}

/* ── Main Page ── */
export default function DetailedAnalysis() {
  const navigate = useNavigate()
  const isDark = useDarkMode()
  const [searchParams] = useSearchParams()
  const mainRef = useRef<HTMLElement>(null)

  const [data, setData] = useState<AppData>({ analysis: null, vulns: [], libs: [], osv_findings: [], osv_warnings: [] })
  const [listEntry, setListEntry] = useState<ListEntry | null>(null)
  const [activeSection, setActiveSection] = useState<'info' | 'code' | 'thirdparty'>('info')
  const [currentFilter, setCurrentFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL')
  const [facetFilter, setFacetFilter] = useState<{ type: 'cwe' | 'owasp' | null; value: string | null }>({ type: null, value: null })
  const [vulnSearch, setVulnSearch] = useState('')
  const [selectedVulnId, setSelectedVulnId] = useState<number | null>(null)
  const [selectedLibName, setSelectedLibName] = useState<string | null>(null)
  const [updatedAt, setUpdatedAt] = useState('-')

  /* ── Load data ── */
  useEffect(() => {
    async function load() {
      let id = searchParams.get('id') || sessionStorage.getItem('apkscan_latest_id') || ''
      let entry: ListEntry | null = null
      try {
        const list = await getAnalysisList() as ListEntry[]
        if (!id && Array.isArray(list) && list.length) id = String(list[0].id)
        entry = Array.isArray(list) ? (list.find(x => String(x.id) === String(id)) ?? list[0] ?? null) : null
        setListEntry(entry)
      } catch { /* ignore */ }

      if (!id) return

      try {
        const [detail, osv] = await Promise.all([
          getAnalysis(id) as Promise<RawAnalysis>,
          getAnalysisOsv(id).catch(() => ({ libs: [], osv: { findings: [], warnings: [] } })) as Promise<OsvPayload>,
        ])
        if ((detail as RawAnalysis).error) return
        setData(normalizeData(detail as RawAnalysis, osv as OsvPayload))
        setUpdatedAt(formatDT((detail as RawAnalysis).created_at))
      } catch { /* ignore */ }
    }
    load()
  }, [searchParams])

  /* ── IntersectionObserver for LNB ── */
  useEffect(() => {
    const root = mainRef.current
    if (!root) return
    const sections = root.querySelectorAll<HTMLElement>('[data-section]')
    if (!sections.length || !('IntersectionObserver' in window)) return

    const obs = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const name = (entry.target as HTMLElement).dataset.section as 'info' | 'code' | 'thirdparty'
          if (name) setActiveSection(name)
        }
      })
    }, { root, threshold: 0.35, rootMargin: '-8% 0px -45% 0px' })

    sections.forEach(s => obs.observe(s))
    return () => obs.disconnect()
  }, [])

  const scrollTo = useCallback((name: string) => {
    const el = document.getElementById('panel-' + name)
    if (!el) return
    setActiveSection(name as 'info' | 'code' | 'thirdparty')
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [])

  /* ── Derived ── */
  const risk = getRiskSnapshot(listEntry, data.vulns, data.osv_findings)
  const meta = scoreMeta(risk.score)

  const filteredVulns = data.vulns.filter(v =>
    (currentFilter === 'ALL' || v.risk === currentFilter) &&
    (!facetFilter.type || String(v[facetFilter.type] || '').trim() === facetFilter.value) &&
    (!vulnSearch || v.category.toLowerCase().includes(vulnSearch.toLowerCase()) ||
      v.cwe.toLowerCase().includes(vulnSearch.toLowerCase()) ||
      v.file_path.toLowerCase().includes(vulnSearch.toLowerCase()))
  )

  const uniqueFiles = new Set(data.vulns.map(v => v.file_path).filter(Boolean))
  const uniqueSources = new Set(data.vulns.map(v => v.source).filter(Boolean))

  /* Third-party derived */
  const cveLibSet = new Set(data.osv_findings.map(f => f.library))
  const warnLibSet = new Set(data.osv_warnings.map(w => w.library))
  const libNames = new Set(data.libs.map(l => l.name))
  const seenCveOnly = new Set<string>()
  const cveOnlyLibs: LibItem[] = []
  data.osv_findings.forEach(f => {
    if (!libNames.has(f.library) && !seenCveOnly.has(f.library)) {
      seenCveOnly.add(f.library)
      cveOnlyLibs.push({ name: f.library, version: f.version || null, type: '-', source: 'OSV' })
    }
  })
  const allLibs = [...data.libs, ...cveOnlyLibs]
  const verifiedLibs = data.libs.filter(l => l.version !== null)

  const activeLibName = selectedLibName && (
    allLibs.some(l => l.name === selectedLibName) ||
    data.osv_findings.some(f => f.library === selectedLibName) ||
    data.osv_warnings.some(w => w.library === selectedLibName)
  ) ? selectedLibName : (allLibs[0]?.name ?? data.osv_findings[0]?.library ?? data.osv_warnings[0]?.library ?? null)

  const activeLib = allLibs.find(l => l.name === activeLibName) ?? (activeLibName ? { name: activeLibName, version: null, type: '-', source: '-' } : null)
  const activeFindings = data.osv_findings.filter(f => f.library === activeLibName)
  const activeWarnings = data.osv_warnings.filter(w => w.library === activeLibName)
  const activeCveCount = activeFindings.length
  const activeWarnCount = activeWarnings.length

  const analysis = data.analysis || {}

  /* ── Render helpers ── */
  function LibRow({ lib }: { lib: LibItem }) {
    const selected = lib.name === activeLibName
    const hasCve = cveLibSet.has(lib.name)
    const hasWarn = warnLibSet.has(lib.name)
    return (
      <tr
        className={`border-b border-slate-100 cursor-pointer transition-colors hover:bg-slate-50 ${selected ? 'bg-blue-50' : ''}`}
        onClick={() => setSelectedLibName(lib.name)}
      >
        <td className="px-3 py-2 text-[11.5px] font-medium text-slate-700 font-mono overflow-hidden text-ellipsis whitespace-nowrap max-w-0 w-full">{lib.name}</td>
        <td className="px-3 py-2 font-mono text-[11.5px] font-semibold" style={{ color: lib.version ? '#16a34a' : '#94a3b8' }}>
          {lib.version ?? <span className="italic font-normal text-slate-400">미확인</span>}
        </td>
        <td className="px-3 py-2 text-[11.5px] text-slate-500">{lib.type}</td>
        <td className="px-3 py-2 text-[11px] text-slate-500 overflow-hidden text-ellipsis whitespace-nowrap">{lib.source}</td>
        <td className="px-3 py-2">
          {hasCve
            ? <RiskBadge level="CVE" small />
            : hasWarn
              ? <span className="text-[9.5px] font-bold px-1.5 rounded bg-yellow-50 border border-yellow-300 text-yellow-700">경고</span>
              : <span className="text-[11.5px] text-green-700 font-semibold flex items-center gap-0.5">
                  <svg width="11" height="11" fill="none" stroke="#16a34a" strokeWidth="2.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/></svg>없음
                </span>
          }
        </td>
      </tr>
    )
  }

  return (
    <div className="min-h-screen bg-[#f1f3f6] font-[Inter,system-ui,sans-serif] text-[#1e293b] text-[13px]">
      {/* ── Navbar ── */}
      <nav className="bg-white border-b border-[#e5e9f0] h-[52px] px-[22px] sticky top-0 z-[100] shadow-[0_1px_3px_rgba(0,0,0,.04)] flex items-center justify-between">
        <div className="flex items-center gap-7">
          <div className="flex items-center">
            <img src={isDark ? '/apkinsight_dark.png' : '/apkinsight.png'} className="w-[50px] h-[50px] rounded-[7px] object-contain flex-shrink-0" alt="APKInsight"/>
            <span className="text-[14px] font-extrabold text-[#0f172a] tracking-tight">APK<span className="text-[#1d4ed8]">Insight</span></span>
          </div>
          <div className="flex items-center gap-0.5">
            {[
              { label: '스캔', path: '/' },
              { label: '대시보드', path: '/dashboard' },
              { label: '최근 분석', path: '/scans' },
              { label: '상세 분석', path: '/analysis' },
            ].map(({ label, path }) => (
              <button
                key={path}
                onClick={() => navigate(path)}
                className={`px-[13px] py-[6px] rounded-md text-[13px] font-medium transition-colors cursor-pointer ${
                  path === '/analysis'
                    ? 'bg-[#e8f0fe] text-blue-700 font-semibold'
                    : 'text-slate-500 hover:bg-slate-100 hover:text-slate-700'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2.5">
          <div className="relative">
            <svg className="absolute left-[9px] top-1/2 -translate-y-1/2 pointer-events-none" width="13" height="13" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            <input className="border-[1.5px] border-slate-200 rounded-[7px] py-[6px] pr-2.5 pl-7 text-xs outline-none w-[200px] bg-white text-slate-800 font-[Inter,sans-serif]" type="text" placeholder="APK 검색..."/>
          </div>
          <DarkModeToggle />
          <button
            onClick={() => navigate('/')}
            className="bg-blue-700 text-white border-none px-4 py-[7px] rounded-[7px] text-xs font-semibold cursor-pointer transition-colors hover:bg-blue-800 flex items-center gap-1.5"
          >
            <svg width="12" height="12" fill="none" stroke="#fff" strokeWidth="2.5" viewBox="0 0 24 24"><path d="M12 4v16m8-8H4"/></svg>
            새 스캔
          </button>
        </div>
      </nav>

      {/* ── Workspace ── */}
      <div className="flex overflow-hidden" style={{ height: 'calc(100vh - 52px)' }}>

        {/* ── Sidebar ── */}
        <aside className="w-[224px] shrink-0 bg-white border-r border-[#e5e9f0] overflow-y-auto flex flex-col">
          {/* APK Info Card */}
          <div className="p-3 border-b border-slate-100">
            <div className="bg-slate-50 border border-[#e5eaf2] rounded-[10px] p-3">
              <div className="flex items-center gap-[9px] mb-2.5">
                <div className="w-[34px] h-[34px] bg-blue-50 rounded-lg flex items-center justify-center border border-blue-200 shrink-0">
                  <svg width="16" height="16" fill="none" stroke="#3b82f6" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                </div>
                <div className="min-w-0">
                  <p className="text-xs font-bold text-slate-900 overflow-hidden text-ellipsis whitespace-nowrap">
                    {(analysis as RawAnalysis).package_name || (analysis as RawAnalysis).apk_name || '-'}
                  </p>
                  <p className="text-[10.5px] text-slate-400 mt-0.5">
                    {(analysis as RawAnalysis).apk_name ? `${(analysis as RawAnalysis).apk_name} · ${formatDT((analysis as RawAnalysis).created_at)}` : '분석 정보를 불러오는 중...'}
                  </p>
                </div>
              </div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] text-slate-500 font-medium">보안 점수</span>
                <span className="text-sm font-black" style={{ color: meta.color }}>{risk.score}점</span>
              </div>
              <div className="h-[5px] rounded-[3px] overflow-hidden" style={{ background: meta.track }}>
                <div className="h-full rounded-[3px] transition-all duration-500" style={{ width: `${Math.min(risk.score, 100)}%`, background: meta.grad }} />
              </div>
              <p className="text-[10px] font-semibold mt-1.5" style={{ color: meta.color }}>{meta.label} — {meta.desc}</p>
            </div>
          </div>

          {/* LNB Menu */}
          <div className="py-2.5 flex-1">
            <p className="text-[10px] font-bold text-slate-400 tracking-[.12em] px-5 pb-2 pt-1 uppercase">분석 결과</p>
            {([
              { id: 'info', label: '정보', cnt: analysis && (analysis as RawAnalysis).id ? 1 : 0, icon: <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M12 2a10 10 0 100 20 10 10 0 000-20z"/></svg> },
              { id: 'code', label: '소스코드 취약점', cnt: data.vulns.length, icon: <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg> },
              { id: 'thirdparty', label: '써드파티 분석', cnt: allLibs.length, icon: <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10"/></svg> },
            ] as { id: string; label: string; cnt: number; icon: React.ReactNode }[]).map(item => (
              <div
                key={item.id}
                onClick={() => scrollTo(item.id)}
                className={`flex items-center gap-[9px] px-3 py-[9px] rounded-lg mx-2 my-0.5 cursor-pointer transition-colors text-[12.5px] font-medium select-none ${
                  activeSection === item.id
                    ? 'bg-blue-50 text-blue-700 font-semibold'
                    : 'text-slate-500 hover:bg-slate-100 hover:text-slate-700'
                }`}
              >
                <div className={`w-7 h-7 rounded-[7px] flex items-center justify-center shrink-0 transition-colors ${activeSection === item.id ? 'bg-blue-100' : 'bg-slate-100'}`}>
                  {item.icon}
                </div>
                <span>{item.label}</span>
                <span className={`ml-auto text-[10px] font-bold px-1.5 py-0.5 rounded transition-colors ${activeSection === item.id ? 'bg-blue-200 text-blue-800' : 'bg-slate-200 text-slate-500'}`}>
                  {item.cnt}
                </span>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-slate-100">
            <button
              onClick={() => navigate('/dashboard')}
              className="w-full flex items-center justify-center gap-1.5 bg-slate-50 text-slate-500 border border-slate-200 rounded-[7px] px-3 py-1.5 text-xs font-medium cursor-pointer hover:bg-slate-100 hover:border-slate-300 transition-colors"
            >
              <svg width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>
              대시보드로 돌아가기
            </button>
          </div>
        </aside>

        {/* ── Main Content ── */}
        <main ref={mainRef} className="flex-1 overflow-y-auto bg-[#f1f3f6] p-5">

          {/* ═══ INFO SECTION ═══ */}
          <section id="panel-info" data-section="info" className="scroll-mt-5 mb-5">
            <div className="mb-[14px]">
              <p className="text-base font-extrabold text-slate-900 tracking-tight mb-1">정보</p>
              <p className="text-xs text-slate-500">APK 기본 정보, 분석 시각, 위험 점수와 주요 요약 수치를 먼저 확인합니다.</p>
            </div>
            <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_14px_rgba(0,0,0,.05)] border border-[#e5eaf2] overflow-hidden">
              {/* Hero */}
              <div className="p-[18px_20px] border-b border-slate-100 bg-white" style={isDark ? undefined : { background: 'linear-gradient(135deg,#f8fbff 0%,#ffffff 100%)' }}>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0 flex-1">
                    <div className="text-2xl font-black text-slate-900 tracking-tight leading-tight">
                      {(analysis as RawAnalysis).package_name || (analysis as RawAnalysis).apk_name || '-'}
                    </div>
                    <div className="text-xs text-slate-500 mt-1.5 break-all">
                      {(analysis as RawAnalysis).apk_name || '분석 정보를 불러오는 중...'}
                    </div>
                    <div className="flex gap-2 flex-wrap mt-3.5">
                      {[
                        { label: '분석 ID', value: String((analysis as RawAnalysis).id || '-') },
                        { label: '분석 시각', value: formatDT((analysis as RawAnalysis).created_at) },
                      ].map(chip => (
                        <span key={chip.label} className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border border-[#dbe7fb] bg-white text-[11px] font-bold text-slate-700">
                          {chip.label} <span>{chip.value}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="p-[14px_16px] rounded-[14px] border min-w-[164px]" style={{ borderColor: meta.color + '33', background: meta.track }}>
                    <div className="text-[28px] font-black leading-none tracking-tight" style={{ color: meta.color }}>{risk.score}점</div>
                    <div className="text-xs font-bold mt-1.5" style={{ color: meta.color }}>{meta.label}</div>
                    <div className="text-[11px] text-slate-500 mt-1">{meta.desc}</div>
                  </div>
                </div>
              </div>
              {/* Overview grid */}
              <div className="grid grid-cols-4 gap-3 p-4 border-b border-slate-100 bg-[#fcfdff]">
                {[
                  { value: data.vulns.length, label: 'Source Vulns', note: '소스코드 기준 취약점 수', color: '' },
                  { value: risk.high, label: 'High Risk', note: '즉시 우선 확인 대상', color: '#dc2626' },
                  { value: data.libs.length, label: 'Libraries', note: '탐지된 써드파티 라이브러리 수', color: '' },
                  { value: data.osv_findings.length + data.osv_warnings.length, label: 'OSV Alerts', note: 'CVE와 경고를 합친 개수', color: '' },
                ].map(card => (
                  <div key={card.label} className="bg-white border border-[#e7edf6] rounded-xl p-[14px_16px] min-w-0">
                    <div className="text-2xl font-black text-slate-900 tracking-tight leading-none" style={{ color: card.color || undefined }}>{card.value}</div>
                    <div className="text-[11px] text-slate-400 font-bold tracking-widest uppercase mt-1.5">{card.label}</div>
                    <div className="text-[11px] text-slate-500 mt-1 whitespace-nowrap overflow-hidden text-ellipsis">{card.note}</div>
                  </div>
                ))}
              </div>
              {/* Detail grid */}
              <div className="grid grid-cols-2 gap-3 p-4 bg-white">
                <div className="border border-[#e7edf6] rounded-xl p-[14px_16px]">
                  <div className="text-[10px] text-slate-400 font-bold tracking-[.08em] uppercase mb-1.5">Package Name</div>
                  <div className="text-[13px] text-slate-900 font-bold break-words">{(analysis as RawAnalysis).package_name || '-'}</div>
                </div>
                <div className="border border-[#e7edf6] rounded-xl p-[14px_16px]">
                  <div className="text-[10px] text-slate-400 font-bold tracking-[.08em] uppercase mb-1.5">APK File</div>
                  <div className="text-[13px] text-slate-900 font-bold break-words">{(analysis as RawAnalysis).apk_name || '-'}</div>
                </div>
                <div className="border border-[#e7edf6] rounded-xl p-[14px_16px] col-span-2">
                  <div className="text-[10px] text-slate-400 font-bold tracking-[.08em] uppercase mb-1.5">Detected Files</div>
                  <div className="text-[13px] text-slate-900 font-bold mb-2">{uniqueFiles.size}개 파일</div>
                  <div className="flex flex-col max-h-[120px] overflow-y-auto border-t border-slate-100 mt-1">
                    {Array.from(uniqueFiles).map(f => {
                      const parts = f.replace(/\\/g, '/').split('/')
                      const base = parts.pop() || f
                      const dir = parts.join('/')
                      return (
                        <div key={f} className="py-[3px] border-b border-slate-50 min-w-0" title={f}>
                          <div className="text-[11px] font-mono text-slate-700 font-medium overflow-hidden text-ellipsis whitespace-nowrap">{base}</div>
                          {dir && <div className="text-[9.5px] font-mono text-slate-400 overflow-hidden text-ellipsis whitespace-nowrap">{dir}</div>}
                        </div>
                      )
                    })}
                  </div>
                </div>
                <div className="border border-[#e7edf6] rounded-xl p-[14px_16px]">
                  <div className="text-[10px] text-slate-400 font-bold tracking-[.08em] uppercase mb-1.5">Detection Sources</div>
                  <div className="text-[13px] text-slate-900 font-bold">{uniqueSources.size ? Array.from(uniqueSources).join(', ') : '탐지 엔진 정보 없음'}</div>
                </div>
              </div>
            </div>
          </section>

          {/* ═══ CODE VULNERABILITIES SECTION ═══ */}
          <section id="panel-code" data-section="code" className="scroll-mt-5 mb-5">
            <div className="mb-[14px]">
              <p className="text-base font-extrabold text-slate-900 tracking-tight mb-1">소스코드 취약점</p>
              <p className="text-xs text-slate-500">필터링된 취약점 목록과 선택 항목의 상세 코드 분석을 한 흐름 안에서 확인합니다.</p>
            </div>
            <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_14px_rgba(0,0,0,.05)] border border-[#e5eaf2] overflow-hidden">
              {/* Code overview grid */}
              <div className="grid grid-cols-4 gap-3 p-4">
                {[
                  { id: 'total', value: data.vulns.length, label: 'Total Vulns', note: `${new Set(data.vulns.map(v => v.category).filter(Boolean)).size}개 유형으로 분류됨`, color: '' },
                  { id: 'high', value: risk.high, label: 'High Risk', note: `${(analysis as RawAnalysis).package_name || (analysis as RawAnalysis).apk_name || '-'} 기준`, color: '#dc2626' },
                  { id: 'files', value: uniqueFiles.size, label: 'Detected Files', note: `총 ${uniqueFiles.size}개 파일에서 탐지`, color: '' },
                  { id: 'sources', value: uniqueSources.size, label: 'Detection Sources', note: Array.from(uniqueSources).slice(0, 2).join(', ') + (uniqueSources.size > 2 ? ' 외' : '') || '탐지 엔진 정보 없음', color: '' },
                ].map(card => (
                  <div key={card.id} className="bg-white border border-[#e7edf6] rounded-xl p-[14px_16px] min-w-0">
                    <div className="text-2xl font-black text-slate-900 tracking-tight leading-none" style={{ color: card.color || undefined }}>{card.value}</div>
                    <div className="text-[11px] text-slate-400 font-bold tracking-widest uppercase mt-1.5">{card.label}</div>
                    <div className="text-[11px] text-slate-500 mt-1 whitespace-nowrap overflow-hidden text-ellipsis">{card.note}</div>
                  </div>
                ))}
              </div>
              {/* Taxonomy grid */}
              <div className="grid grid-cols-2 gap-3 p-4 border-t border-slate-100">
                {([
                  { title: 'Top CWE', rows: countBy(data.vulns, 'cwe'), key: 'cwe' as const, empty: '집계 가능한 CWE가 없습니다.' },
                  { title: 'Top OWASP', rows: countBy(data.vulns, 'owasp'), key: 'owasp' as const, empty: '집계 가능한 OWASP가 없습니다.' },
                ]).map(({ title, rows, key, empty }) => (
                  <div key={title} className="border border-[#eef2f7] rounded-xl p-[14px_16px] bg-white">
                    <div className="text-xs font-bold text-slate-900 mb-2.5">{title}</div>
                    {rows.length ? rows.map(([name, count]) => (
                      <div
                        key={name}
                        onClick={() => setFacetFilter(f => f.type === key && f.value === name ? { type: null, value: null } : { type: key, value: name })}
                        className="flex items-center justify-between gap-3 px-2.5 py-2 -mx-2.5 rounded-lg cursor-pointer hover:bg-slate-50 transition-colors border-b border-slate-50 last:border-none"
                      >
                        <span className="text-xs text-slate-700 overflow-hidden text-ellipsis whitespace-nowrap">{name}</span>
                        <span className="text-xs font-extrabold text-slate-900 shrink-0">{count}</span>
                      </div>
                    )) : <div className="text-xs text-slate-400 py-2">{empty}</div>}
                  </div>
                ))}
              </div>
              {/* Facet chip */}
              {facetFilter.type && facetFilter.value && (
                <div className="flex items-center gap-2 flex-wrap px-4 py-3 border-t border-slate-100 bg-white">
                  <span className="inline-flex items-center gap-1.5 bg-blue-50 text-blue-700 border border-blue-200 rounded-full px-2.5 py-[5px] text-[11px] font-bold">
                    {facetFilter.type.toUpperCase()}: {facetFilter.value}
                    <button onClick={() => setFacetFilter({ type: null, value: null })} className="bg-none border-none text-inherit cursor-pointer leading-none">×</button>
                  </span>
                </div>
              )}
              {/* Toolbar */}
              <div className="bg-white border-t border-[#e5e9f0] px-4 py-2.5 flex items-center gap-2.5 flex-wrap">
                <div className="flex gap-1.5">
                  {([
                    { label: '전체', val: 'ALL' as const },
                    { label: `HIGH ${risk.high}`, val: 'HIGH' as const },
                    { label: `MEDIUM ${risk.medium}`, val: 'MEDIUM' as const },
                    { label: `LOW ${risk.low}`, val: 'LOW' as const },
                  ]).map(btn => (
                    <button
                      key={btn.val}
                      onClick={() => setCurrentFilter(btn.val)}
                      className={`px-3 py-[5px] rounded-md text-[11.5px] font-semibold cursor-pointer border-[1.5px] transition-colors font-[Inter,sans-serif] ${
                        currentFilter === btn.val
                          ? btn.val === 'HIGH'
                            ? 'border-orange-300 bg-orange-50 text-orange-700'
                            : btn.val === 'MEDIUM'
                              ? 'border-yellow-300 bg-yellow-50 text-yellow-700'
                              : btn.val === 'LOW'
                                ? 'border-green-300 bg-green-50 text-green-700'
                                : 'border-blue-400 bg-blue-50 text-blue-700'
                          : 'border-slate-200 bg-slate-50 text-slate-500 hover:border-slate-300'
                      }`}
                    >
                      {btn.label}
                    </button>
                  ))}
                </div>
                <div className="relative flex-1 max-w-[260px]">
                  <svg className="absolute left-[9px] top-1/2 -translate-y-1/2 pointer-events-none" width="12" height="12" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                  <input
                    value={vulnSearch}
                    onChange={e => setVulnSearch(e.target.value)}
                    type="text"
                    placeholder="취약점 검색..."
                    className="border-[1.5px] border-slate-200 rounded-[7px] py-[5px] pr-2.5 pl-7 text-xs outline-none w-full font-[Inter,sans-serif] text-slate-800 bg-white"
                  />
                </div>
                <span className="text-[11.5px] text-slate-400 ml-auto">{filteredVulns.length}건 표시 중</span>
              </div>
              {/* Vuln list */}
              <div className="bg-white">
                {filteredVulns.length === 0
                  ? <div className="py-10 text-center text-slate-400 text-xs">검색 결과가 없습니다</div>
                  : filteredVulns.map(v => {
                    const sel = v.id === selectedVulnId
                    return (
                      <div key={v.id}>
                        <div
                          onClick={() => setSelectedVulnId(sel ? null : v.id)}
                          className={`px-[14px] py-[11px] border-b border-slate-100 cursor-pointer transition-colors border-l-[3px] ${sel ? 'bg-blue-50 border-l-blue-500' : 'bg-white border-l-transparent hover:bg-slate-50'}`}
                        >
                          <div className="flex items-center gap-[7px] mb-[5px]">
                            <RiskBadge level={v.risk} small />
                            <span className="text-[11px] font-bold text-slate-500 font-mono">{v.cwe}</span>
                            <span className="text-[10.5px] text-slate-400 ml-auto">#{v.id}</span>
                            <svg style={{ transform: `rotate(${sel ? 90 : 0}deg)`, transition: 'transform .2s' }} width="12" height="12" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 18l6-6-6-6"/></svg>
                          </div>
                          <p className="text-xs font-bold text-slate-900 mb-1 overflow-hidden text-ellipsis whitespace-nowrap font-mono">{v.category}</p>
                          <p className="text-[11px] text-slate-400 overflow-hidden text-ellipsis whitespace-nowrap flex items-center gap-[3px]">
                            <svg width="10" height="10" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                            {v.file_path.split('/').pop()}:{v.line}
                          </p>
                        </div>
                        {sel && (
                          <div className="border-b border-[#e5e9f0] bg-slate-50 p-4">
                            <div className="flex items-center gap-[9px] pb-3 mb-3 border-b border-[#e5e9f0]">
                              <RiskBadge level={v.risk} />
                              <span className="font-mono text-[13px] font-bold text-slate-900 flex-1 overflow-hidden text-ellipsis whitespace-nowrap">{v.category}</span>
                              <button
                                onClick={e => { e.stopPropagation(); setSelectedVulnId(null) }}
                                className="bg-none border border-slate-200 rounded-md w-[26px] h-[26px] flex items-center justify-center cursor-pointer text-slate-400 text-base shrink-0"
                                title="닫기"
                              >−</button>
                            </div>
                            <div className="mb-3.5">
                              <p className="text-[10px] font-bold text-slate-400 tracking-[.2em] mb-1.5 uppercase">설 명</p>
                              <p className="text-[13px] text-slate-600 leading-[1.7]">{v.explanation}</p>
                            </div>
                            <div className="mb-3.5">
                              <p className="text-[10px] font-bold text-slate-400 tracking-[.2em] mb-1.5 uppercase">파 일</p>
                              <p className="font-mono text-xs text-slate-500 break-all">{v.file_path} : {v.line}</p>
                            </div>
                            <div className="mb-3.5">
                              <p className="text-[10px] font-bold text-slate-400 tracking-[.2em] mb-2 uppercase">코 드</p>
                              <CodeBlock code={v.code} lang="java" />
                            </div>
                            {v.fix && (
                              <div className="mb-3.5 p-3 bg-green-50 border border-green-200 rounded-lg">
                                <p className="text-[10px] font-bold text-green-700 tracking-[.2em] mb-1.5 uppercase">수정 방안</p>
                                <p className="text-[13px] text-green-800 leading-[1.7]">{v.fix}</p>
                              </div>
                            )}
                            <div className="flex gap-6 flex-wrap">
                              {[{ label: 'CWE', value: v.cwe }, { label: 'OWASP', value: v.owasp }].map(item => (
                                <div key={item.label}>
                                  <p className="text-[10px] font-bold text-slate-400 tracking-[.2em] mb-1 uppercase">{item.label}</p>
                                  <p className="text-[13px] font-semibold text-slate-600">{item.value}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })
                }
              </div>
            </div>
          </section>

          {/* ═══ THIRD PARTY SECTION ═══ */}
          <section id="panel-thirdparty" data-section="thirdparty" className="scroll-mt-5 mb-5">
            <div className="mb-[14px]">
              <p className="text-base font-extrabold text-slate-900 tracking-tight mb-1">써드파티 분석</p>
              <p className="text-xs text-slate-500">탐지된 라이브러리와 OSV.dev 기반 결과를 아래로 이어서 탐색할 수 있습니다.</p>
            </div>

            {/* Summary cards */}
            <div className="flex gap-3 mb-4 flex-wrap">
              {[
                { value: allLibs.length, label: '전체 라이브러리', color: '#0f172a', bg: '#eff6ff', border: '#bfdbfe', stroke: '#3b82f6', icon: <svg width="18" height="18" fill="none" stroke="#3b82f6" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10"/></svg> },
                { value: data.osv_findings.length, label: 'CVE 확인', color: '#dc2626', bg: '#fef2f2', border: '#fca5a5', stroke: '#ef4444', icon: <svg width="18" height="18" fill="none" stroke="#ef4444" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg> },
                { value: data.osv_warnings.length, label: '버전 미확인 경고', color: '#d97706', bg: '#fffbeb', border: '#fcd34d', stroke: '#f59e0b', icon: <svg width="18" height="18" fill="none" stroke="#f59e0b" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg> },
                { value: allLibs.filter(l => !cveLibSet.has(l.name) && !warnLibSet.has(l.name)).length, label: '취약점 없음', color: '#16a34a', bg: '#f0fdf4', border: '#86efac', stroke: '#22c55e', icon: <svg width="18" height="18" fill="none" stroke="#22c55e" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> },
              ].map(card => (
                <div key={card.label} className="bg-white border border-[#e5eaf2] rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07)] p-[14px_20px] flex items-center gap-3.5 flex-1 min-w-[150px]">
                  <div className="w-10 h-10 rounded-[10px] flex items-center justify-center shrink-0 border" style={{ background: card.bg, borderColor: card.border }}>
                    {card.icon}
                  </div>
                  <div>
                    <p className="text-[22px] font-black text-slate-900 leading-none" style={{ color: card.color }}>{card.value}</p>
                    <p className="text-[11px] text-slate-400 font-semibold mt-[3px]">{card.label}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Library detail panel */}
            <div className="bg-white rounded-xl border border-[#dbe7fb] shadow-[0_1px_3px_rgba(0,0,0,.07)] p-[16px_18px] mb-4" style={isDark ? undefined : { background: 'linear-gradient(180deg,#fbfdff 0%,#ffffff 100%)' }}>
              <div className="flex items-start justify-between gap-3 mb-3">
                <div>
                  <p className="text-sm font-extrabold text-slate-900 tracking-tight">라이브러리 상세</p>
                  <p className="text-[11px] text-slate-400 mt-1">표에서 라이브러리를 클릭하면 버전, 소스, CVE, 경고를 한 번에 확인할 수 있습니다.</p>
                </div>
                {activeLib && (
                  <span className="text-[11px] font-bold px-2 py-1 rounded-full border whitespace-nowrap" style={{
                    color: activeCveCount ? '#c2410c' : activeWarnCount ? '#92400e' : '#166534',
                    background: activeCveCount ? '#ffedd5' : activeWarnCount ? '#fef3c7' : '#dcfce7',
                    borderColor: activeCveCount ? '#fdba74' : activeWarnCount ? '#fcd34d' : '#86efac',
                  }}>
                    {activeCveCount ? 'CVE 발견' : activeWarnCount ? '경고 있음' : '안전'}
                  </span>
                )}
              </div>
              {activeLib ? (
                <>
                  <div className="text-[18px] font-black text-slate-900 tracking-tight mb-3">{activeLib.name}</div>
                  <div className="grid grid-cols-4 gap-2.5 mb-3.5">
                    {[
                      { label: 'Version', value: activeLib.version ?? '미확인' },
                      { label: 'Type', value: activeLib.type || '-' },
                      { label: 'Source', value: activeLib.source || '-' },
                      { label: 'Risk Summary', value: `CVE ${activeCveCount}건 / 경고 ${activeWarnCount}건` },
                    ].map(m => (
                      <div key={m.label} className="p-[12px_14px] border border-[#e8eef8] rounded-[10px] bg-white">
                        <div className="text-[10px] text-slate-400 font-bold tracking-[.08em] uppercase mb-1.5">{m.label}</div>
                        <div className="text-[13px] font-bold text-slate-900 break-words">{m.value}</div>
                      </div>
                    ))}
                  </div>
                  <div className="pt-3 mt-3 border-t border-[#eef2f7]">
                    <div className="text-xs font-bold text-slate-900 mb-2">연결된 CVE</div>
                    {activeFindings.length ? activeFindings.map(f => (
                      <div key={f.vuln_id} className="py-2.5 border-b border-[#f5f7fb] last:border-none last:pb-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1.5">
                          <span className="font-mono text-[11px] font-bold text-slate-900">{f.vuln_id}</span>
                          <RiskBadge level={f.severity} small />
                          <span className="text-[11px] text-slate-400">수정 버전 {f.fixed_version || '-'}</span>
                        </div>
                        <div className="text-xs text-slate-600 leading-relaxed">{f.summary_ko || f.summary || '-'}</div>
                      </div>
                    )) : <p className="text-xs text-slate-400 py-1">연결된 CVE가 없습니다.</p>}
                  </div>
                  <div className="pt-3 mt-3 border-t border-[#eef2f7]">
                    <div className="text-xs font-bold text-slate-900 mb-2">버전 미확인 경고</div>
                    {activeWarnings.length ? activeWarnings.map((w, i) => (
                      <div key={i} className="py-2.5 border-b border-[#f5f7fb] last:border-none last:pb-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1.5">
                          <span className="text-xs font-bold text-slate-900">버전 미확인 경고</span>
                          <span className="text-[11px] text-yellow-600 font-extrabold">{w.vuln_count}건</span>
                          <span className="text-[11px] text-slate-400">권장 수정 버전 {w.fixed_version || '-'}</span>
                        </div>
                        <div className="text-xs text-slate-600 leading-relaxed">
                          {(w.summaries_ko || []).map((s, j) => <span key={j}>• {s}<br /></span>)}
                        </div>
                      </div>
                    )) : <p className="text-xs text-slate-400 py-1">버전 미확인 경고가 없습니다.</p>}
                  </div>
                </>
              ) : (
                <p className="text-xs text-slate-400">표시할 라이브러리 데이터가 없습니다.</p>
              )}
            </div>

            {/* Library tables */}
            <div className="flex flex-col gap-4">
              {/* All libraries */}
              <div className="bg-white rounded-xl border border-[#e5eaf2] shadow-[0_1px_3px_rgba(0,0,0,.07)] overflow-hidden">
                <div className="flex items-center justify-between gap-3 px-4 py-3.5 border-b border-slate-100 bg-white">
                  <div>
                    <p className="text-[13px] font-bold text-slate-900 tracking-tight">전체 라이브러리</p>
                    <p className="text-[11px] text-slate-400 mt-[3px]">탐지된 모든 라이브러리와 버전, 소스, CVE 상태를 한 번에 확인합니다.</p>
                  </div>
                  <span className="text-[11px] font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-1 rounded-full whitespace-nowrap">{allLibs.length}건</span>
                </div>
                <table className="w-full border-collapse" style={{ tableLayout: 'fixed' }}>
                  <colgroup><col /><col style={{ width: 100 }}/><col style={{ width: 90 }}/><col style={{ width: 140 }}/><col style={{ width: 90 }}/></colgroup>
                  <thead><tr className="bg-slate-50">
                    {['라이브러리', '버전', '타입', '소스', 'CVE 상태'].map(h => (
                      <th key={h} className="px-3 py-2 text-left text-[10.5px] font-bold text-slate-500 tracking-[.05em] whitespace-nowrap uppercase">{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {allLibs.length ? allLibs.map(l => <LibRow key={l.name} lib={l} />) : (
                      <tr><td colSpan={5} className="px-3 py-6 text-center text-slate-400 text-xs">탐지된 라이브러리가 없습니다.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Verified */}
              <div className="bg-white rounded-xl border border-[#e5eaf2] shadow-[0_1px_3px_rgba(0,0,0,.07)] overflow-hidden">
                <div className="flex items-center justify-between gap-3 px-4 py-3.5 border-b border-slate-100 bg-white">
                  <div>
                    <p className="text-[13px] font-bold text-slate-900 tracking-tight">버전 확인 라이브러리</p>
                    <p className="text-[11px] text-slate-400 mt-[3px]">실제 버전을 확인할 수 있어 바로 검토 가능한 구성 요소만 모았습니다.</p>
                  </div>
                  <span className="text-[11px] font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-1 rounded-full whitespace-nowrap">{verifiedLibs.length}건</span>
                </div>
                <table className="w-full border-collapse" style={{ tableLayout: 'fixed' }}>
                  <colgroup><col /><col style={{ width: 100 }}/><col style={{ width: 90 }}/><col style={{ width: 140 }}/><col style={{ width: 90 }}/></colgroup>
                  <thead><tr className="bg-slate-50">
                    {['라이브러리', '버전', '타입', '소스', 'CVE 상태'].map(h => (
                      <th key={h} className="px-3 py-2 text-left text-[10.5px] font-bold text-slate-500 tracking-[.05em] whitespace-nowrap uppercase">{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {verifiedLibs.length ? verifiedLibs.map(l => <LibRow key={l.name} lib={l} />) : (
                      <tr><td colSpan={5} className="px-3 py-6 text-center text-slate-400 text-xs">버전이 확인된 라이브러리가 없습니다.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* CVE findings */}
              <div className="bg-white rounded-xl border border-[#e5eaf2] shadow-[0_1px_3px_rgba(0,0,0,.07)] overflow-hidden">
                <div className="flex items-center justify-between gap-3 px-4 py-3.5 border-b border-slate-100 bg-white">
                  <div>
                    <p className="text-[13px] font-bold text-slate-900 tracking-tight">CVE 발견 항목</p>
                    <p className="text-[11px] text-slate-400 mt-[3px]">실제 취약점이 매핑된 라이브러리와 수정 버전을 아래로 이어서 봅니다.</p>
                  </div>
                  <span className="text-[11px] font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-1 rounded-full whitespace-nowrap">{data.osv_findings.length}건</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse" style={{ tableLayout: 'auto', minWidth: 600 }}>
                    <thead><tr className="bg-slate-50">
                      {['라이브러리', '버전', 'CVE ID', '심각도', '요약 (한국어)'].map(h => (
                        <th key={h} className="px-3 py-2 text-left text-[10.5px] font-bold text-slate-500 tracking-[.05em] whitespace-nowrap uppercase min-w-[70px]">{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {data.osv_findings.length ? data.osv_findings.map(f => (
                        <tr
                          key={`${f.library}-${f.vuln_id}`}
                          className={`border-b border-slate-100 cursor-pointer hover:bg-slate-50 transition-colors ${f.library === activeLibName ? 'bg-blue-50' : ''}`}
                          onClick={() => setSelectedLibName(f.library)}
                        >
                          <td className="px-3 py-2 text-[11.5px] font-medium text-slate-700 font-mono overflow-hidden text-ellipsis whitespace-nowrap" style={{ minWidth: 160 }}>{f.library}</td>
                          <td className="px-3 py-2 font-mono text-[11px] text-slate-500" style={{ minWidth: 70 }}>{f.version}</td>
                          <td className="px-3 py-2 font-mono text-[11px] text-slate-700" style={{ minWidth: 100 }}>{f.vuln_id}</td>
                          <td className="px-3 py-2" style={{ minWidth: 70 }}><RiskBadge level={f.severity} small /></td>
                          <td className="px-3 py-2 text-[11.5px] text-slate-700" style={{ minWidth: 180 }}>
                            {f.summary_ko}<br />
                            <span className="text-[10.5px] text-slate-400">수정 버전: <b>{f.fixed_version}</b></span>
                          </td>
                        </tr>
                      )) : (
                        <tr><td colSpan={5} className="px-3 py-6 text-center text-slate-400 text-xs">확인된 CVE 항목이 없습니다.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Warnings */}
              <div className="bg-white rounded-xl border border-[#e5eaf2] shadow-[0_1px_3px_rgba(0,0,0,.07)] overflow-hidden">
                <div className="flex items-center justify-between gap-3 px-4 py-3.5 border-b border-slate-100 bg-white">
                  <div>
                    <p className="text-[13px] font-bold text-slate-900 tracking-tight">버전 미확인 경고</p>
                    <p className="text-[11px] text-slate-400 mt-[3px]">정확한 버전 식별이 안 돼 추가 확인이 필요한 항목을 따로 분리했습니다.</p>
                  </div>
                  <span className="text-[11px] font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-1 rounded-full whitespace-nowrap">{data.osv_warnings.length}건</span>
                </div>
                <table className="w-full border-collapse" style={{ tableLayout: 'fixed' }}>
                  <colgroup><col /><col style={{ width: 80 }}/><col style={{ width: 90 }}/><col /></colgroup>
                  <thead><tr className="bg-slate-50">
                    {['라이브러리', 'CVE 수', '수정 버전', '주요 취약점 요약'].map(h => (
                      <th key={h} className="px-3 py-2 text-left text-[10.5px] font-bold text-slate-500 tracking-[.05em] whitespace-nowrap uppercase">{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {data.osv_warnings.length ? data.osv_warnings.map((w, i) => (
                      <tr
                        key={i}
                        className={`border-b border-slate-100 cursor-pointer hover:bg-slate-50 transition-colors ${w.library === activeLibName ? 'bg-blue-50' : ''}`}
                        onClick={() => setSelectedLibName(w.library)}
                      >
                        <td className="px-3 py-2 text-xs font-medium text-slate-700 overflow-hidden text-ellipsis whitespace-nowrap">{w.library}</td>
                        <td className="px-3 py-2 text-[13px] font-extrabold text-yellow-600 text-center">{w.vuln_count}</td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-500">{w.fixed_version}</td>
                        <td className="px-3 py-2 text-[11.5px] text-slate-500">{(w.summaries_ko || []).map((s, j) => <span key={j}>• {s}<br /></span>)}</td>
                      </tr>
                    )) : (
                      <tr><td colSpan={4} className="px-3 py-6 text-center text-slate-400 text-xs">버전 미확인 경고가 없습니다.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* OSV footer */}
            <div className="border border-[#e5eaf2] rounded-xl bg-white mt-4 px-5 py-[9px] flex items-center justify-between">
              <span className="text-[11.5px] text-slate-400 flex items-center gap-1.5">
                <svg width="13" height="13" fill="none" stroke="#94a3b8" strokeWidth="1.8" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path strokeLinecap="round" d="M12 8v4m0 4h.01"/></svg>
                OSV.dev 데이터를 기반으로 분석되며, 결과는 파일 내 메타데이터를 통해 탐지됩니다.
              </span>
              <span className="text-[11.5px] text-slate-400 flex items-center gap-1.5 shrink-0 ml-4">
                <svg width="12" height="12" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                마지막 업데이트: {updatedAt}
              </span>
            </div>
          </section>

        </main>
      </div>
    </div>
  )
}
