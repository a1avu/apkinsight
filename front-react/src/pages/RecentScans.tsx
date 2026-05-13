import { useEffect, useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { getAnalysisList, getAnalysis, getAnalysisOsv, deleteAnalysis as apiDelete } from '@/api/api'
import DarkModeToggle from '@/components/DarkModeToggle'
import { useDarkMode } from '@/hooks/useDarkMode'

/* ── Types ── */
interface ListEntry {
  id: number | string
  apk_name?: string
  package_name?: string
  created_at?: string
  risk_score?: number
  risk_high?: number
  risk_medium?: number
  risk_low?: number
}

interface RawResult {
  risk?: string
  is_third_party?: boolean
}

interface RawDetail {
  results?: RawResult[]
  error?: string
}

interface OsvFinding {
  severity?: string
}

interface OsvPayload {
  osv?: { findings?: OsvFinding[] }
}

/* ── Helpers ── */
function computeRisk(detail: RawDetail, osv: OsvPayload) {
  const results = (Array.isArray(detail?.results) ? detail.results : []).filter(r => !r.is_third_party)
  const findings = Array.isArray(osv?.osv?.findings) ? osv.osv.findings : []
  const high   = results.filter(r => String(r.risk || '').toUpperCase() === 'HIGH').length
  const medium = results.filter(r => String(r.risk || '').toUpperCase() === 'MEDIUM').length
  const low    = results.filter(r => ['LOW', 'INFO'].includes(String(r.risk || '').toUpperCase())).length
  const score  = Math.min(100, high * 10 + medium * 5 + low + findings.reduce((s, f) => {
    const sev = String(f?.severity || '').toUpperCase()
    return s + (sev === 'CRITICAL' || sev === 'HIGH' ? 8 : 3)
  }, 0))
  return { score, high, medium, low }
}

function riskMeta(score: number) {
  if (score >= 70) return { label: '높은 위험', cls: 'bg-red-100 text-red-700' }
  if (score >= 40) return { label: '중간 위험', cls: 'bg-yellow-100 text-yellow-700' }
  return { label: '낮은 위험', cls: 'bg-green-100 text-green-700' }
}

function formatDT(v?: string) {
  if (!v) return '-'
  try { return new Date(v).toLocaleString('ko-KR') } catch { return v }
}

function needsHydration(item: ListEntry) {
  return !Number(item.risk_score) && !Number(item.risk_high) && !Number(item.risk_medium) && !Number(item.risk_low)
}

/* ── Component ── */
export default function RecentScans() {
  const navigate = useNavigate()
  const isDark = useDarkMode()
  const [analyses, setAnalyses]   = useState<ListEntry[]>([])
  const [hydrating, setHydrating] = useState(false)
  const globalSearch = ''
  const [listSearch,   setListSearch]   = useState('')
  const abortRef = useRef(false)

  const load = useCallback(async () => {
    abortRef.current = false
    try {
      const raw = await getAnalysisList() as ListEntry[]
      const list: ListEntry[] = Array.isArray(raw) ? raw : []
      setAnalyses(list)

      const toHydrate = list.filter(needsHydration)
      if (!toHydrate.length) return

      setHydrating(true)
      const hydrated = await Promise.all(list.map(async item => {
        if (!needsHydration(item)) return item
        try {
          const [detail, osv] = await Promise.all([
            getAnalysis(String(item.id)) as Promise<RawDetail>,
            getAnalysisOsv(String(item.id)).catch(() => ({ osv: { findings: [] } })) as Promise<OsvPayload>,
          ])
          if ((detail as RawDetail).error) return item
          const risk = computeRisk(detail, osv)
          return { ...item, risk_score: risk.score, risk_high: risk.high, risk_medium: risk.medium, risk_low: risk.low }
        } catch { return item }
      }))
      if (!abortRef.current) setAnalyses(hydrated)
    } catch {
      setAnalyses([])
    } finally {
      setHydrating(false)
    }
  }, [])

  useEffect(() => {
    load()
    return () => { abortRef.current = true }
  }, [load])

  const handleDelete = useCallback(async (id: number | string) => {
    if (!window.confirm(`분석 #${id}를 삭제할까요?`)) return
    try {
      await apiDelete(String(id))
      setAnalyses(prev => prev.filter(item => String(item.id) !== String(id)))
    } catch {
      alert('분석 삭제에 실패했습니다. API 연결 상태를 확인하세요.')
    }
  }, [])

  /* ── Derived stats ── */
  const total    = analyses.length
  const highRisk = analyses.filter(a => Number(a.risk_score || 0) >= 70).length
  const avg      = total ? Math.round(analyses.reduce((s, a) => s + Number(a.risk_score || 0), 0) / total) : 0
  const latest   = total ? formatDT(analyses[0].created_at) : '-'

  /* ── Filtered rows ── */
  const q = (globalSearch + ' ' + listSearch).toLowerCase().trim()
  const rows = analyses.filter(item => {
    if (!q) return true
    return [item.apk_name, item.package_name, item.id].some(v => String(v || '').toLowerCase().includes(q))
  })

  return (
    <div className="min-h-screen bg-[#f1f3f6] font-[Inter,system-ui,sans-serif] text-[#1e293b] text-[13px]">

      {/* ── Navbar ── */}
      <nav className="bg-white border-b border-[#e5e9f0] h-[52px] px-[22px] sticky top-0 z-[100] shadow-[0_1px_3px_rgba(0,0,0,.04)] flex items-center justify-between">
        <div className="flex items-center gap-7">
          <div className="flex items-center">
            <img src={isDark ? '/apkinsight_dark.png' : '/apkinsight.png'} className="w-[50px] h-[50px] rounded-[7px] object-contain flex-shrink-0" alt="APKInsight"/>
            <span className="text-[14px] font-extrabold text-[#0f172a] tracking-tight">APK<span className="text-[#1d4ed8]">Insight</span></span>
          </div>
          <div className="flex items-center gap-0.5 flex-wrap">
            {[
              { label: '스캔',     path: '/' },
              { label: '대시보드', path: '/dashboard' },
              { label: '최근 분석', path: '/scans' },
              { label: '상세 분석', path: '/analysis' },
            ].map(({ label, path }) => (
              <button
                key={path}
                onClick={() => navigate(path)}
                className={`px-[13px] py-[6px] rounded-md text-[13px] font-medium transition-colors cursor-pointer ${
                  path === '/scans'
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

      {/* ── Shell ── */}
      <div className="p-5">

        {/* Header card */}
        <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_14px_rgba(0,0,0,.05)] border border-[#e5eaf2] p-[20px_22px] mb-4" style={isDark ? undefined : { background: 'linear-gradient(135deg,#f8fbff 0%,#ffffff 100%)' }}>
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="text-2xl font-black text-slate-900 tracking-tight">최근 분석</div>
              <div className="text-[13px] text-slate-500 mt-1.5">DB에 저장된 분석 이력을 조회하고, 원하는 분석으로 바로 이동하거나 삭제할 수 있습니다.</div>
            </div>
            {hydrating && (
              <span className="text-[11px] text-slate-400 flex items-center gap-1.5 self-center">
                <svg className="animate-spin" width="13" height="13" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                위험 점수 계산 중...
              </span>
            )}
          </div>
        </div>

        {/* Summary grid */}
        <div className="grid grid-cols-4 gap-[13px] mb-4">
          {[
            { label: 'Total Analyses',  value: String(total),   note: 'DB에 저장된 전체 분석 수',       big: true },
            { label: 'High Risk Apps',  value: String(highRisk), note: '위험 점수 70점 이상',           big: true },
            { label: 'Average Score',   value: `${avg}점`,       note: '저장된 전체 분석 평균 점수',     big: true },
            { label: 'Latest Scan',     value: latest,           note: '가장 최근 분석 시각',           big: false },
          ].map(card => (
            <div key={card.label} className="bg-white rounded-xl border border-[#e5eaf2] p-[16px_18px]" style={isDark ? undefined : { background: 'linear-gradient(180deg,#ffffff 0%,#fbfdff 100%)' }}>
              <div className="text-[10px] font-extrabold text-slate-400 tracking-[.12em] uppercase">{card.label}</div>
              <div className={`font-black text-slate-900 leading-none mt-2.5 tracking-tight ${card.big ? 'text-[30px]' : 'text-[18px] leading-tight'}`}>
                {card.value}
              </div>
              <div className="text-[11px] text-slate-500 mt-1.5">{card.note}</div>
            </div>
          ))}
        </div>

        {/* Table card */}
        <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_14px_rgba(0,0,0,.05)] border border-[#e5eaf2] p-[18px_18px_8px]">
          {/* Toolbar */}
          <div className="flex items-center justify-between gap-3 flex-wrap mb-3.5">
            <div>
              <div className="text-[15px] font-extrabold text-slate-900 tracking-tight">최근 분석 목록</div>
              <div className="text-xs text-slate-500 mt-1">앱, 패키지명, 위험 점수, 취약점 수 요약을 기준으로 바로 찾을 수 있습니다.</div>
            </div>
            <div className="relative min-w-[280px] max-w-[360px] flex-1">
              <svg className="absolute left-[11px] top-1/2 -translate-y-1/2 pointer-events-none" width="14" height="14" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
              <input
                value={listSearch}
                onChange={e => setListSearch(e.target.value)}
                className="border-[1.5px] border-slate-200 rounded-[10px] py-2.5 pr-3 pl-[34px] text-xs outline-none w-full bg-white font-[Inter,sans-serif] text-slate-800 focus:border-blue-300 focus:shadow-[0_0_0_3px_rgba(59,130,246,.12)]"
                type="text"
                placeholder="앱명, 패키지명, 분석 ID로 검색"
              />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-auto">
            <table className="w-full border-collapse" style={{ minWidth: 1120 }}>
              <thead>
                <tr>
                  {['앱', '분석 ID', '위험 점수', 'HIGH / MEDIUM / LOW', '분석 시각', '액션'].map(h => (
                    <th key={h} className="px-[14px] py-3 text-left text-[10.5px] font-extrabold text-slate-500 tracking-[.08em] whitespace-nowrap uppercase border-b border-[#e5eaf2]">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map(item => {
                  const score = Number(item.risk_score || 0)
                  const risk  = riskMeta(score)
                  return (
                    <tr key={item.id} className="group">
                      {/* App */}
                      <td className="px-[14px] py-[14px] border-b border-slate-100 group-hover:bg-slate-50 align-middle">
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="w-[42px] h-[42px] rounded-xl border border-blue-200 flex items-center justify-center shrink-0" style={{ background: 'linear-gradient(135deg,#dbeafe 0%,#eff6ff 100%)' }}>
                            <svg width="18" height="18" fill="none" stroke="#2563eb" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg>
                          </div>
                          <div className="min-w-0">
                            <div className="text-[13px] font-bold text-slate-900 overflow-hidden text-ellipsis whitespace-nowrap">{item.apk_name || '-'}</div>
                            <div className="text-[11px] text-slate-500 overflow-hidden text-ellipsis whitespace-nowrap mt-[3px]">{item.package_name || '-'}</div>
                          </div>
                        </div>
                      </td>
                      {/* ID */}
                      <td className="px-[14px] py-[14px] border-b border-slate-100 group-hover:bg-slate-50 align-middle font-mono text-xs text-slate-700">
                        #{item.id}
                      </td>
                      {/* Risk score */}
                      <td className="px-[14px] py-[14px] border-b border-slate-100 group-hover:bg-slate-50 align-middle">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className="text-[20px] font-black text-slate-900 tracking-tight">{score}점</span>
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-[5px] rounded-full text-[11px] font-extrabold ${risk.cls}`}>
                            {risk.label}
                          </span>
                        </div>
                      </td>
                      {/* H/M/L */}
                      <td className="px-[14px] py-[14px] border-b border-slate-100 group-hover:bg-slate-50 align-middle">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10.5px] font-bold px-[9px] py-[3px] rounded-full bg-orange-100 text-orange-700">H {Number(item.risk_high || 0)}</span>
                          <span className="text-[10.5px] font-bold px-[9px] py-[3px] rounded-full bg-yellow-100 text-yellow-700">M {Number(item.risk_medium || 0)}</span>
                          <span className="text-[10.5px] font-bold px-[9px] py-[3px] rounded-full bg-green-100 text-green-700">L {Number(item.risk_low || 0)}</span>
                        </div>
                      </td>
                      {/* Created at */}
                      <td className="px-[14px] py-[14px] border-b border-slate-100 group-hover:bg-slate-50 align-middle text-slate-500 whitespace-nowrap text-xs">
                        {formatDT(item.created_at)}
                      </td>
                      {/* Actions */}
                      <td className="px-[14px] py-[14px] border-b border-slate-100 group-hover:bg-slate-50 align-middle">
                        <div className="flex items-center gap-2 flex-wrap">
                          <button
                            onClick={() => {
                              sessionStorage.setItem('apkscan_latest_id', String(item.id))
                              navigate(`/dashboard?id=${item.id}`)
                            }}
                            className="bg-slate-50 text-slate-600 border border-slate-200 rounded-[7px] px-3 py-1.5 text-xs font-medium cursor-pointer hover:bg-slate-100 hover:border-slate-300 transition-colors flex items-center gap-1.5"
                          >
                            대시보드
                          </button>
                          <button
                            onClick={() => {
                              sessionStorage.setItem('apkscan_latest_id', String(item.id))
                              navigate(`/analysis?id=${item.id}`)
                            }}
                            className="bg-slate-50 text-slate-600 border border-slate-200 rounded-[7px] px-3 py-1.5 text-xs font-medium cursor-pointer hover:bg-slate-100 hover:border-slate-300 transition-colors flex items-center gap-1.5"
                          >
                            상세 분석
                          </button>
                          <button
                            onClick={() => handleDelete(item.id)}
                            className="bg-red-50 text-red-600 border border-red-200 rounded-[7px] px-3 py-1.5 text-xs font-semibold cursor-pointer hover:bg-red-100 transition-colors"
                          >
                            삭제
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Empty state */}
          {rows.length === 0 && (
            <div className="py-[54px] text-center text-slate-400 text-xs">조회된 분석이 없습니다.</div>
          )}
        </div>
      </div>
    </div>
  )
}
