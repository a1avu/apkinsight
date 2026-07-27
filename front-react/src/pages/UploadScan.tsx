import { useState, useRef, useCallback, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import DarkModeToggle from '@/components/DarkModeToggle'
import { useDarkMode } from '@/hooks/useDarkMode'
import {
  analyzeFile,
  getStatus,
  getResult,
  getAnalysisList,
  getAnalysisOsv,
} from '@/api/api'

// ─── Types ───────────────────────────────────────────────────────────────────

type ScanStatus = 'idle' | 'running' | 'done' | 'error'
type StepState = 'pending' | 'active' | 'done'
type LLMProvider = 'local' | 'gemini'
type QueueItemStatus = 'pending' | 'running' | 'done' | 'error' | 'skipped'

interface VulnCounts {
  critical: number
  high: number
  medium: number
  low: number
}

interface FileResult {
  ownCount: number
  thirdPartyCount: number
  vulnCounts: VulnCounts
}

interface QueueItem {
  id: string
  file: File
  status: QueueItemStatus
  errorMessage?: string
  result?: FileResult
}

interface LogEntry {
  text: string
  color: string
}

interface StatusResponse {
  status: string
  log?: string[]
}

interface ResultResponse {
  data?: {
    custom: Array<{ risk: string }>
    third_party: Array<unknown>
  }
}

interface AnalysisListItem {
  id: string
}

interface OsvResponse {
  libs?: Array<unknown>
}

type PollOutcome =
  | { kind: 'done' }
  | { kind: 'error'; apiKeyError: boolean }
  | { kind: 'cancelled' }

// ─── Constants ───────────────────────────────────────────────────────────────

const STATUS_STEP_MAP: Record<string, number> = {
  queing_jadx: 0,
  queing_lib_detect: 1,
  queing_osv: 1,
  queing_mobfscan: 2,
  queing_custom_grep: 2,
  queing_merge: 2,
  queing_AI: 3,
  done: 4,
}

const STEPS = [
  { title: 'APK 압축 해제 & 디컴파일',       desc: 'Jadx를 사용해 소스코드를 추출합니다' },
  { title: '라이브러리 탐지 & OSV 조회',      desc: '써드파티 라이브러리 버전 탐지 & CVE 조회' },
  { title: '소스코드 & 매니페스트 정적 분석', desc: '패턴 매칭 · 권한 분석 · 결과 병합' },
  { title: 'AI 취약점 분석',                  desc: '취약 코드 컨텍스트 생성 & 추론' },
  { title: '보고서 생성',                     desc: 'OWASP 분류 & 위험도 점수 산정' },
]

// Per-step default SVG icons (shown in pending state)
const STEP_ICONS = [
  <svg key={0} width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10"/></svg>,
  <svg key={1} width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>,
  <svg key={2} width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>,
  <svg key={3} width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>,
  <svg key={4} width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>,
]

function getLogColor(line: string): string {
  if (line.startsWith('FIND')) return '#dc2626'
  if (line.startsWith('WARN')) return '#ea580c'
  if (line.startsWith('OK'))   return '#16a34a'
  if (line.startsWith('AI'))   return '#6366f1'
  if (line.startsWith('SCAN')) return '#0891b2'
  if (line.startsWith('OSV'))  return '#d97706'
  if (line.startsWith('LIB'))  return '#2563eb'
  if (line.startsWith('JADX')) return '#059669'
  return '#64748b'
}

function formatElapsed(secs: number): string {
  const m = Math.floor(secs / 60)
  const s = String(secs % 60).padStart(2, '0')
  return `경과 ${m}:${s}`
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function UploadScan() {
  const navigate = useNavigate()
  const isDark = useDarkMode()

  // File queue
  const [queue, setQueue] = useState<QueueItem[]>([])
  const [currentIndex, setCurrentIndex] = useState(-1)
  const [isDragOver, setIsDragOver] = useState(false)
  const [dropZoneError, setDropZoneError] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // LLM / API key
  const [llmProvider, setLlmProvider] = useState<LLMProvider>('local')
  const [apiKey, setApiKey] = useState('')
  const [apiKeyError, setApiKeyError] = useState(false)

  // Scan orchestration
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [isRunning, setIsRunning] = useState(false)
  const [showLog, setShowLog] = useState(false)
  const [showResult, setShowResult] = useState(false)
  const [showApiKeyErrorModal, setShowApiKeyErrorModal] = useState(false)

  // Progress (current queue item)
  const [steps, setSteps] = useState<StepState[]>(Array(5).fill('pending') as StepState[])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [progress, setProgress] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [isProgAnimating, setIsProgAnimating] = useState(false)

  // Stable refs
  const logRef        = useRef<HTMLDivElement>(null)
  const pollTimerRef  = useRef<ReturnType<typeof setInterval> | null>(null)
  const elapsedTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const currentStepRef  = useRef(-1)
  const seenLogCountRef = useRef(0)
  const cancelRequestedRef = useRef(false)
  const abortReasonRef = useRef<'cancel' | 'apikey' | null>(null)

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pollTimerRef.current)   clearInterval(pollTimerRef.current)
      if (elapsedTimerRef.current) clearInterval(elapsedTimerRef.current)
    }
  }, [])

  // ─── Helpers ───────────────────────────────────────────────────────────────

  const appendLog = useCallback((line: string) => {
    setLogs(prev => [...prev, { text: line, color: getLogColor(line) }])
  }, [])

  const stopTimers = useCallback(() => {
    if (pollTimerRef.current)   { clearInterval(pollTimerRef.current);   pollTimerRef.current = null }
    if (elapsedTimerRef.current) { clearInterval(elapsedTimerRef.current); elapsedTimerRef.current = null }
  }, [])

  const fetchResultForItem = useCallback(async (idx: number) => {
    try {
      const data = await getResult() as ResultResponse
      if (!data.data) return

      const counts: VulnCounts = { critical: 0, high: 0, medium: 0, low: 0 }
      data.data.custom.forEach(v => {
        const r = v.risk.toUpperCase()
        if      (r === 'CRITICAL') counts.critical++
        else if (r === 'HIGH')     counts.high++
        else if (r === 'MEDIUM')   counts.medium++
        else if (r === 'LOW')      counts.low++
      })
      const ownCount = Object.values(counts).reduce((a, b) => a + b, 0)

      let thirdPartyCount = 0
      try {
        const list = await getAnalysisList() as AnalysisListItem[]
        if (list.length > 0) {
          const latestId = list[0].id
          sessionStorage.setItem('apkscan_latest_id', latestId)
          const osvData = await getAnalysisOsv(latestId) as OsvResponse
          thirdPartyCount = (osvData.libs ?? []).length
        }
      } catch (_) { /* non-critical */ }

      setQueue(prev => prev.map((q, i) => i === idx
        ? { ...q, status: 'done', result: { ownCount, thirdPartyCount, vulnCounts: counts } }
        : q))
      setShowResult(true)
    } catch (e) {
      appendLog(`WARN  결과 조회 실패: ${e instanceof Error ? e.message : ''}`)
    }
  }, [appendLog])

  const pollUntilSettled = useCallback((): Promise<PollOutcome> => {
    return new Promise(resolve => {
      seenLogCountRef.current = 0
      if (pollTimerRef.current) clearInterval(pollTimerRef.current)
      pollTimerRef.current = setInterval(async () => {
        if (cancelRequestedRef.current) {
          stopTimers()
          resolve({ kind: 'cancelled' })
          return
        }
        try {
          const statusData = await getStatus() as StatusResponse
          const bs = statusData.status
          const log = Array.isArray(statusData.log) ? statusData.log : []

          for (let i = seenLogCountRef.current; i < log.length; i++) {
            appendLog('INFO  ' + log[i])
          }
          seenLogCountRef.current = log.length

          const targetStep = STATUS_STEP_MAP[bs]
          if (targetStep !== undefined && targetStep > currentStepRef.current) {
            // Capture fromStep BEFORE updating the ref — the setSteps updater runs
            // after ref assignment, so reading currentStepRef.current inside the
            // updater would yield the already-updated value, making the loop a no-op.
            const fromStep = Math.max(0, currentStepRef.current)
            if (bs !== 'done') currentStepRef.current = targetStep
            setSteps(prev => {
              const next = [...prev] as StepState[]
              for (let i = fromStep; i < targetStep; i++) next[i] = 'done'
              if (bs !== 'done') next[targetStep] = 'active'
              return next
            })
            setProgress(bs === 'done' ? 100 : Math.round((targetStep / 5) * 100))
          }

          if (bs === 'done') {
            stopTimers()
            setSteps(Array(5).fill('done') as StepState[])
            setProgress(100)
            appendLog('OK    분석 완료!')
            resolve({ kind: 'done' })
          } else if (bs === 'error') {
            stopTimers()
            const isApiKeyError = log.some(l => l.includes('API 키 검증 실패'))
            resolve({ kind: 'error', apiKeyError: isApiKeyError })
          } else if (bs === 'idle' && currentStepRef.current >= 0) {
            stopTimers()
            resolve({ kind: 'error', apiKeyError: false })
          }
        } catch (e) {
          appendLog(`WARN  상태 조회 실패: ${e instanceof Error ? e.message : ''}`)
        }
      }, 1500)
    })
  }, [appendLog, stopTimers])

  // ─── File handlers ─────────────────────────────────────────────────────────

  const addFiles = (files: FileList | File[]) => {
    if (isRunning) return
    const list = Array.from(files).filter(f => /\.(apk|xapk)$/i.test(f.name))
    if (list.length === 0) return
    setQueue(prev => [...prev, ...list.map(f => ({
      id: `${f.name}-${f.size}-${f.lastModified}-${crypto.randomUUID()}`,
      file: f,
      status: 'pending' as QueueItemStatus,
    }))])
  }

  const removeFromQueue = (id: string) => {
    setQueue(prev => prev.filter(q => q.id !== id || q.status !== 'pending'))
  }

  const onDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragOver(true) }
  const onDragLeave = () => setIsDragOver(false)
  const onDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
    if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files)
  }
  const onFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) addFiles(e.target.files)
    e.target.value = ''
  }

  // ─── LLM / API key handlers ────────────────────────────────────────────────

  const onLLMChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setLlmProvider(e.target.value as LLMProvider)
    setApiKey('')
    setApiKeyError(false)
  }

  const onApiKeyInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    setApiKey(val)
    if (llmProvider === 'gemini' && val.length > 0) {
      // 기존 AIzaSy... 형식과 신규 AQ.Ab... (auth key) 형식을 모두 허용
      setApiKeyError(!(val.startsWith('AIzaSy') || val.startsWith('AQ.')))
    } else {
      setApiKeyError(false)
    }
  }

  // ─── Scan ──────────────────────────────────────────────────────────────────

  const startScan = async () => {
    if (queue.length === 0) {
      setDropZoneError(true)
      setTimeout(() => setDropZoneError(false), 1500)
      return
    }
    if (!apiKey.trim()) { setApiKeyError(true); return }
    if (apiKeyError) return

    cancelRequestedRef.current = false
    abortReasonRef.current = null
    setShowLog(true)
    setShowResult(false)
    setScanStatus('running')
    setIsRunning(true)

    const provider = llmProvider === 'local' ? 'ollama' : 'gemini'

    for (let i = 0; i < queue.length; i++) {
      if (cancelRequestedRef.current) break

      setCurrentIndex(i)
      const item = queue[i]
      setQueue(prev => prev.map((q, idx) => idx === i ? { ...q, status: 'running' } : q))

      // Reset per-file progress UI
      setLogs([])
      setProgress(0)
      setIsProgAnimating(true)
      currentStepRef.current = -1
      setSteps(Array(5).fill('pending') as StepState[])
      setElapsed(0)
      if (elapsedTimerRef.current) clearInterval(elapsedTimerRef.current)
      elapsedTimerRef.current = setInterval(() => setElapsed(prev => prev + 1), 1000)

      appendLog(`INFO  [${i + 1}/${queue.length}] ${item.file.name} 업로드 중...`)

      let uploadOk = true
      try {
        const data = await analyzeFile(item.file, provider, apiKey) as { error?: string }
        if (data.error) {
          appendLog(`WARN  ${data.error}`)
          uploadOk = false
        } else {
          appendLog('OK    업로드 성공 — 분석 시작')
        }
      } catch (e) {
        appendLog(`WARN  서버 연결 실패: ${e instanceof Error ? e.message : ''}`)
        uploadOk = false
      }

      if (!uploadOk) {
        setIsProgAnimating(false)
        setQueue(prev => prev.map((q, idx) => idx === i ? { ...q, status: 'error', errorMessage: '업로드 실패' } : q))
        setShowResult(true)
        continue
      }

      const outcome = await pollUntilSettled()

      if (outcome.kind === 'cancelled') {
        setIsProgAnimating(false)
        setQueue(prev => prev.map((q, idx) => idx === i ? { ...q, status: 'error', errorMessage: '취소됨' } : q))
        setShowResult(true)
        break
      } else if (outcome.kind === 'done') {
        setIsProgAnimating(false)
        // Reading /result resets the backend's global status to "idle", which is
        // required before the next file's /analyze call will be accepted.
        await fetchResultForItem(i)
      } else {
        setIsProgAnimating(false)
        appendLog(outcome.apiKeyError ? 'WARN  API 키 검증 실패' : 'WARN  분석 중 오류 발생')
        setQueue(prev => prev.map((q, idx) => idx === i
          ? { ...q, status: 'error', errorMessage: outcome.apiKeyError ? 'API 키 검증 실패' : '분석 중 오류 발생' }
          : q))
        setShowResult(true)
        if (outcome.apiKeyError) {
          setShowApiKeyErrorModal(true)
          abortReasonRef.current = 'apikey'
          cancelRequestedRef.current = true
          break
        }
        // Non-API-key failure only affects this file — keep going.
      }
    }

    setQueue(prev => prev.map(q => q.status === 'pending' ? { ...q, status: 'skipped' } : q))
    stopTimers()
    setIsProgAnimating(false)
    setIsRunning(false)
    setCurrentIndex(-1)
    // Cast (not just annotate): cancelScan mutates this ref from a separate closure,
    // which TS's control-flow narrowing for startScan can't see, so it infers this
    // read as 'apikey' | null and would otherwise reject the 'cancel' comparison below.
    const abortReason = abortReasonRef.current as 'cancel' | 'apikey' | null
    setScanStatus(
      abortReason === 'cancel' ? 'idle' :
      abortReason === 'apikey' ? 'error' :
      'done'
    )
  }

  const cancelScan = () => {
    cancelRequestedRef.current = true
    abortReasonRef.current = 'cancel'
    appendLog('WARN  사용자에 의해 취소됨 — 남은 파일은 처리되지 않습니다')
  }

  // ─── Derived UI values ─────────────────────────────────────────────────────

  const statusInfo = {
    idle:    { cls: 'bg-slate-100 text-slate-500 border border-slate-200', text: '대기 중', tag: 'IDLE',    blink: false },
    running: { cls: 'bg-blue-50 text-blue-700 border border-blue-200',     text: '분석 중', tag: 'RUNNING', blink: true  },
    done:    { cls: 'bg-green-50 text-green-700 border border-green-200',   text: '완료',   tag: 'DONE',    blink: false },
    error:   { cls: 'bg-slate-100 text-slate-500 border border-slate-200', text: '오류',   tag: 'ERROR',   blink: false },
  }[scanStatus]

  const dropZoneCls = cn(
    'border-2 border-dashed rounded-[10px] bg-[#f8fbff] transition-all cursor-pointer text-center px-5 py-10',
    'border-[#c7d9f0] hover:border-blue-400 hover:bg-blue-50',
    queue.length > 0 && 'border-solid border-green-400 bg-green-50 hover:border-green-400 hover:bg-green-50',
    dropZoneError && 'border-red-400',
    isDragOver  && 'border-blue-400 bg-blue-50',
    isRunning   && 'pointer-events-none opacity-70',
  )

  const finishedItems = queue.filter(q => q.status === 'done' || q.status === 'error')

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#f1f3f6] text-[#1e293b] text-[13px]" style={{ fontFamily: "'Inter', system-ui, sans-serif" }}>

      {/* ════ API 키 검증 실패 모달 ════ */}
      {showApiKeyErrorModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
          <div className="bg-white rounded-xl shadow-[0_4px_24px_rgba(0,0,0,.12)] border border-[#e8edf2] p-6 w-[300px] animate-in fade-in zoom-in-95 duration-150">
            <div className="flex flex-col items-center text-center gap-3">
              <div className="w-11 h-11 rounded-full bg-[#fef2f2] border border-[#fecaca] flex items-center justify-center">
                <svg width="20" height="20" fill="none" stroke="#dc2626" strokeWidth="2.2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                </svg>
              </div>
              <div>
                <p className="text-[14px] font-bold text-[#0f172a] mb-1">API 키 검증 실패</p>
                <p className="text-[12px] text-[#64748b] leading-relaxed">입력하신 API 키를 확인하고<br/>다시 시도해주세요.</p>
              </div>
              <button
                className="mt-1 w-full bg-[#1d4ed8] hover:bg-[#1e40af] text-white text-[13px] font-semibold py-2 rounded-[7px] transition-colors"
                onClick={() => setShowApiKeyErrorModal(false)}
              >
                확인
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ════ Navbar ════ */}
      <nav className="bg-white border-b border-[#e5e9f0] h-[52px] px-[22px] sticky top-0 z-50 shadow-[0_1px_3px_rgba(0,0,0,.04)] flex items-center justify-between">
        <div className="flex items-center gap-7">
          <div className="flex items-center">
            <img src={isDark ? '/apkinsight_dark.png' : '/apkinsight.png'} className="w-[50px] h-[50px] rounded-[7px] object-contain flex-shrink-0" alt="APKInsight"/>
            <span className="text-[14px] font-extrabold text-[#0f172a] tracking-tight">
              APK<span className="text-[#1d4ed8]">Insight</span>
            </span>
          </div>
          <div className="flex items-center gap-0.5">
            <Link to="/"          className="px-[13px] py-[6px] rounded-[6px] text-[13px] font-semibold text-[#1d4ed8] bg-[#e8f0fe] no-underline">스캔</Link>
            <Link to="/dashboard" className="px-[13px] py-[6px] rounded-[6px] text-[13px] font-medium text-[#64748b] hover:bg-slate-100 hover:text-[#334155] no-underline transition-colors">대시보드</Link>
            <Link to="/scans"     className="px-[13px] py-[6px] rounded-[6px] text-[13px] font-medium text-[#64748b] hover:bg-slate-100 hover:text-[#334155] no-underline transition-colors">최근 분석</Link>
            <Link to="/analysis"  className="px-[13px] py-[6px] rounded-[6px] text-[13px] font-medium text-[#64748b] hover:bg-slate-100 hover:text-[#334155] no-underline transition-colors">상세 분석</Link>
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

      {/* ════ Main ════ */}
      <div className="max-w-[680px] mx-auto mt-10 px-5 pb-10">

        {/* Page header */}
        <div className="mb-7">
          <h1 className="text-[22px] font-extrabold text-[#0f172a] mb-1.5 tracking-tight">APK 보안 분석</h1>
          <p className="text-[13px] text-[#64748b]">APK 파일을 업로드하면 정적 분석 후 AI가 취약점을 탐지합니다</p>
        </div>

        {/* ── Card 01: 파일 업로드 ── */}
        <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_12px_rgba(0,0,0,.04)] border border-[#e8edf2] p-6 mb-4">
          <div className="text-[11px] font-bold text-[#94a3b8] tracking-[.12em] uppercase pb-3.5 border-b border-[#f1f5f9] mb-[18px]">
            01 — 파일 업로드
          </div>

          {/* Drop zone */}
          <div
            className={dropZoneCls}
            onClick={() => { if (!isRunning) fileInputRef.current?.click() }}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
          >
            <input ref={fileInputRef} type="file" accept=".apk,.xapk" multiple className="hidden" onChange={onFileSelect}/>
            {queue.length === 0 ? (
              <div>
                <div className="w-14 h-14 bg-blue-50 rounded-xl flex items-center justify-center mx-auto mb-3.5 border border-blue-100">
                  <svg width="26" height="26" fill="none" stroke="#3b82f6" strokeWidth="1.8" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
                  </svg>
                </div>
                <p className="text-[14px] font-semibold text-[#334155] mb-1">APK 파일을 드래그하거나 클릭하세요</p>
                <p className="text-[12px] text-[#94a3b8]">여러 개 선택 가능 · 지원 형식: .apk · .xapk &nbsp;·&nbsp; 최대 200 MB</p>
              </div>
            ) : (
              <div>
                <div className="w-[52px] h-[52px] bg-green-50 rounded-xl flex items-center justify-center mx-auto mb-3 border border-green-100">
                  <svg width="24" height="24" fill="none" stroke="#22c55e" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                </div>
                <p className="text-[14px] font-semibold text-[#15803d] mb-[3px]">{queue.length}개 파일 선택됨</p>
                <p className="text-[11px] text-[#94a3b8] mt-1.5">클릭하거나 드롭하여 파일 추가</p>
              </div>
            )}
          </div>

          {/* Queue list */}
          {queue.length > 0 && (
            <div className="mt-3 space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {queue.map((item, idx) => {
                const s = item.status
                return (
                  <div
                    key={item.id}
                    className={cn(
                      'flex items-center gap-2.5 px-3 py-2 rounded-[7px] border text-[12px]',
                      s === 'running' ? 'border-blue-200 bg-blue-50'
                      : s === 'done'   ? 'border-green-200 bg-green-50'
                      : s === 'error'  ? 'border-red-200 bg-red-50'
                      : s === 'skipped'? 'border-[#e2e8f0] bg-[#f8fafc] opacity-60'
                                       : 'border-[#e2e8f0] bg-white',
                    )}
                  >
                    <span
                      className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 text-[10px] font-bold"
                      style={{
                        background: s === 'done' ? '#dcfce7' : s === 'error' ? '#fee2e2' : s === 'running' ? '#dbeafe' : '#f1f5f9',
                        color:      s === 'done' ? '#16a34a' : s === 'error' ? '#dc2626' : s === 'running' ? '#1d4ed8' : '#94a3b8',
                      }}
                    >
                      {s === 'running' ? (
                        <span className="w-3 h-3 border-2 border-blue-200 border-t-blue-500 rounded-full animate-spin inline-block" />
                      ) : s === 'done' ? '✓' : s === 'error' ? '!' : s === 'skipped' ? '–' : idx + 1}
                    </span>
                    <span className="flex-1 min-w-0 truncate font-medium text-[#334155]">{item.file.name}</span>
                    <span className="text-[#94a3b8] flex-shrink-0">{(item.file.size / 1024 / 1024).toFixed(1)} MB</span>
                    {item.errorMessage && (
                      <span className="text-red-600 flex-shrink-0">{item.errorMessage}</span>
                    )}
                    {s === 'pending' && !isRunning && (
                      <button
                        className="text-[#94a3b8] hover:text-red-600 flex-shrink-0 px-1"
                        onClick={(e) => { e.stopPropagation(); removeFromQueue(item.id) }}
                      >
                        ✕
                      </button>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* LLM + API key row */}
          <div className="mt-4 flex gap-2.5 items-end flex-wrap">
            <div className="flex-1 min-w-[130px]">
              <label className="block text-[11px] font-semibold text-[#64748b] tracking-[.06em] mb-[5px]">LLM PROVIDER</label>
              <select
                className="border border-[#d1dbe8] rounded-[7px] px-3 py-2 text-[13px] outline-none bg-white text-[#1e293b] w-full focus:border-blue-400 focus:ring-2 focus:ring-blue-100 transition-all"
                value={llmProvider}
                onChange={onLLMChange}
              >
                <option value="local">Ollama (로컬)</option>
                <option value="gemini">Gemini</option>
              </select>
            </div>
            <div className="flex-[2] min-w-[170px]">
              <label className="block text-[11px] font-semibold text-[#64748b] tracking-[.06em] mb-[5px]">
                {llmProvider === 'gemini' ? 'GEMINI API KEY' : 'API KEY'}
              </label>
              <div className="relative">
                <svg className="absolute left-[10px] top-1/2 -translate-y-1/2 pointer-events-none" width="13" height="13" fill="none" stroke="#94a3b8" strokeWidth="2" viewBox="0 0 24 24">
                  <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
                </svg>
                <input
                  type="password"
                  className={cn(
                    'border rounded-[7px] pl-8 pr-3 py-2 text-[13px] outline-none bg-white text-[#1e293b] w-full placeholder:text-[#94a3b8] transition-all',
                    apiKeyError
                      ? 'border-red-400 ring-2 ring-red-100'
                      : 'border-[#d1dbe8] focus:border-blue-400 focus:ring-2 focus:ring-blue-100',
                  )}
                  placeholder={llmProvider === 'gemini' ? 'AIzaSy... 또는 AQ....' : '서버 API 키를 입력하세요'}
                  value={apiKey}
                  onChange={onApiKeyInput}
                />
              </div>
              {apiKeyError && (
                <p className="text-[11px] text-red-600 mt-[3px]">AIzaSy 또는 AQ. 로 시작해야 합니다</p>
              )}
            </div>
          </div>

          {/* RUN + status badge */}
          <div className="mt-3 flex items-center justify-end gap-2.5">
            <div className={cn('inline-flex items-center gap-[5px] px-2.5 py-1 rounded-[5px] text-[11px] font-semibold tracking-[.04em]', statusInfo.cls)}>
              <span className={cn('w-1.5 h-1.5 rounded-full bg-current flex-shrink-0', statusInfo.blink && 'animate-pulse')}/>
              {statusInfo.text}
              <span className="opacity-55 ml-0.5">{statusInfo.tag}</span>
            </div>
            <Button
              className="bg-[#1d4ed8] hover:bg-[#1e40af] text-white text-[13px] font-semibold px-6 py-[9px] h-auto gap-1.5 disabled:bg-[#93c5fd] disabled:cursor-not-allowed"
              disabled={isRunning}
              onClick={startScan}
            >
              RUN
            </Button>
          </div>
        </div>

        {/* ── Card 02: 진행 로그 ── */}
        {showLog && (
          <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_12px_rgba(0,0,0,.04)] border border-[#e8edf2] p-6 mb-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div className="flex items-center justify-between mb-3.5">
              <div className="text-[11px] font-bold text-[#94a3b8] tracking-[.12em] uppercase">
                02 — 진행 로그
                {isRunning && currentIndex >= 0 && queue[currentIndex] && (
                  <span className="ml-2 normal-case font-semibold text-[#1d4ed8]">
                    ({currentIndex + 1}/{queue.length}) {queue[currentIndex].file.name}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[11px] text-[#94a3b8] tabular-nums">{formatElapsed(elapsed)}</span>
                <button
                  className="bg-[#fef2f2] text-[#dc2626] border border-[#fecaca] rounded-[6px] px-3 py-[5px] text-[12px] font-semibold hover:bg-[#fee2e2] transition-colors"
                  onClick={cancelScan}
                >
                  취소
                </button>
              </div>
            </div>

            {/* Progress bar */}
            <div className="h-[5px] bg-[#f1f5f9] rounded-full overflow-hidden mb-4">
              <div
                className={cn(
                  'h-full rounded-full bg-gradient-to-r from-[#1d4ed8] to-[#3b82f6] transition-[width] duration-500 ease-out',
                  isProgAnimating && 'animate-pulse',
                )}
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* Step rows */}
            <div className="space-y-2 mb-3.5">
              {STEPS.map((step, idx) => {
                const state = steps[idx]
                const isActive = state === 'active'
                const isDone   = state === 'done'
                return (
                  <div
                    key={idx}
                    className={cn(
                      'flex items-center gap-3 px-3.5 py-3 rounded-[8px] border transition-all duration-300',
                      isActive ? 'border-blue-200 bg-blue-50'
                      : isDone ? 'border-green-200 bg-green-50'
                               : 'border-[#f1f5f9] bg-[#fafafa]',
                    )}
                  >
                    {/* Step icon */}
                    <div
                      className={cn(
                        'w-8 h-8 rounded-[6px] flex items-center justify-center flex-shrink-0 text-[12px] font-bold',
                        isActive ? 'bg-blue-50 border-[1.5px] border-blue-400 text-blue-400'
                        : isDone ? 'bg-green-50 border-[1.5px] border-green-400 text-green-700'
                                 : 'bg-[#f1f5f9] border-[1.5px] border-[#e2e8f0] text-[#94a3b8]',
                      )}
                    >
                      {isDone ? (
                        <svg width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
                        </svg>
                      ) : isActive ? (
                        <div className="w-4 h-4 border-2 border-blue-200 border-t-blue-500 rounded-full animate-spin"/>
                      ) : (
                        STEP_ICONS[idx]
                      )}
                    </div>

                    {/* Step text */}
                    <div className="flex-1 min-w-0">
                      <p className="text-[13px] font-semibold text-[#334155] mb-[1px]">{step.title}</p>
                      <p className="text-[11px] text-[#94a3b8]">{step.desc}</p>
                    </div>

                    {/* Step status */}
                    <div className="text-[11px] whitespace-nowrap">
                      {isDone   ? <span className="text-green-700 font-semibold">완료</span>
                      : isActive ? <span className="text-blue-500 font-semibold">분석 중...</span>
                                 : <span className="text-[#94a3b8]">대기 중</span>}
                    </div>
                  </div>
                )
              })}
            </div>

            {/* Terminal log */}
            <div
              ref={logRef}
              className="bg-[#f8fafc] rounded-[8px] p-3.5 text-[12px] text-[#334155] h-44 overflow-y-auto border border-[#e2e8f0] leading-7"
              style={{ fontFamily: "'Cascadia Code', Consolas, monospace" }}
            >
              {logs.length === 0 ? (
                <span className="text-[#94a3b8]">-- 스캔 시작 대기 중 --</span>
              ) : (
                logs.map((entry, i) => (
                  <div key={i}>
                    <span className="text-[#cbd5e0] mr-2">&gt;</span>
                    <span style={{ color: entry.color }}>{entry.text}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* ── Card 03: 분석 결과 ── */}
        {showResult && (
          <div className="bg-white rounded-xl shadow-[0_1px_3px_rgba(0,0,0,.07),0_4px_12px_rgba(0,0,0,.04)] border border-[#e8edf2] p-6 mb-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div className="flex items-center justify-between pb-3.5 border-b border-[#f1f5f9] mb-[18px]">
              <div className="text-[11px] font-bold text-[#94a3b8] tracking-[.12em] uppercase">03 — 분석 결과</div>
              <span className="text-[11px] text-[#94a3b8]">
                {queue.filter(q => q.status === 'done').length}/{queue.length} 완료
              </span>
            </div>

            <div className="space-y-4">
              {finishedItems.map(item => (
                <div key={item.id} className="border border-[#e8edf2] rounded-[10px] p-4">
                  {/* APK name + status */}
                  <div className="flex gap-2.5 flex-wrap mb-3.5 items-center">
                    <div className="flex-[2] bg-[#f8fafc] border border-[#e2e8f0] rounded-[8px] p-[11px] flex items-center gap-2.5 min-w-[160px]">
                      <svg width="14" height="14" fill="none" stroke="#3b82f6" strokeWidth="2" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/>
                      </svg>
                      <span className="text-[12px] font-semibold text-[#334155] truncate">{item.file.name}</span>
                    </div>
                    {item.status === 'error' ? (
                      <div className="bg-red-50 border border-red-200 rounded-[8px] px-4 py-[11px] text-center">
                        <p className="text-[12px] font-semibold text-red-600">{item.errorMessage ?? '분석 실패'}</p>
                      </div>
                    ) : (
                      <div className="bg-[#f8fafc] border border-[#e2e8f0] rounded-[8px] px-4 py-[11px] text-center">
                        <p className="text-[10px] text-[#94a3b8] font-semibold tracking-[.04em] mb-0.5">자체 코드</p>
                        <p className="text-[16px] font-extrabold text-[#334155]">{item.result?.ownCount ?? 0}건</p>
                      </div>
                    )}
                  </div>

                  {item.result && (
                    <>
                      {/* Third-party count */}
                      <div className="mb-3.5">
                        <div className="bg-blue-50 border border-blue-200 rounded-[8px] px-4 py-[9px] inline-flex items-center gap-2">
                          <span className="text-[12px] font-semibold text-[#1d4ed8]">써드파티 라이브러리</span>
                          <span className="text-[17px] font-extrabold text-[#1d4ed8]">{item.result.thirdPartyCount}</span>
                          <span className="text-[12px] text-blue-400">개</span>
                        </div>
                      </div>

                      {/* Severity boxes */}
                      <div>
                        <p className="text-[11px] font-semibold text-[#64748b] tracking-[.04em] mb-2.5">자체 코드 결과</p>
                        <div className="flex gap-2 flex-wrap">
                          <div className="flex-1 min-w-[68px] rounded-[8px] p-3 text-center bg-[#fff7ed] border border-[#fed7aa]">
                            <p className="text-[22px] font-extrabold text-[#ea580c] leading-none">{item.result.vulnCounts.high}</p>
                            <p className="text-[10px] text-[#fb923c] font-semibold mt-[3px] tracking-[.03em]">HIGH</p>
                          </div>
                          <div className="flex-1 min-w-[68px] rounded-[8px] p-3 text-center bg-[#fefce8] border border-[#fef08a]">
                            <p className="text-[22px] font-extrabold text-[#ca8a04] leading-none">{item.result.vulnCounts.medium}</p>
                            <p className="text-[10px] text-[#facc15] font-semibold mt-[3px] tracking-[.03em]">MEDIUM</p>
                          </div>
                          <div className="flex-1 min-w-[68px] rounded-[8px] p-3 text-center bg-[#f0fdf4] border border-[#bbf7d0]">
                            <p className="text-[22px] font-extrabold text-[#16a34a] leading-none">{item.result.vulnCounts.low}</p>
                            <p className="text-[10px] text-[#4ade80] font-semibold mt-[3px] tracking-[.03em]">LOW</p>
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              ))}
            </div>

            {/* Dashboard link */}
            <div className="mt-[18px] pt-4 border-t border-[#f1f5f9] flex items-center justify-between gap-4">
              <p className="text-[12px] text-[#94a3b8]">분석이 완료되었습니다. 대시보드에서 상세 결과를 확인하세요.</p>
              <Button
                className="bg-[#1d4ed8] hover:bg-[#1e40af] text-white text-[13px] font-semibold gap-1.5 shrink-0"
                onClick={() => navigate('/dashboard')}
              >
                <svg width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                </svg>
                대시보드에서 보기 →
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
