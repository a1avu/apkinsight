import { useState, useEffect } from 'react'

export default function DarkModeToggle() {
  const [isDark, setIsDark] = useState(() => {
    try { return localStorage.getItem('apkinsight_theme') === 'dark' } catch { return false }
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark-mode', isDark)
    try { localStorage.setItem('apkinsight_theme', isDark ? 'dark' : 'light') } catch { /* */ }
  }, [isDark])

  return (
    <button
      id="dark-mode-toggle"
      onClick={() => setIsDark(d => !d)}
      title="다크 모드 전환"
      aria-label="다크 모드 전환"
    >
      <span className="dm-icon-sun">☀️</span>
      <span className="dm-icon-moon">🌙</span>
      <span className="dm-thumb" />
    </button>
  )
}
