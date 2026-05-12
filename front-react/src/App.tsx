import { Routes, Route } from 'react-router-dom'
import UploadScan        from '@/pages/UploadScan'
import Dashboard         from '@/pages/Dashboard'
import DetailedAnalysis  from '@/pages/DetailedAnalysis'
import RecentScans       from '@/pages/RecentScans'

export default function App() {
  return (
    <Routes>
      <Route path="/"          element={<UploadScan />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/analysis"  element={<DetailedAnalysis />} />
      <Route path="/scans"     element={<RecentScans />} />
    </Routes>
  )
}
