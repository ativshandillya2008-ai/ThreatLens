import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { api, UserInfo } from './api/client'
import InboxPage from './pages/InboxPage'
import LoginPage from './pages/LoginPage'
import EmailDetailPage from './pages/EmailDetailPage'
import AuditLogPage from './pages/AuditLogPage'
import AgentPage from './pages/AgentPage'
import ThreatMapPage from './pages/ThreatMapPage'

function App() {
  const [user, setUser] = useState<UserInfo | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.auth
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-screen bg-slate-50 text-slate-900 gap-4">
        <div className="relative flex items-center justify-center">
          <div className="h-14 w-14 rounded-2xl bg-blue-600 flex items-center justify-center shadow-md shadow-blue-500/20 animate-pulse">
            <Shield className="h-7 w-7 text-white" />
          </div>
          <div className="absolute -inset-2 rounded-3xl border border-blue-200 animate-spin border-t-transparent pointer-events-none" />
        </div>
        <div className="text-xs text-slate-500 font-mono tracking-wider">
          INITIALIZING THREATLENS SHIELD...
        </div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={user ? <Navigate to="/inbox" replace /> : <LoginPage />} />
        <Route
          path="/inbox"
          element={user ? <InboxPage user={user} onLogout={() => setUser(null)} initialCategory="inbox" /> : <Navigate to="/" replace />}
        />
        <Route
          path="/spam"
          element={user ? <InboxPage user={user} onLogout={() => setUser(null)} initialCategory="spam" /> : <Navigate to="/" replace />}
        />
        <Route
          path="/agent"
          element={user ? <AgentPage user={user} /> : <Navigate to="/" replace />}
        />
        <Route
          path="/email/:id"
          element={user ? <EmailDetailPage user={user} /> : <Navigate to="/" replace />}
        />
        <Route
          path="/audit"
          element={user ? <AuditLogPage user={user} /> : <Navigate to="/" replace />}
        />
        <Route
          path="/map"
          element={user ? <ThreatMapPage user={user} /> : <Navigate to="/" replace />}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
