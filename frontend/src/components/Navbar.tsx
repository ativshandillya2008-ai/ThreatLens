import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Shield,
  Inbox,
  FileText,
  Radio,
  LogOut,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  Bot,
  Globe,
} from 'lucide-react'
import { api, UserInfo, WatchSetupResponse } from '../api/client'

interface Props {
  user: UserInfo
  onLogout: () => void
}

export default function Navbar({ user, onLogout }: Props) {
  const location = useLocation()
  const [watchLoading, setWatchLoading] = useState(false)
  const [watchResult, setWatchResult] = useState<WatchSetupResponse | null>(null)
  const [showWatchModal, setShowWatchModal] = useState(false)
  const [watchError, setWatchError] = useState('')

  const handleSetupWatch = async () => {
    setWatchLoading(true)
    setWatchError('')
    try {
      const res = await api.gmail.setupWatch()
      setWatchResult(res)
      setShowWatchModal(true)
    } catch (err) {
      setWatchError(String(err))
      setShowWatchModal(true)
    } finally {
      setWatchLoading(false)
    }
  }

  const navItems = [
    { to: '/inbox', label: 'Inbox', icon: Inbox },
    { to: '/agent', label: 'AI Agent', icon: Bot, badge: 'Claude-like' },
    { to: '/audit', label: 'Forensic Audit', icon: FileText },
    { to: '/map', label: 'Threat Map', icon: Globe, badge: 'Live Radar' },
  ]

  return (
    <>
      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-md shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          {/* Logo & Navigation */}
          <div className="flex items-center gap-6">
            <Link to="/inbox" className="flex items-center gap-3 group">
              <div className="h-9 w-9 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-sm group-hover:bg-blue-700 transition-colors">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-base tracking-tight text-slate-900">ThreatLens</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold font-mono">
                    SECURITY
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  <span>Threat Engine Active</span>
                </div>
              </div>
            </Link>

            {/* Nav Tabs */}
            <nav className="hidden md:flex items-center gap-1.5 ml-2">
              {navItems.map(({ to, label, icon: Icon, badge }) => {
                const isActive = location.pathname === to
                return (
                  <Link
                    key={to}
                    to={to}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-blue-50 text-blue-700 border border-blue-200'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    }`}
                  >
                    <Icon className="h-4 w-4 text-blue-600" />
                    <span>{label}</span>
                    {badge && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded-full bg-blue-100 text-blue-800 font-semibold font-mono">
                        {badge}
                      </span>
                    )}
                  </Link>
                )
              })}
            </nav>
          </div>

          {/* Right Utilities */}
          <div className="flex items-center gap-3">
            {/* Setup Real-time Gmail Watch */}
            <button
              onClick={handleSetupWatch}
              disabled={watchLoading}
              title="Configure Gmail Cloud Pub/Sub Watch"
              className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-50 border border-slate-200 hover:border-blue-300 text-slate-700 hover:text-blue-700 transition-all disabled:opacity-50 shadow-sm"
            >
              <Radio className={`h-3.5 w-3.5 text-blue-600 ${watchLoading ? 'animate-spin' : ''}`} />
              <span>{watchLoading ? 'Syncing...' : 'Real-Time Watch'}</span>
            </button>

            {/* API Docs Link */}
            <a
              href="/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden lg:inline-flex items-center gap-1 text-xs text-slate-500 hover:text-blue-700 px-2.5 py-1.5 rounded-lg hover:bg-slate-100 transition-colors"
            >
              <span>API Docs</span>
              <ExternalLink className="h-3 w-3" />
            </a>

            {/* User Profile Pill */}
            <div className="flex items-center gap-2.5 pl-2 border-l border-slate-200">
              {user.picture ? (
                <img
                  src={user.picture}
                  alt={user.name || user.email}
                  className="h-8 w-8 rounded-full border border-slate-200 object-cover"
                />
              ) : (
                <div className="h-8 w-8 rounded-full bg-blue-50 border border-blue-200 flex items-center justify-center text-xs font-bold text-blue-700">
                  {user.email.charAt(0).toUpperCase()}
                </div>
              )}
              <div className="hidden sm:block text-left">
                <div className="text-xs font-semibold text-slate-900 truncate max-w-[130px]">
                  {user.name || user.email.split('@')[0]}
                </div>
                <div className="text-[10px] text-slate-500 truncate max-w-[130px]">
                  {user.email}
                </div>
              </div>

              {/* Logout */}
              <button
                onClick={onLogout}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-slate-100 transition-colors"
                title="Sign out"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Gmail Watch Setup Modal */}
      {showWatchModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center gap-3">
              {watchError ? (
                <AlertCircle className="h-6 w-6 text-rose-600 flex-shrink-0" />
              ) : (
                <CheckCircle2 className="h-6 w-6 text-emerald-600 flex-shrink-0" />
              )}
              <h3 className="text-sm font-bold text-slate-900">
                {watchError ? 'Gmail Watch Setup' : 'Real-Time Protection Status'}
              </h3>
            </div>

            {watchError ? (
              <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-xl p-3 leading-relaxed">
                {watchError}
                <div className="mt-2 text-[11px] text-slate-500">
                  Ensure `PUBSUB_TOPIC` is defined in `.env` and Gmail API push permissions are granted.
                </div>
              </div>
            ) : (
              <div className="space-y-3 text-xs text-slate-700">
                <p>
                  Gmail Push Notifications (Cloud Pub/Sub) watch hook has been registered successfully.
                </p>
                <div className="bg-slate-50 rounded-xl p-3 border border-slate-200 font-mono text-[11px] space-y-1.5 text-slate-800">
                  <div>
                    <span className="text-slate-500">Status: </span>
                    <span className="text-emerald-700 font-semibold">{watchResult?.status || 'Active'}</span>
                  </div>
                  {watchResult?.watch?.historyId && (
                    <div>
                      <span className="text-slate-500">History ID: </span>
                      <span className="text-blue-700">{watchResult.watch.historyId}</span>
                    </div>
                  )}
                  {watchResult?.watch?.expiration && (
                    <div>
                      <span className="text-slate-500">Expires: </span>
                      <span>{new Date(Number(watchResult.watch.expiration)).toLocaleString()}</span>
                    </div>
                  )}
                </div>
                <p className="text-[11px] text-slate-500">
                  ThreatLens will automatically renew the watch every 6 days in the background.
                </p>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowWatchModal(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-xl text-xs font-semibold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
