import { useCallback, useEffect, useRef, useState } from 'react'
import {
  RefreshCw,
  Search,
  X,
  Mail,
  Inbox as InboxIcon,
  Shield,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { api, EmailSummary, UserInfo } from '../api/client'
import EmailRow from '../components/EmailRow'
import Navbar from '../components/Navbar'
import ThreatStatsCards from '../components/ThreatStatsCards'

interface Props {
  user: UserInfo
  onLogout: () => void
}

export default function InboxPage({ user, onLogout }: Props) {
  const [emails, setEmails] = useState<EmailSummary[]>([])
  const [currentPage, setCurrentPage] = useState(1)
  const [discoveredPages, setDiscoveredPages] = useState<number[]>([1])
  const [nextPageToken, setNextPageToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [submittedQuery, setSubmittedQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [isScanning, setIsScanning] = useState(false)
  const [unscoredCount, setUnscoredCount] = useState(0)
  const [statsTrigger, setStatsTrigger] = useState(0)

  // Token cache: index 0 is page 1 (null token), index 1 is page 2, etc.
  const pageTokensRef = useRef<(string | null)[]>([null])
  const currentPageRef = useRef(1)

  const fetchPage = useCallback(
    async (targetPage: number = 1, isBackgroundSync: boolean = false) => {
      if (!isBackgroundSync) {
        setLoading(true)
      }
      setError('')

      try {
        const token = pageTokensRef.current[targetPage - 1] ?? undefined
        const data = await api.gmail.messages({
          q: submittedQuery || undefined,
          max_results: 25,
          page_token: token || undefined,
        })

        const msgs = data.messages || []
        setEmails(msgs)
        setNextPageToken(data.nextPageToken || null)

        // If next page token exists, save it for targetPage + 1
        if (data.nextPageToken) {
          pageTokensRef.current[targetPage] = data.nextPageToken
          setDiscoveredPages(prev => {
            const pages = new Set([...prev, targetPage, targetPage + 1])
            return Array.from(pages).sort((a, b) => a - b)
          })
        } else {
          // Truncate any beyond targetPage since there is no next page
          pageTokensRef.current = pageTokensRef.current.slice(0, targetPage)
          setDiscoveredPages(prev => {
            const pages = new Set([...prev.filter(p => p <= targetPage), targetPage])
            return Array.from(pages).sort((a, b) => a - b)
          })
        }

        currentPageRef.current = targetPage
        setCurrentPage(targetPage)

        const unscored = msgs.filter(m => !m.threat.severity).length
        setUnscoredCount(unscored)
        const scanningActive = Boolean(data.scanning || unscored > 0)
        setIsScanning(scanningActive)
        setStatsTrigger(prev => prev + 1)
      } catch (e) {
        setError(String(e))
      } finally {
        if (!isBackgroundSync) {
          setLoading(false)
        }
      }
    },
    [submittedQuery]
  )

  // Fetch initial page on mount and whenever search query changes
  useEffect(() => {
    pageTokensRef.current = [null]
    currentPageRef.current = 1
    setCurrentPage(1)
    setDiscoveredPages([1])
    setNextPageToken(null)
    fetchPage(1)
  }, [fetchPage, submittedQuery])

  // Periodic polling: refreshes the CURRENT page without resetting to page 1
  useEffect(() => {
    const intervalMs = isScanning ? 3_000 : 30_000
    const interval = setInterval(() => {
      fetchPage(currentPageRef.current, true)
    }, intervalMs)
    return () => clearInterval(interval)
  }, [fetchPage, isScanning])

  const handlePageChange = (newPage: number) => {
    if (newPage < 1 || newPage === currentPage || loading) return
    fetchPage(newPage)
    window.scrollTo({ top: 180, behavior: 'smooth' })
  }

  const handleTriggerScan = async () => {
    setIsScanning(true)
    try {
      await api.gmail.scan(25)
      await fetchPage(currentPageRef.current, false)
    } catch (e) {
      console.error('Scan trigger error:', e)
    }
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (query === submittedQuery) {
      pageTokensRef.current = [null]
      currentPageRef.current = 1
      setCurrentPage(1)
      setDiscoveredPages([1])
      fetchPage(1)
    } else {
      setSubmittedQuery(query)
    }
  }

  const handleClearSearch = () => {
    setQuery('')
    setSubmittedQuery('')
  }

  const filteredEmails = emails.filter(m => {
    if (!severityFilter) return true
    return m.threat.severity === severityFilter
  })

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col selection:bg-blue-600 selection:text-white">
      <Navbar user={user} onLogout={onLogout} />

      <div className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full">
        {/* Threat Stats Summary Cards */}
        <ThreatStatsCards
          activeSeverity={severityFilter}
          onFilterSeverity={setSeverityFilter}
          refreshTrigger={statsTrigger}
        />

        {/* Action / Search Bar */}
        <div className="bg-white border border-slate-200 rounded-2xl p-4 mb-5 shadow-sm space-y-3">
          <div className="flex flex-col sm:flex-row items-center gap-3">
            {/* Search Input */}
            <form onSubmit={handleSearch} className="relative flex-1 w-full">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search subject, sender, or content (e.g. from:support, label:quarantine)..."
                className="w-full bg-slate-50 border border-slate-300 rounded-xl pl-10 pr-9 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:bg-white transition-all font-sans"
              />
              {query && (
                <button
                  type="button"
                  onClick={handleClearSearch}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </form>

            <div className="flex items-center gap-2 w-full sm:w-auto justify-between sm:justify-end">
              {/* Severity Dropdown */}
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="bg-slate-50 border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-700 focus:outline-none focus:border-blue-600 transition-all font-medium"
              >
                <option value="">All Severities</option>
                <option value="HIGH">High Threat (Quarantined)</option>
                <option value="MEDIUM">Suspicious Only</option>
                <option value="LOW">Verified Safe</option>
              </select>

              {/* Scan Inbox Button */}
              <button
                onClick={handleTriggerScan}
                disabled={isScanning || loading}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-xs font-semibold text-white shadow-sm transition-all disabled:opacity-60"
                title="Scan inbox messages with AI Threat Engine"
              >
                <Shield className={`h-3.5 w-3.5 ${isScanning ? 'animate-pulse' : ''}`} />
                <span>{isScanning ? 'Scanning...' : 'Scan Inbox'}</span>
              </button>

              {/* Refresh Button */}
              <button
                onClick={() => fetchPage(currentPageRef.current)}
                disabled={loading}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-50 hover:bg-slate-100 text-xs font-semibold text-slate-700 border border-slate-200 transition-all disabled:opacity-50"
                title="Refresh current page"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-blue-600' : ''}`} />
                <span className="hidden md:inline">Refresh</span>
              </button>
            </div>
          </div>

          {/* Quick Filter Badges */}
          <div className="flex items-center gap-2 pt-1 border-t border-slate-100 text-xs flex-wrap">
            <span className="text-slate-500 text-[11px] font-medium mr-1">Filter:</span>
            {[
              { id: '', label: 'All Messages' },
              { id: 'HIGH', label: 'High Threats', color: 'text-rose-700 bg-rose-50 border-rose-200' },
              { id: 'MEDIUM', label: 'Suspicious', color: 'text-amber-700 bg-amber-50 border-amber-200' },
              { id: 'LOW', label: 'Safe', color: 'text-emerald-700 bg-emerald-50 border-emerald-200' },
            ].map(pill => {
              const active = severityFilter === pill.id
              return (
                <button
                  key={pill.id}
                  onClick={() => setSeverityFilter(pill.id)}
                  className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium border transition-all ${
                    active
                      ? 'bg-blue-600 text-white border-blue-600 shadow-sm'
                      : pill.color || 'bg-slate-100 text-slate-600 border-slate-200 hover:bg-slate-200'
                  }`}
                >
                  {pill.label}
                </button>
              )
            })}
            {submittedQuery && (
              <span className="ml-auto text-[11px] text-blue-700 font-mono bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                Filter: "{submittedQuery}"
              </span>
            )}
          </div>
        </div>

        {/* Active Scanning Status Banner */}
        {isScanning && (
          <div className="mb-4 px-4 py-3 bg-blue-50 border border-blue-200 rounded-2xl flex items-center justify-between text-xs text-blue-900 shadow-sm">
            <div className="flex items-center gap-2.5 font-medium">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-600" />
              </span>
              <span>AI Threat Engine is actively scanning and scoring messages...</span>
            </div>
            {unscoredCount > 0 ? (
              <span className="font-mono text-[11px] bg-blue-100 text-blue-800 font-semibold px-2.5 py-0.5 rounded-full border border-blue-200">
                {unscoredCount} unscored remaining
              </span>
            ) : (
              <span className="font-mono text-[11px] bg-emerald-100 text-emerald-800 font-semibold px-2.5 py-0.5 rounded-full border border-emerald-200">
                All analyzed
              </span>
            )}
          </div>
        )}

        {/* Error Notification */}
        {error && (
          <div className="mb-4 p-4 bg-rose-50 border border-rose-200 rounded-2xl text-rose-800 text-xs flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => fetchPage(currentPageRef.current)} className="underline text-rose-700 font-semibold">
              Retry
            </button>
          </div>
        )}

        {/* Email Inbox Table */}
        <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-sm">
          <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
              <Mail className="h-4 w-4 text-blue-600" />
              <span>Inbox Feed</span>
              <span className="text-slate-500 font-normal">
                (Page {currentPage} — {filteredEmails.length} {filteredEmails.length === 1 ? 'message' : 'messages'} shown)
              </span>
              {loading && emails.length > 0 && (
                <RefreshCw className="h-3 w-3 animate-spin text-blue-600 ml-1" />
              )}
            </div>
            <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
              {isScanning ? (
                <span className="flex items-center gap-1.5 text-blue-600 font-medium">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-600" />
                  </span>
                  <span>Scanning active (3s sync)</span>
                </span>
              ) : (
                <span>Auto-sync: 30s</span>
              )}
            </div>
          </div>

          {loading && emails.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
              <span className="text-xs text-slate-500 font-medium">Scanning mailbox and analyzing email security...</span>
            </div>
          ) : filteredEmails.length === 0 ? (
            <div className="text-center py-20 px-4">
              <InboxIcon className="h-10 w-10 text-slate-300 mx-auto mb-3" />
              <p className="text-sm font-semibold text-slate-800">No emails match your selection</p>
              <p className="text-xs text-slate-500 mt-1">
                {severityFilter || submittedQuery
                  ? 'Try clearing your search query or switching your severity filter.'
                  : 'Your inbox is clear or no emails have been imported yet.'}
              </p>
              {(severityFilter || submittedQuery) && (
                <button
                  onClick={() => {
                    setSeverityFilter('')
                    setQuery('')
                    setSubmittedQuery('')
                  }}
                  className="mt-4 px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 transition-colors"
                >
                  Reset all filters
                </button>
              )}
            </div>
          ) : (
            <div className="divide-y divide-slate-200">
              {filteredEmails.map(email => (
                <EmailRow key={email.id} email={email} />
              ))}
            </div>
          )}

          {/* Pagination Controls */}
          {(emails.length > 0 || currentPage > 1) && (
            <div className="px-5 py-3.5 bg-slate-50 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="text-xs text-slate-600 flex items-center gap-2 flex-wrap justify-center sm:justify-start">
                <span>
                  Page <span className="font-bold text-slate-900">{currentPage}</span>
                </span>
                <span className="text-slate-300">•</span>
                <span>
                  <span className="font-semibold text-slate-900">{filteredEmails.length}</span>{' '}
                  {filteredEmails.length === 1 ? 'message' : 'messages'} on this page
                  {filteredEmails.length !== emails.length && ` (${emails.length} total fetched)`}
                </span>
                <span className="text-slate-300">•</span>
                <span className="text-slate-500 font-mono text-[11px] bg-slate-200/60 px-2 py-0.5 rounded">
                  25 per page
                </span>
              </div>

              <div className="flex items-center gap-2">
                {/* Previous Page Button */}
                <button
                  onClick={() => handlePageChange(currentPage - 1)}
                  disabled={currentPage <= 1 || loading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:text-blue-700 hover:border-blue-300 disabled:opacity-40 disabled:hover:text-slate-700 disabled:hover:border-slate-200 transition-all shadow-sm"
                  title="Go to previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  <span>Previous</span>
                </button>

                {/* Page Number Pills */}
                <div className="flex items-center gap-1">
                  {discoveredPages
                    .filter(p => {
                      if (p === 1 || p === discoveredPages[discoveredPages.length - 1]) return true
                      if (Math.abs(p - currentPage) <= 1) return true
                      return false
                    })
                    .map((pageNum, idx, arr) => {
                      const prevPageNum = idx > 0 ? arr[idx - 1] : 0
                      const showEllipsis = idx > 0 && pageNum - prevPageNum > 1
                      return (
                        <div key={pageNum} className="flex items-center gap-1">
                          {showEllipsis && <span className="text-slate-400 text-xs px-1">...</span>}
                          <button
                            onClick={() => handlePageChange(pageNum)}
                            disabled={loading || pageNum === currentPage}
                            className={`min-w-[32px] h-7 px-2 rounded-xl text-xs font-semibold transition-all ${
                              pageNum === currentPage
                                ? 'bg-blue-600 text-white shadow-sm'
                                : 'bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 hover:text-blue-700'
                            }`}
                          >
                            {pageNum}
                          </button>
                        </div>
                      )
                    })}
                </div>

                {/* Next Page Button */}
                <button
                  onClick={() => handlePageChange(currentPage + 1)}
                  disabled={!nextPageToken || loading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-xs font-semibold text-slate-700 hover:text-blue-700 hover:border-blue-300 disabled:opacity-40 disabled:hover:text-slate-700 disabled:hover:border-slate-200 transition-all shadow-sm"
                  title={nextPageToken ? 'Go to next page' : 'No more messages'}
                >
                  <span>Next</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
