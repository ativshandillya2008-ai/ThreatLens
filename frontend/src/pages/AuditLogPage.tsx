import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FileText,
  RefreshCw,
  Search,
  Filter,
  ArrowRight,
  Code2,
  CheckCircle2,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  UserCheck,
  Printer,
  Inbox,
  AlertTriangle,
} from 'lucide-react'
import { api, ThreatDetail, UserInfo } from '../api/client'
import ThreatBadge from '../components/ThreatBadge'
import Navbar from '../components/Navbar'
import ThreatStatsCards from '../components/ThreatStatsCards'
import ForensicReportModal from '../components/ForensicReportModal'

interface Props {
  user: UserInfo
}

export default function AuditLogPage({ user }: Props) {
  const navigate = useNavigate()
  const [threats, setThreats] = useState<ThreatDetail[]>([])
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('')
  const [senderFilter, setSenderFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)

  // Forensic Report modal state
  const [reportThreat, setReportThreat] = useState<ThreatDetail | null>(null)

  // Header inspection modal state
  const [inspectModalThreat, setInspectModalThreat] = useState<ThreatDetail | null>(null)
  const [rawHeaders, setRawHeaders] = useState<string>('')
  const [loadingHeaders, setLoadingHeaders] = useState(false)
  const [copiedHeaders, setCopiedHeaders] = useState(false)

  // Quick override modal state
  const [overrideTarget, setOverrideTarget] = useState<ThreatDetail | null>(null)
  const [overrideAction, setOverrideAction] = useState<'release' | 'confirm'>('release')
  const [overrideFolder, setOverrideFolder] = useState<'inbox' | 'spam'>('inbox')
  const [overrideReason, setOverrideReason] = useState('')
  const [overrideSubmitting, setOverrideSubmitting] = useState(false)
  const [overrideSuccess, setOverrideSuccess] = useState('')

  const fetchThreats = async () => {
    setLoading(true)
    try {
      const data = await api.threats.list({
        severity: severityFilter || undefined,
        sender: senderFilter || undefined,
        date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
        date_to: dateTo ? new Date(dateTo).toISOString() : undefined,
        page,
        page_size: pageSize,
      })
      setThreats(data.threats)
      setTotalPages(data.total_pages)
      setTotal(data.total)
    } catch (e) {
      console.error('Failed to fetch threats audit log:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchThreats()
  }, [severityFilter, page, pageSize])

  const handleApplyFilter = (e: React.FormEvent) => {
    e.preventDefault()
    setPage(1)
    fetchThreats()
  }

  const handleResetFilters = () => {
    setSeverityFilter('')
    setSenderFilter('')
    setDateFrom('')
    setDateTo('')
    setPage(1)
  }

  const handleInspectHeaders = async (threat: ThreatDetail) => {
    setInspectModalThreat(threat)
    setLoadingHeaders(true)
    setCopiedHeaders(false)
    try {
      const detail = await api.threats.get(threat.id, true)
      setRawHeaders(detail.raw_headers || '(No encrypted headers found or retention period expired)')
    } catch (err) {
      setRawHeaders(`Failed to load raw headers: ${String(err)}`)
    } finally {
      setLoadingHeaders(false)
    }
  }

  const handleCopyHeaders = () => {
    if (!rawHeaders) return
    navigator.clipboard.writeText(rawHeaders)
    setCopiedHeaders(true)
    setTimeout(() => setCopiedHeaders(false), 2000)
  }

  const handleExecuteOverride = async () => {
    if (!overrideTarget) return
    setOverrideSubmitting(true)
    try {
      await api.threats.override(overrideTarget.id, overrideAction, overrideReason, overrideFolder)
      setOverrideSuccess(`Email successfully updated & moved to ${overrideFolder === 'inbox' ? 'Gmail Inbox' : 'Gmail Spam folder'}!`)
      setTimeout(() => {
        setOverrideTarget(null)
        setOverrideSuccess('')
        setOverrideReason('')
        fetchThreats()
      }, 1200)
    } catch (err) {
      alert(`Override failed: ${String(err)}`)
    } finally {
      setOverrideSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col selection:bg-blue-600 selection:text-white">
      <Navbar user={user} onLogout={() => (window.location.href = '/')} />

      <div className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full">
        {/* Threat Stats Cards */}
        <ThreatStatsCards
          activeSeverity={severityFilter}
          onFilterSeverity={s => {
            setSeverityFilter(s)
            setPage(1)
          }}
        />

        {/* Filter Box */}
        <form onSubmit={handleApplyFilter} className="bg-white border border-slate-200 rounded-2xl p-4 mb-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
              <Filter className="h-3.5 w-3.5 text-blue-600" />
              <span>Forensic Audit Records</span>
              <span className="text-[11px] text-slate-400 font-normal">
                ({total} entries indexed)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleResetFilters}
                className="text-[11px] text-slate-500 hover:text-slate-800 transition-colors"
              >
                Reset filters
              </button>
              <button
                type="button"
                onClick={() => fetchThreats()}
                className="p-1 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors"
                title="Refresh audit log"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-blue-600' : ''}`} />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Sender filter */}
            <div>
              <label className="block text-[11px] text-slate-500 font-medium mb-1">Sender Email / Domain</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
                <input
                  type="text"
                  value={senderFilter}
                  onChange={e => setSenderFilter(e.target.value)}
                  placeholder="e.g. alert@bank.com"
                  className="w-full bg-slate-50 border border-slate-300 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600"
                />
              </div>
            </div>

            {/* Severity filter */}
            <div>
              <label className="block text-[11px] text-slate-500 font-medium mb-1">Classification</label>
              <select
                value={severityFilter}
                onChange={e => {
                  setSeverityFilter(e.target.value)
                  setPage(1)
                }}
                className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-blue-600"
              >
                <option value="">All Classifications</option>
                <option value="HIGH">High Threat (Quarantined)</option>
                <option value="MEDIUM">Suspicious Only</option>
                <option value="LOW">Verified Clean</option>
              </select>
            </div>

            {/* Date From */}
            <div>
              <label className="block text-[11px] text-slate-500 font-medium mb-1">From Date</label>
              <input
                type="date"
                value={dateFrom}
                onChange={e => setDateFrom(e.target.value)}
                className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-blue-600"
              />
            </div>

            {/* Date To */}
            <div>
              <label className="block text-[11px] text-slate-500 font-medium mb-1">To Date</label>
              <input
                type="date"
                value={dateTo}
                onChange={e => setDateTo(e.target.value)}
                className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          <div className="flex justify-end pt-1">
            <button
              type="submit"
              className="px-4 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-xs font-semibold text-white transition-colors shadow-sm"
            >
              Apply Filter
            </button>
          </div>
        </form>

        {/* Audit Log Table Container */}
        <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-sm">
          <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
              <FileText className="h-4 w-4 text-blue-600" />
              <span>Forensic Audit Log</span>
              <span className="text-slate-500 font-normal">
                (Page {page} of {totalPages || 1})
              </span>
            </div>

            <div className="flex items-center gap-3 text-xs">
              <span className="text-slate-500 text-[11px]">Rows:</span>
              <select
                value={pageSize}
                onChange={e => {
                  setPageSize(Number(e.target.value))
                  setPage(1)
                }}
                className="bg-white border border-slate-300 rounded-lg px-2 py-1 text-xs text-slate-700"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>
          </div>

          {loading ? (
            <div className="flex flex-col items-center justify-center py-20 gap-3">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
              <span className="text-xs text-slate-500 font-medium">Fetching forensic audit records...</span>
            </div>
          ) : threats.length === 0 ? (
            <div className="text-center py-20 px-4">
              <FileText className="h-10 w-10 text-slate-300 mx-auto mb-3" />
              <p className="text-sm font-semibold text-slate-800">No threat audit records match your filters</p>
              <p className="text-xs text-slate-500 mt-1">
                Records are generated as incoming emails are scanned by the pipeline.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-200">
              {threats.map(t => (
                <div
                  key={t.id}
                  className="p-4 hover:bg-slate-50 transition-colors flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                >
                  {/* Left: Badge + Subject/Sender */}
                  <div className="flex items-start gap-3.5 min-w-0 flex-1">
                    <ThreatBadge severity={t.severity} score={t.final_score} size="sm" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setReportThreat(t)}
                          className="text-xs font-semibold text-slate-900 hover:text-blue-700 truncate text-left transition-colors cursor-pointer"
                          title="View Forensic Audit Report without opening email"
                        >
                          {t.subject || '(no subject)'}
                        </button>
                        {t.quarantined && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-50 text-rose-700 border border-rose-200 font-mono font-medium">
                            QUARANTINE
                          </span>
                        )}
                        {t.detected_language && !['English', 'en', 'Unknown'].includes(t.detected_language) && (
                          <span
                            className="text-[10px] px-1.5 py-0.2 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 font-medium flex items-center gap-1"
                            title={`Detected Language: ${t.detected_language}`}
                          >
                            <span>🇮🇳</span>
                            <span>{t.detected_language.replace(/\s*\(.*?\)/, '')}</span>
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate mt-0.5">
                        Sender: <span className="text-slate-800 font-mono">{t.sender}</span>
                      </div>
                    </div>
                  </div>

                  {/* Middle: Pipeline Breakdown */}
                  <div className="flex items-center gap-2.5 text-xs flex-wrap">
                    {/* Auth Status */}
                    <div className="bg-slate-50 px-2 py-1 rounded-lg border border-slate-200 text-[11px]">
                      <span className="text-slate-500 mr-1">Auth:</span>
                      <span
                        className={
                          t.spf === 'pass' && t.dkim === 'pass'
                            ? 'text-emerald-700 font-semibold'
                            : 'text-rose-700 font-semibold'
                        }
                      >
                        SPF:{t.spf} / DKIM:{t.dkim}
                      </span>
                    </div>

                    {/* Geo Location */}
                    <div className="bg-slate-50 px-2 py-1 rounded-lg border border-slate-200 text-[11px]">
                      <span className="text-slate-500 mr-1">Origin:</span>
                      <span className="text-slate-800 font-mono">
                        {t.geo_country || 'Unknown'} {t.geo_asn ? `(${t.geo_asn})` : ''}
                      </span>
                    </div>

                    {/* AI Score */}
                    <div className="bg-slate-50 px-2 py-1 rounded-lg border border-slate-200 text-[11px]">
                      <span className="text-slate-500 mr-1">AI:</span>
                      <span className={t.llm_score > 0.5 ? 'text-rose-700 font-bold' : 'text-slate-800'}>
                        {(t.llm_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>

                  {/* Right: Actions */}
                  <div className="flex items-center gap-2 flex-shrink-0 self-end md:self-auto">
                    <button
                      onClick={() => setReportThreat(t)}
                      className="px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 transition-all shadow-2xs flex items-center gap-1.5 cursor-pointer"
                      title="View & Print Forensic Report without opening email"
                    >
                      <Printer className="h-3.5 w-3.5 text-blue-600" />
                      <span>Forensic Report</span>
                    </button>

                    <button
                      onClick={() => handleInspectHeaders(t)}
                      className="p-1.5 rounded-lg text-slate-500 hover:text-blue-700 hover:bg-slate-100 transition-colors border border-slate-200 cursor-pointer"
                      title="Inspect Decrypted RFC Headers"
                    >
                      <Code2 className="h-4 w-4" />
                    </button>

                    <button
                      onClick={() => {
                        setOverrideTarget(t)
                        setOverrideAction(t.quarantined ? 'release' : 'confirm')
                        setOverrideFolder(t.quarantined ? 'inbox' : 'spam')
                      }}
                      className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 transition-colors shadow-sm cursor-pointer"
                      title="Submit Audit Override & Move Email"
                    >
                      Override
                    </button>

                    <button
                      onClick={() => navigate(`/email/${t.message_id}`)}
                      className="p-1.5 rounded-lg text-slate-500 hover:text-blue-700 hover:bg-slate-100 transition-colors border border-slate-200 cursor-pointer"
                      title="Open Full Analysis & Mail Viewer"
                    >
                      <ArrowRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination bar */}
          {totalPages > 1 && (
            <div className="px-5 py-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between">
              <div className="text-xs text-slate-600">
                Page <span className="font-bold text-slate-900">{page}</span> of{' '}
                <span className="font-bold text-slate-900">{totalPages}</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:text-blue-700 disabled:opacity-40 transition-colors shadow-sm"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  <span>Previous</span>
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-xs font-medium text-slate-700 hover:text-blue-700 disabled:opacity-40 transition-colors shadow-sm"
                >
                  <span>Next</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Inspect Decrypted Raw RFC Headers Modal */}
      {inspectModalThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
          <div className="w-full max-w-3xl bg-white border border-slate-200 rounded-2xl p-6 shadow-2xl flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-blue-600" />
                  <span>Decrypted RFC2822 Headers</span>
                </h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Threat ID: {inspectModalThreat.id} — Subject: {inspectModalThreat.subject}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyHeaders}
                  disabled={loadingHeaders}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs font-medium text-slate-700 transition-colors"
                >
                  {copiedHeaders ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-600" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      <span>Copy Headers</span>
                    </>
                  )}
                </button>
                <button
                  onClick={() => setInspectModalThreat(null)}
                  className="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs font-semibold text-slate-700 transition-colors"
                >
                  Close
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-auto bg-slate-50 border border-slate-200 rounded-xl p-4 font-mono text-[11px] text-slate-800 leading-relaxed whitespace-pre-wrap">
              {loadingHeaders ? (
                <div className="flex items-center justify-center py-12 text-slate-500 gap-2">
                  <RefreshCw className="h-4 w-4 animate-spin text-blue-600" />
                  <span>Decrypting raw headers via Fernet key...</span>
                </div>
              ) : (
                rawHeaders
              )}
            </div>
          </div>
        </div>
      )}

      {/* Manual Override Action Modal */}
      {overrideTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-2.5">
              <UserCheck className="h-5 w-5 text-blue-600" />
              <h3 className="text-sm font-bold text-slate-900">Manual Security Override</h3>
            </div>

            <div className="text-xs text-slate-700 bg-slate-50 p-3 rounded-xl border border-slate-200 space-y-1">
              <div className="truncate">
                <span className="text-slate-500">Subject: </span>
                <span className="text-slate-900 font-semibold">{overrideTarget.subject}</span>
              </div>
              <div className="truncate">
                <span className="text-slate-500">Sender: </span>
                <span className="text-slate-800">{overrideTarget.sender}</span>
              </div>
              <div>
                <span className="text-slate-500">Status: </span>
                <span className={overrideTarget.quarantined ? 'text-rose-700 font-semibold' : 'text-emerald-700 font-semibold'}>
                  {overrideTarget.quarantined ? 'Quarantined' : 'Clean'}
                </span>
              </div>
            </div>

            {overrideSuccess ? (
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-800 text-xs flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                <span>{overrideSuccess}</span>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs text-slate-700 font-bold mb-1.5">
                    Select Target Folder & Disposition:
                  </label>
                  <div className="grid grid-cols-2 gap-2.5">
                    <button
                      type="button"
                      onClick={() => {
                        setOverrideAction('release')
                        setOverrideFolder('inbox')
                      }}
                      className={`p-3 rounded-xl text-left border transition-all cursor-pointer ${
                        overrideFolder === 'inbox'
                          ? 'bg-emerald-50 text-emerald-950 border-emerald-400 ring-2 ring-emerald-500/20 shadow-xs'
                          : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center gap-1.5">
                        <Inbox className={`h-4 w-4 ${overrideFolder === 'inbox' ? 'text-emerald-600' : 'text-slate-400'}`} />
                        <span className="font-bold text-xs">Move to Inbox</span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-1 leading-normal">
                        Remove quarantine & restore directly to user's Inbox.
                      </p>
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        setOverrideAction('confirm')
                        setOverrideFolder('spam')
                      }}
                      className={`p-3 rounded-xl text-left border transition-all cursor-pointer ${
                        overrideFolder === 'spam'
                          ? 'bg-rose-50 text-rose-950 border-rose-400 ring-2 ring-rose-500/20 shadow-xs'
                          : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center gap-1.5">
                        <AlertTriangle className={`h-4 w-4 ${overrideFolder === 'spam' ? 'text-rose-600' : 'text-slate-400'}`} />
                        <span className="font-bold text-xs">Move to Spam</span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-1 leading-normal">
                        Flag as confirmed threat & move to Spam folder.
                      </p>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-slate-600 font-medium mb-1">
                    Audited Reason (optional):
                  </label>
                  <input
                    type="text"
                    value={overrideReason}
                    onChange={e => setOverrideReason(e.target.value)}
                    placeholder="e.g. Verified sender over phone"
                    className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setOverrideTarget(null)}
                    disabled={overrideSubmitting}
                    className="px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-xs text-slate-700 transition-colors font-medium cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleExecuteOverride}
                    disabled={overrideSubmitting}
                    className="px-4 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-xs font-semibold text-white transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
                  >
                    {overrideSubmitting
                      ? 'Moving Email...'
                      : `Apply Override & Move to ${overrideFolder === 'inbox' ? 'Inbox' : 'Spam'}`}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Forensic Threat Assessment & Audit Dossier Modal */}
      {reportThreat && (
        <ForensicReportModal
          threat={reportThreat}
          onClose={() => setReportThreat(null)}
        />
      )}
    </div>
  )
}
