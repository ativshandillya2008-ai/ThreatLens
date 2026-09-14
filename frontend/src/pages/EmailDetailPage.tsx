import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Calendar, User, AlertTriangle, RefreshCw, LocateFixed, Crosshair } from 'lucide-react'
import { api, ThreatDetail, UserInfo } from '../api/client'
import ThreatInterstitial from '../components/ThreatInterstitial'
import AuditPanel from '../components/AuditPanel'
import ThreatBadge from '../components/ThreatBadge'
import Navbar from '../components/Navbar'

interface Props {
  user: UserInfo
}

export default function EmailDetailPage({ user }: Props) {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [messageData, setMessageData] = useState<{
    message: Record<string, unknown>
    threat: ThreatDetail | null
  } | null>(null)
  const [showInterstitial, setShowInterstitial] = useState(false)
  const [interstitialPassed, setInterstitialPassed] = useState(false)
  const [error, setError] = useState('')

  const fetchDetail = () => {
    if (!id) return
    setLoading(true)
    setError('')
    api.gmail
      .message(id)
      .then(data => {
        setMessageData(data as typeof messageData)
        const threat = (data as { threat: ThreatDetail | null }).threat
        if (threat?.severity === 'HIGH' && !interstitialPassed) {
          setShowInterstitial(true)
        }
      })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchDetail()
  }, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  const threat = messageData?.threat

  // Extract display headers
  const msg = messageData?.message as Record<string, unknown> | undefined
  const headers: Record<string, string> = {}
  const payload = msg?.payload as Record<string, unknown> | undefined
  const headerList = (payload?.headers as Array<{ name: string; value: string }>) ?? []
  for (const h of headerList) {
    headers[h.name.toLowerCase()] = h.value
  }

  const subject = headers['subject'] || '(no subject)'
  const from = headers['from'] || ''
  const date = headers['date'] || ''

  // Extract body — prefer text/html, fall back to text/plain
  let bodyHtml = ''
  const parts = (payload?.parts as Array<Record<string, unknown>>) ?? []

  const findBody = (mimeType: string): string => {
    for (const part of parts) {
      if (part.mimeType === mimeType) {
        const data = (part.body as Record<string, string>)?.data
        if (data) return atob(data.replace(/-/g, '+').replace(/_/g, '/'))
      }
    }
    if (payload?.mimeType === mimeType) {
      const data = (payload?.body as Record<string, string>)?.data
      if (data) return atob(data.replace(/-/g, '+').replace(/_/g, '/'))
    }
    return ''
  }

  bodyHtml = findBody('text/html')
  const bodyText = !bodyHtml ? findBody('text/plain') : ''

  const handleTrackLocation = () => {
    navigate('/map', {
      state: {
        focusEmailId: id,
        threatId: threat?.id,
        subject: subject,
        sender: from,
        lat: threat?.geo_lat,
        lon: threat?.geo_lon,
        country: threat?.geo_country,
        city: threat?.geo_hops?.[0]?.city,
        ip: threat?.geo_hops?.[0]?.ip,
      },
    })
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col selection:bg-blue-100 selection:text-blue-900 text-slate-900">
      <Navbar user={user} onLogout={() => (window.location.href = '/')} />

      {/* HIGH-threat interstitial — must be passed before email content is visible */}
      {showInterstitial && threat && (
        <ThreatInterstitial
          threat={threat}
          onProceed={() => {
            setShowInterstitial(false)
            setInterstitialPassed(true)
          }}
          onKeepQuarantined={() => navigate('/inbox')}
        />
      )}

      {/* Sub-header navigation */}
      <div className="border-b border-slate-200 bg-white/90 sticky top-16 z-20 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={() => navigate('/inbox')}
              className="p-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-600 hover:text-slate-900 transition-colors shadow-sm"
              title="Back to Inbox"
            >
              <ArrowLeft className="h-4 w-4" />
            </button>
            <div className="min-w-0">
              <div className="font-semibold text-sm text-slate-900 truncate max-w-xl">
                {subject}
              </div>
              <div className="text-[11px] text-slate-500 truncate flex items-center gap-2 mt-0.5 font-mono">
                <span>From: {from}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-shrink-0">
            <button
              onClick={handleTrackLocation}
              className="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-sm transition-all flex items-center gap-1.5"
              title="Track accurate origin location of this sender on ThreatLens radar map"
            >
              <Crosshair className="h-3.5 w-3.5 text-blue-200" />
              <span>Track Accurate Location</span>
            </button>

            {threat && (
              <ThreatBadge severity={threat.severity} score={threat.final_score} size="md" />
            )}
            <button
              onClick={fetchDetail}
              disabled={loading}
              className="p-1.5 rounded-xl bg-white border border-slate-200 text-slate-600 hover:text-slate-900 transition-colors shadow-sm"
              title="Refresh analysis"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-blue-600' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="flex-1 flex flex-col items-center justify-center py-20 gap-3">
          <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
          <span className="text-xs text-slate-500">Decrypting & inspecting email envelope...</span>
        </div>
      ) : error ? (
        <div className="flex-1 max-w-2xl mx-auto px-4 py-16 text-center">
          <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl text-rose-800 text-xs mb-4">
            {error}
          </div>
          <button
            onClick={() => navigate('/inbox')}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-xs text-white rounded-xl transition-colors shadow-sm"
          >
            Back to Inbox
          </button>
        </div>
      ) : (
        <div className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Email Content Pane (2 Columns) */}
          <div className="lg:col-span-2 space-y-4">
            {/* Metadata Card */}
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm space-y-2.5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h1 className="text-base font-bold text-slate-900 tracking-tight">{subject}</h1>
                  <div className="flex items-center gap-1.5 text-xs text-slate-600 mt-1 font-mono">
                    <User className="h-3.5 w-3.5 text-slate-400" />
                    <span>{from}</span>
                  </div>
                </div>
                <div className="text-[11px] text-slate-500 flex items-center gap-1 font-mono">
                  <Calendar className="h-3.5 w-3.5 text-slate-400" />
                  <span>{date}</span>
                </div>
              </div>

              {/* Quick Origin Location Bar */}
              <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 font-medium">Origin Hop:</span>
                  <span className="font-semibold text-slate-800">
                    {threat?.geo_country ? `${threat.geo_country}${threat.geo_hops?.[0]?.city ? ` (${threat.geo_hops[0].city})` : ''}` : 'Public IP Relay'}
                  </span>
                </div>
                <button
                  onClick={handleTrackLocation}
                  className="text-blue-600 hover:text-blue-800 font-semibold flex items-center gap-1 transition-colors"
                >
                  <LocateFixed className="h-3.5 w-3.5" />
                  <span>Pinpoint on Radar &rarr;</span>
                </button>
              </div>
            </div>

            {/* Warning Banner if Suspicious */}
            {threat?.severity === 'MEDIUM' && (
              <div className="flex items-start gap-3 p-3.5 bg-amber-50 border border-amber-200 rounded-xl text-amber-900 text-xs">
                <AlertTriangle className="h-5 w-5 text-amber-600 flex-shrink-0 mt-0.5" />
                <div className="leading-relaxed">
                  <strong className="text-amber-950">Caution: Suspicious Email</strong> — This message triggered
                  threat indicators with a {(threat.final_score * 100).toFixed(0)}% risk score. Examine links and
                  origin authentication in the forensic panel before interacting.
                </div>
              </div>
            )}

            {/* Email Body Viewer */}
            <div className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
              <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between text-xs text-slate-600">
                <span className="font-mono text-[11px] font-medium text-slate-700">Message Content</span>
                <span className="text-[10px] text-slate-500">{bodyHtml ? 'HTML Rendered' : 'Plaintext'}</span>
              </div>

              <div className="p-5 overflow-auto max-h-[70vh]">
                {bodyHtml ? (
                  <div
                    className="prose max-w-none text-xs text-slate-800 overflow-auto bg-slate-50/60 p-4 rounded-xl border border-slate-200"
                    dangerouslySetInnerHTML={{ __html: bodyHtml }}
                  />
                ) : bodyText ? (
                  <pre className="bg-slate-50/60 p-4 rounded-xl border border-slate-200 text-xs text-slate-800 whitespace-pre-wrap font-sans leading-relaxed">
                    {bodyText}
                  </pre>
                ) : (
                  <div className="text-center py-12 text-slate-400 text-xs font-mono">
                    (No displayable message body content found)
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Forensic Intelligence Sidebar (1 Column) */}
          <div className="lg:col-span-1 space-y-3">
            <div className="flex items-center justify-between px-1">
              <span className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Forensic Report</span>
              <span className="text-[10px] text-slate-500 font-mono">ID: {threat?.id ? threat.id.slice(0, 8) : 'N/A'}</span>
            </div>

            {threat ? (
              <AuditPanel
                threat={threat}
                onThreatUpdated={updated => {
                  setMessageData(prev => (prev ? { ...prev, threat: updated } : null))
                }}
              />
            ) : (
              <div className="bg-white border border-slate-200 p-6 rounded-xl text-center text-xs text-slate-500 shadow-sm">
                This email has not yet been processed by the threat pipeline.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
