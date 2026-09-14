import { useEffect, useState } from 'react'
import { ShieldAlert, CheckCircle, Trash2 } from 'lucide-react'
import { ThreatDetail, api } from '../api/client'

interface Props {
  threat: ThreatDetail
  onProceed: () => void          // User chose to open anyway
  onKeepQuarantined: () => void  // User chose to keep it quarantined
}

export default function ThreatInterstitial({ threat, onProceed, onKeepQuarantined }: Props) {
  const [overrideReason, setOverrideReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  // Prevent Escape key dismiss
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') e.preventDefault()
    }
    window.addEventListener('keydown', handler, { capture: true })
    return () => window.removeEventListener('keydown', handler, { capture: true })
  }, [])

  const handleMarkSafe = async () => {
    setSubmitting(true)
    setError('')
    try {
      await api.threats.override(threat.id, 'release', overrideReason || 'User marked as safe')
      onProceed()
    } catch {
      setError('Failed to log override. Try again.')
      setSubmitting(false)
    }
  }

  const handleKeep = async () => {
    setSubmitting(true)
    try {
      await api.threats.override(threat.id, 'confirm', 'User confirmed quarantine')
    } catch {
      // Best effort
    }
    onKeepQuarantined()
  }

  const scorePercent = (threat.final_score * 100).toFixed(0)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl bg-white rounded-2xl overflow-hidden shadow-2xl border border-rose-200">
        {/* Red threat banner */}
        <div className="bg-rose-50 border-b border-rose-100 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-rose-100 flex items-center justify-center text-rose-600 flex-shrink-0">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <div className="text-rose-950 font-bold text-lg">High Threat Email Quarantined</div>
              <div className="text-rose-700 text-xs mt-0.5">
                This email triggered critical risk indicators with a threat score of {scorePercent}%.
              </div>
            </div>
          </div>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-4 text-slate-800">
          {/* Score meter */}
          <div>
            <div className="flex justify-between text-xs text-slate-600 mb-1.5 font-medium">
              <span>Calculated Threat Probability</span>
              <span className="text-rose-600 font-bold">{scorePercent}%</span>
            </div>
            <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
              <div
                className="h-full bg-rose-600 rounded-full transition-all"
                style={{ width: `${scorePercent}%` }}
              />
            </div>
          </div>

          {/* Threat details */}
          <div className="bg-slate-50 rounded-xl p-4 space-y-3 border border-slate-200">
            <div className="text-xs font-semibold text-slate-900">Forensic Diagnosis</div>
            <div className="grid grid-cols-3 gap-3 text-xs">
              <div>
                <div className="text-slate-500 text-[11px]">Type</div>
                <div className="text-rose-700 font-semibold capitalize mt-0.5">
                  {threat.llm_threat_type.replace(/_/g, ' ')}
                </div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px]">Origin Country</div>
                <div className="text-slate-800 font-medium mt-0.5">{threat.geo_country || 'Unknown'}</div>
              </div>
              <div>
                <div className="text-slate-500 text-[11px]">Auth Failures</div>
                <div className="text-rose-700 font-semibold mt-0.5">
                  {[threat.spf, threat.dkim, threat.dmarc].filter(r => r === 'fail').length} / 3
                </div>
              </div>
            </div>

            {threat.llm_reasoning.length > 0 && (
              <div>
                <div className="text-[11px] text-slate-500 mb-1.5 font-medium">Flagged Behaviors:</div>
                <ul className="space-y-1">
                  {threat.llm_reasoning.slice(0, 3).map((r, i) => (
                    <li key={i} className="text-xs text-slate-700 flex gap-2">
                      <span className="text-rose-500 mt-0.5 flex-shrink-0">•</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {Object.keys(threat.unsafe_urls).length > 0 && (
              <div className="border-t border-slate-200 pt-3">
                <div className="text-xs text-rose-700 font-semibold mb-1">
                  ⚠️ {Object.keys(threat.unsafe_urls).length} suspicious link(s) detected:
                </div>
                {Object.keys(threat.unsafe_urls).slice(0, 3).map(url => (
                  <div key={url} className="text-xs font-mono text-rose-800 bg-rose-50 px-2 py-1 rounded border border-rose-200 truncate mt-1">
                    {url}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Override reason input */}
          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1">
              Reason for manual override (logged to immutable audit trail):
            </label>
            <input
              type="text"
              value={overrideReason}
              onChange={e => setOverrideReason(e.target.value)}
              placeholder="e.g. Expected invoice from verified vendor"
              className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-600"
            />
          </div>

          {error && <div className="text-rose-600 text-xs font-medium">{error}</div>}
        </div>

        {/* Actions */}
        <div className="flex gap-3 px-6 py-4 bg-slate-50 border-t border-slate-200">
          <button
            onClick={handleKeep}
            disabled={submitting}
            className="flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-xl bg-white border border-slate-300 hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors disabled:opacity-50 shadow-sm"
          >
            <Trash2 className="h-4 w-4" />
            Keep Quarantined
          </button>
          <button
            onClick={handleMarkSafe}
            disabled={submitting}
            className="flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-medium transition-colors disabled:opacity-50 shadow-sm"
          >
            <CheckCircle className="h-4 w-4" />
            {submitting ? 'Logging...' : 'Mark Safe & Open'}
          </button>
        </div>
      </div>
    </div>
  )
}
