import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ChevronDown,
  ChevronRight,
  Shield,
  Globe,
  Brain,
  Link as LinkIcon,
  Code2,
  UserCheck,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Lock,
  Unlock,
  Crosshair,
  MapPin,
  Printer,
} from 'lucide-react'
import { ThreatDetail, api } from '../api/client'
import ThreatBadge from './ThreatBadge'
import GeoLocationMap, { MapMarkerItem } from './GeoLocationMap'
import ForensicReportModal from './ForensicReportModal'

interface Props {
  threat: ThreatDetail
  onThreatUpdated?: (updated: ThreatDetail) => void
}

function Section({
  title,
  icon: Icon,
  children,
  defaultOpen = true,
}: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden shadow-sm transition-all">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2.5 px-4 py-3 bg-slate-50/70 text-left hover:bg-slate-100 transition-colors"
      >
        <Icon className="h-4 w-4 text-blue-600" />
        <span className="font-bold text-xs text-slate-900">{title}</span>
        <span className="ml-auto">
          {open ? (
            <ChevronDown className="h-4 w-4 text-slate-400" />
          ) : (
            <ChevronRight className="h-4 w-4 text-slate-400" />
          )}
        </span>
      </button>
      {open && <div className="px-4 py-3.5 bg-white text-xs border-t border-slate-100">{children}</div>}
    </div>
  )
}

function ResultPill({ value }: { value: string }) {
  const val = (value || 'none').toLowerCase()
  const color =
    val === 'pass'
      ? 'text-emerald-700 bg-emerald-50 border-emerald-200'
      : val === 'fail' || val === 'permerror'
      ? 'text-rose-700 bg-rose-50 border-rose-200'
      : val === 'softfail' || val === 'temperror'
      ? 'text-amber-700 bg-amber-50 border-amber-200'
      : 'text-slate-600 bg-slate-100 border-slate-200'

  return (
    <span className={`inline-block font-mono text-[11px] font-bold px-2 py-0.5 rounded border uppercase ${color}`}>
      {val}
    </span>
  )
}

export default function AuditPanel({ threat, onThreatUpdated }: Props) {
  const navigate = useNavigate()
  const [showReport, setShowReport] = useState(false)
  const [showRawHeaders, setShowRawHeaders] = useState(false)
  const [rawHeaders, setRawHeaders] = useState<string>('')
  const [loadingHeaders, setLoadingHeaders] = useState(false)
  const [copiedHeaders, setCopiedHeaders] = useState(false)

  const [overrideAction, setOverrideAction] = useState<'release' | 'confirm'>('release')
  const [overrideReason, setOverrideReason] = useState('')
  const [overrideSubmitting, setOverrideSubmitting] = useState(false)
  const [overrideMessage, setOverrideMessage] = useState('')

  const handleFetchHeaders = async () => {
    if (rawHeaders) {
      setShowRawHeaders(prev => !prev)
      return
    }
    setLoadingHeaders(true)
    setShowRawHeaders(true)
    try {
      const data = await api.threats.get(threat.id, true)
      setRawHeaders(data.raw_headers || '(No encrypted raw headers stored)')
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

  const handleApplyOverride = async () => {
    setOverrideSubmitting(true)
    setOverrideMessage('')
    try {
      await api.threats.override(threat.id, overrideAction, overrideReason)
      setOverrideMessage(`Override recorded: marked as ${overrideAction}`)
      const updated = await api.threats.get(threat.id)
      onThreatUpdated?.(updated)
      setOverrideReason('')
    } catch (err) {
      setOverrideMessage(`Error: ${String(err)}`)
    } finally {
      setOverrideSubmitting(false)
    }
  }

  return (
    <div className="space-y-3.5">
      {/* Top Metric Summary Card */}
      <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between">
          <ThreatBadge severity={threat.severity} score={threat.final_score} size="md" />
          <div className="text-right">
            <div className="text-[10px] text-slate-400 font-mono uppercase">Analyzed</div>
            <div className="text-xs text-slate-700 font-mono font-medium mt-0.5">
              {threat.analyzed_at ? new Date(threat.analyzed_at).toLocaleTimeString() : 'N/A'}
            </div>
          </div>
        </div>

        <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between">
          <div>
            <div className="text-[10px] text-slate-500 font-semibold">Threat Score</div>
            <div className="text-2xl font-extrabold text-slate-900 font-mono">
              {(threat.final_score * 100).toFixed(1)}%
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-slate-500 font-semibold">Status</div>
            <div className="mt-1">
              {threat.quarantined ? (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-50 text-rose-700 border border-rose-200 font-mono">
                  <Lock className="h-3 w-3" />
                  Quarantined
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
                  <Unlock className="h-3 w-3" />
                  Clean
                </span>
              )}
            </div>
          </div>
        </div>

        <button
          onClick={() => setShowReport(true)}
          className="mt-3 w-full py-2 px-3 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all shadow-2xs cursor-pointer"
          title="View & Print Official Forensic Threat Assessment Report Dossier"
        >
          <Printer className="h-3.5 w-3.5 text-blue-600" />
          <span>View & Print Forensic Audit Report</span>
        </button>
      </div>

      {/* 1. Email Authentication */}
      <Section title="Authentication (SPF / DKIM / DMARC)" icon={Shield}>
        <div className="grid grid-cols-3 gap-2 text-center">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200">
            <div className="text-slate-500 text-[10px] mb-1 font-semibold">SPF</div>
            <ResultPill value={threat.spf} />
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200">
            <div className="text-slate-500 text-[10px] mb-1 font-semibold">DKIM</div>
            <ResultPill value={threat.dkim} />
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200">
            <div className="text-slate-500 text-[10px] mb-1 font-semibold">DMARC</div>
            <ResultPill value={threat.dmarc} />
          </div>
        </div>
      </Section>

      {/* 2. Geolocation Analysis */}
      <Section title="IP Route & Geolocation" icon={Globe}>
        <div className="space-y-2.5">
          {threat.geo_mismatch && (
            <div className="flex items-start gap-2 p-2.5 bg-amber-50 border border-amber-200 rounded-xl text-amber-800 text-xs">
              <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" />
              <span>Geo-Mismatch: Origin IP differs from sender domain's home country.</span>
            </div>
          )}

          {/* Interactive World Map of Sender & Relay Route */}
          {(() => {
            const originHop = threat.geo_hops?.[0]
            const senderLat = threat.geo_lat || originHop?.lat || 37.0902
            const senderLon = threat.geo_lon || originHop?.lon || -95.7129

            const senderMarkers: MapMarkerItem[] = [
              {
                id: `threat-origin-${threat.id}`,
                ip: originHop?.ip || 'Origin Server',
                lat: senderLat,
                lon: senderLon,
                city: originHop?.city || 'Unknown City',
                country: threat.geo_country || originHop?.country || 'Unknown',
                isp: threat.geo_org || originHop?.isp || originHop?.org || 'Origin Carrier',
                asn: threat.geo_asn || originHop?.asn || 'N/A',
                threat_score: Math.round(threat.final_score * 100),
                threat_tier: {
                  tier: threat.severity === 'HIGH' ? 'Critical' : threat.severity === 'MEDIUM' ? 'High' : 'Safe',
                  score: Math.round(threat.final_score * 100),
                  color: threat.severity === 'HIGH' ? '#990000' : threat.severity === 'MEDIUM' ? '#f87171' : '#4ade80',
                  bg_color: 'rgba(255, 255, 255, 0.1)',
                  border_color: '#ffffff',
                  label: threat.severity,
                  typical: `Email: ${threat.subject}`,
                },
                cardinal_coords: originHop?.cardinal_coords,
                confidence_statement: `Origin Gateway: ${originHop?.city || 'Region'}, ${threat.geo_country || 'Unknown'}`,
              },
            ]

            return (
              <div className="rounded-xl overflow-hidden border border-slate-200 shadow-sm">
                <GeoLocationMap
                  markers={senderMarkers}
                  hops={threat.geo_hops}
                  height="260px"
                  showTileSwitcher={false}
                  showRadius={true}
                />
              </div>
            )
          })()}

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="col-span-2 p-2.5 bg-blue-50/70 rounded-xl border border-blue-200/80">
              <div className="text-blue-700 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1">
                <MapPin className="h-3 w-3 text-blue-600" />
                <span>Actual Physical Location</span>
              </div>
              <div className="text-slate-900 font-bold text-xs mt-0.5">
                {threat.geo_hops?.[0]?.city && threat.geo_country
                  ? `${threat.geo_hops[0].city}, ${threat.geo_country}`
                  : threat.geo_country || 'Origin Network Gateway'}
              </div>
              {threat.geo_lat && threat.geo_lon && (
                <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                  {threat.geo_hops?.[0]?.cardinal_coords || `${threat.geo_lat.toFixed(4)}°, ${threat.geo_lon.toFixed(4)}°`}
                </div>
              )}
            </div>

            <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200">
              <div className="text-slate-500 text-[10px]">Country</div>
              <div className="text-slate-900 font-semibold mt-0.5">{threat.geo_country || 'Unknown'}</div>
            </div>
            <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200">
              <div className="text-slate-500 text-[10px]">ASN</div>
              <div className="text-slate-800 font-mono text-[11px] mt-0.5">{threat.geo_asn || 'Unknown'}</div>
            </div>
            <div className="col-span-2 p-2.5 bg-slate-50 rounded-xl border border-slate-200">
              <div className="text-slate-500 text-[10px]">Organization / ISP</div>
              <div className="text-slate-900 truncate mt-0.5 font-medium">{threat.geo_org || 'Unknown'}</div>
            </div>
          </div>

          <button
            onClick={() => {
              navigate('/map', {
                state: {
                  focusEmailId: threat.message_id,
                  threatId: threat.id,
                  subject: threat.subject,
                  sender: threat.sender,
                  lat: threat.geo_lat || threat.geo_hops?.[0]?.lat,
                  lon: threat.geo_lon || threat.geo_hops?.[0]?.lon,
                  country: threat.geo_country,
                  city: threat.geo_hops?.[0]?.city,
                  ip: threat.geo_hops?.[0]?.ip,
                },
              })
            }}
            className="w-full py-2 px-3 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all shadow-xs"
          >
            <Crosshair className="h-3.5 w-3.5 text-blue-600" />
            <span>Open in ThreatLens Radar (Track Accurate Location)</span>
          </button>
        </div>
      </Section>

      {/* 3. Gemini Content Analysis */}
      <Section title="Gemini AI Threat Analysis" icon={Brain}>
        <div className="space-y-2.5">
          <div className="flex items-center justify-between p-2.5 bg-slate-50 rounded-xl border border-slate-200">
            <div>
              <div className="text-[10px] text-slate-500">Threat Type</div>
              <div className="text-slate-900 font-bold text-xs capitalize mt-0.5">
                {threat.llm_threat_type.replace(/_/g, ' ')}
              </div>
            </div>
            <div className="text-right">
              <div className="text-[10px] text-slate-500">AI Threat Score</div>
              <div className="text-rose-700 font-mono font-bold text-sm mt-0.5">
                {(threat.llm_score * 100).toFixed(0)}%
              </div>
            </div>
          </div>

          {threat.detected_language && (
            <div className="p-2.5 bg-indigo-50/60 rounded-xl border border-indigo-200/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-base">
                  {threat.detected_language !== 'English' && threat.detected_language !== 'en' ? '🇮🇳' : '🌐'}
                </span>
                <div>
                  <div className="text-[10px] text-indigo-700 font-bold uppercase tracking-wider">
                    Language Intelligence
                  </div>
                  <div className="text-slate-900 font-semibold text-xs mt-0.5 flex items-center gap-1.5">
                    <span>{threat.detected_language}</span>
                    {threat.language_code && (
                      <span className="text-[10px] font-mono text-indigo-700 bg-indigo-100 px-1.5 py-0.2 rounded font-semibold uppercase">
                        {threat.language_code}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              {threat.detected_language !== 'English' && threat.detected_language !== 'en' && (
                <span className="text-[10px] font-semibold text-indigo-800 bg-white border border-indigo-200 px-2 py-0.5 rounded-md shadow-xs">
                  Native Indic Scan
                </span>
              )}
            </div>
          )}

          {threat.llm_reasoning && threat.llm_reasoning.length > 0 && (
            <div>
              <div className="text-[10px] font-bold text-slate-600 uppercase mb-1.5">
                Forensic Reasoning
              </div>
              <ul className="space-y-1">
                {threat.llm_reasoning.map((r, i) => (
                  <li key={i} className="text-xs text-slate-700 flex items-start gap-1.5 leading-relaxed">
                    <span className="text-blue-600 font-bold mt-0.5">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {threat.llm_suspicious_phrases && threat.llm_suspicious_phrases.length > 0 && (
            <div>
              <div className="text-[10px] font-bold text-slate-600 uppercase mb-1.5">
                Flagged Phrases
              </div>
              <div className="flex flex-wrap gap-1">
                {threat.llm_suspicious_phrases.map((p, i) => (
                  <span
                    key={i}
                    className="text-[11px] font-mono bg-rose-50 text-rose-800 border border-rose-200 px-2 py-0.5 rounded-md"
                  >
                    "{p}"
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </Section>

      {/* 4. Safe Browsing */}
      <Section title="URL Reputation Scanner" icon={LinkIcon}>
        <div className="space-y-2">
          {Object.keys(threat.unsafe_urls).length > 0 ? (
            <div className="space-y-1">
              <div className="text-xs font-bold text-rose-700 flex items-center gap-1">
                <AlertTriangle className="h-3.5 w-3.5" />
                <span>Malicious Links Found:</span>
              </div>
              {Object.entries(threat.unsafe_urls).map(([url, type]) => (
                <div
                  key={url}
                  className="p-2 rounded-xl bg-rose-50 border border-rose-200 text-xs font-mono text-rose-800 flex flex-col"
                >
                  <span className="break-all">{url}</span>
                  <span className="text-[10px] text-rose-600 font-bold uppercase">{type}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 p-2.5 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-800 text-xs">
              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
              <span>All links verified safe via Google Safe Browsing.</span>
            </div>
          )}
        </div>
      </Section>

      {/* 5. Headers & Override */}
      <Section title="Forensic Headers & Override" icon={Code2} defaultOpen={false}>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-600">Raw RFC Headers:</span>
            <button
              onClick={handleFetchHeaders}
              disabled={loadingHeaders}
              className="px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-xs text-slate-700 font-medium"
            >
              {loadingHeaders ? 'Decrypting...' : showRawHeaders ? 'Hide' : 'Inspect Headers'}
            </button>
          </div>

          {showRawHeaders && (
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl font-mono text-[10px] text-slate-800 max-h-48 overflow-auto whitespace-pre-wrap">
              {rawHeaders}
            </div>
          )}

          <div className="pt-2 border-t border-slate-100 space-y-2">
            <div className="text-xs font-bold text-slate-800">Quick Override</div>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => setOverrideAction('release')}
                className={`py-1.5 rounded-lg text-xs font-semibold border ${
                  overrideAction === 'release'
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-400'
                    : 'bg-white text-slate-600 border-slate-200'
                }`}
              >
                Release
              </button>
              <button
                onClick={() => setOverrideAction('confirm')}
                className={`py-1.5 rounded-lg text-xs font-semibold border ${
                  overrideAction === 'confirm'
                    ? 'bg-rose-50 text-rose-800 border-rose-400'
                    : 'bg-white text-slate-600 border-slate-200'
                }`}
              >
                Quarantine
              </button>
            </div>
            <input
              type="text"
              value={overrideReason}
              onChange={e => setOverrideReason(e.target.value)}
              placeholder="Reason (optional)"
              className="w-full bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs text-slate-800"
            />
            {overrideMessage && (
              <div className="text-[11px] p-2 bg-blue-50 text-blue-800 rounded-lg border border-blue-200">
                {overrideMessage}
              </div>
            )}
            <button
              onClick={handleApplyOverride}
              disabled={overrideSubmitting}
              className="w-full py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-xs font-semibold text-white transition-colors cursor-pointer"
            >
              {overrideSubmitting ? 'Saving...' : 'Apply Override'}
            </button>
          </div>
        </div>
      </Section>

      {/* Forensic Threat Assessment & Audit Dossier Modal */}
      {showReport && (
        <ForensicReportModal
          threat={threat}
          onClose={() => setShowReport(false)}
        />
      )}
    </div>
  )
}
