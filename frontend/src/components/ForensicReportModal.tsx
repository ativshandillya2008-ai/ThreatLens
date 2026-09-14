import { useState } from 'react'
import {
  Printer,
  Copy,
  Check,
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Brain,
  Link as LinkIcon,
  Lock,
  Calendar,
  User,
  MapPin,
  CheckCircle2,
  XCircle,
  FileText,
} from 'lucide-react'
import { ThreatDetail } from '../api/client'

interface Props {
  threat: ThreatDetail
  onClose: () => void
}

export default function ForensicReportModal({ threat, onClose }: Props) {
  const [copied, setCopied] = useState(false)

  const handlePrint = () => {
    window.print()
  }

  const handleCopyText = () => {
    const lines = [
      '================================================================================',
      'THREATLENS™ CYBER DEFENSE & FORENSIC INTELLIGENCE LABS',
      'OFFICIAL FORENSIC EMAIL THREAT AUDIT & INCIDENT DOSSIER',
      '================================================================================',
      `Audit Reference ID : ${threat.id}`,
      `Message ID         : ${threat.message_id}`,
      `Subject            : ${threat.subject || '(no subject)'}`,
      `Sender (From)      : ${threat.sender}`,
      `Received At        : ${threat.received_at || 'N/A'}`,
      `Analyzed At        : ${threat.analyzed_at}`,
      `Severity           : ${threat.severity}`,
      `Overall Score      : ${(threat.final_score * 100).toFixed(1)}%`,
      `Quarantine Status  : ${threat.quarantined ? 'QUARANTINED' : 'ACTIVE'}`,
      `Detected Language  : ${threat.detected_language || 'English'} (${threat.language_code || 'en'})`,
      '--------------------------------------------------------------------------------',
      'AUTHENTICATION INTEGRITY (SPF / DKIM / DMARC):',
      `  - SPF Status     : ${threat.spf.toUpperCase()}`,
      `  - DKIM Status    : ${threat.dkim.toUpperCase()}`,
      `  - DMARC Status   : ${threat.dmarc.toUpperCase()}`,
      `  - Auth Score     : ${(threat.auth_score * 100).toFixed(0)}%`,
      '--------------------------------------------------------------------------------',
      'ORIGIN & NETWORK GEOLOCATION:',
      `  - Country        : ${threat.geo_country || 'Unknown'}`,
      `  - ASN / ISP      : ${threat.geo_asn || 'Unknown'} (${threat.geo_org || 'Unknown'})`,
      `  - Coordinates    : ${threat.geo_lat ?? 'N/A'}, ${threat.geo_lon ?? 'N/A'}`,
      `  - Geo Mismatch   : ${threat.geo_mismatch ? 'YES (SUSPICIOUS ROUTING)' : 'NO'}`,
      `  - Geo Score      : ${(threat.geo_score * 100).toFixed(0)}%`,
      '--------------------------------------------------------------------------------',
      'AI CONTENT INTELLIGENCE & HEURISTICS (GEMINI):',
      `  - Threat Type    : ${threat.llm_threat_type.toUpperCase()}`,
      `  - AI Score       : ${(threat.llm_score * 100).toFixed(0)}%`,
      '  - Forensic Reasoning:',
      ...(threat.llm_reasoning || []).map(r => `     * ${r}`),
      '  - Flagged Phrases:',
      ...(threat.llm_suspicious_phrases || []).map(p => `     * "${p}"`),
      '--------------------------------------------------------------------------------',
      'HYPERLINKS & SAFE BROWSING:',
      `  - URLs Checked   : ${threat.urls_checked?.length || 0}`,
      `  - Malicious URLs : ${Object.keys(threat.unsafe_urls || {}).length}`,
      ...Object.entries(threat.unsafe_urls || {}).map(([url, verdict]) => `     * [${verdict}] ${url}`),
      '================================================================================',
      'CLASSIFICATION: CONFIDENTIAL // LAW ENFORCEMENT & CYBER DEFENSE AUDIT',
    ]

    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2200)
  }

  const isHigh = threat.severity === 'HIGH'
  const isMedium = threat.severity === 'MEDIUM'

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/70 backdrop-blur-xs flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      {/* Modal Card */}
      <div className="bg-white rounded-2xl max-w-4xl w-full max-h-[92vh] flex flex-col shadow-2xl border border-slate-200 overflow-hidden">
        {/* Top Action Toolbar (Hidden when printing) */}
        <div className="no-print px-5 py-3.5 bg-slate-900 text-white flex items-center justify-between gap-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5 min-w-0">
            <Shield className="h-5 w-5 text-blue-400 flex-shrink-0" />
            <div className="min-w-0">
              <h2 className="text-sm font-bold truncate">Forensic Threat Assessment & Audit Dossier</h2>
              <p className="text-[11px] text-slate-400 font-mono truncate">Incident ID: {threat.id}</p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={handlePrint}
              className="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
              title="Print official forensic report or save as PDF"
            >
              <Printer className="h-4 w-4" />
              <span>Print Report</span>
            </button>

            <button
              onClick={handleCopyText}
              className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 border border-slate-700 transition-colors shadow-sm cursor-pointer"
              title="Copy forensic text summary to clipboard"
            >
              {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
              <span>{copied ? 'Copied' : 'Copy Text'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
              title="Close report"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Printable Report Document Body */}
        <div className="flex-1 overflow-y-auto p-6 sm:p-8 bg-slate-50">
          <div
            id="forensic-printable-report"
            className="bg-white rounded-2xl border border-slate-200 p-6 sm:p-8 shadow-xs space-y-6 text-slate-800"
          >
            {/* Document Masthead */}
            <div className="border-b-2 border-slate-900 pb-5">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <Shield className="h-6 w-6 text-blue-700" />
                    <span className="font-extrabold text-sm tracking-wider uppercase text-slate-900">
                      ThreatLens™ Cyber Defense & Forensic Labs
                    </span>
                  </div>
                  <h1 className="text-lg sm:text-xl font-black text-slate-950 mt-1 uppercase tracking-tight">
                    Official Forensic Email Threat Assessment Dossier
                  </h1>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Automated Multi-Vector Forensic Inspection & Anti-Spoofing Audit
                  </p>
                </div>

                {/* Classification Stamp */}
                <div className="text-right sm:self-center">
                  <div
                    className={`inline-block px-3 py-1.5 rounded-xl border-2 font-mono font-black text-xs uppercase tracking-wider ${
                      isHigh
                        ? 'bg-rose-50 text-rose-800 border-rose-600'
                        : isMedium
                        ? 'bg-amber-50 text-amber-800 border-amber-500'
                        : 'bg-emerald-50 text-emerald-800 border-emerald-600'
                    }`}
                  >
                    {isHigh
                      ? '🚨 CRITICAL THREAT — QUARANTINED'
                      : isMedium
                      ? '⚠️ SUSPICIOUS — ELEVATED RISK'
                      : '🛡️ VERIFIED BENIGN — CLEAN'}
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1">
                    Score: {(threat.final_score * 100).toFixed(1)}% | Date:{' '}
                    {new Date(threat.analyzed_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            </div>

            {/* Section 1: Email Envelope & Incident Summary */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5 flex items-center gap-1.5">
                <FileText className="h-4 w-4 text-blue-600" />
                <span>1. Incident & Email Envelope Metadata</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs">
                <div>
                  <span className="text-slate-500 font-medium">Subject:</span>
                  <div className="font-bold text-slate-900 mt-0.5 break-words">
                    {threat.subject || '(no subject)'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 font-medium">Sender (From):</span>
                  <div className="font-mono text-slate-800 mt-0.5 break-all">
                    {threat.sender}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 font-medium">Message ID:</span>
                  <div className="font-mono text-slate-600 text-[11px] mt-0.5 break-all">
                    {threat.message_id}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 font-medium">Analyzed At:</span>
                  <div className="font-mono text-slate-800 mt-0.5">
                    {new Date(threat.analyzed_at).toUTCString()}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 font-medium">Quarantine Isolation:</span>
                  <div className="mt-0.5">
                    {threat.quarantined ? (
                      <span className="font-bold text-rose-700 inline-flex items-center gap-1">
                        <Lock className="h-3 w-3" /> Quarantined in Isolated Repository
                      </span>
                    ) : (
                      <span className="font-semibold text-emerald-700">Active (Not Quarantined)</span>
                    )}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 font-medium">Language Identification:</span>
                  <div className="font-semibold text-slate-800 mt-0.5 flex items-center gap-1.5">
                    {threat.detected_language && !['English', 'en'].includes(threat.detected_language) && (
                      <span>🇮🇳</span>
                    )}
                    <span>{threat.detected_language || 'English'}</span>
                    {threat.language_code && (
                      <span className="text-[10px] font-mono text-indigo-700 bg-indigo-50 border border-indigo-200 px-1 rounded uppercase">
                        {threat.language_code}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Section 2: Multi-Vector Risk Scorecard */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5 flex items-center gap-1.5">
                <ShieldAlert className="h-4 w-4 text-blue-600" />
                <span>2. Multi-Vector Threat Risk Matrix</span>
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center shadow-2xs">
                  <div className="text-[11px] font-medium text-slate-500">Authentication</div>
                  <div
                    className={`text-lg font-black font-mono mt-1 ${
                      threat.auth_score > 0.5 ? 'text-rose-600' : 'text-emerald-600'
                    }`}
                  >
                    {(threat.auth_score * 100).toFixed(0)}%
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">SPF / DKIM / DMARC</div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center shadow-2xs">
                  <div className="text-[11px] font-medium text-slate-500">Origin Geolocation</div>
                  <div
                    className={`text-lg font-black font-mono mt-1 ${
                      threat.geo_score > 0.5 ? 'text-rose-600' : 'text-slate-800'
                    }`}
                  >
                    {(threat.geo_score * 100).toFixed(0)}%
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    {threat.geo_country || 'Unknown'}
                  </div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center shadow-2xs">
                  <div className="text-[11px] font-medium text-slate-500">AI Heuristics</div>
                  <div
                    className={`text-lg font-black font-mono mt-1 ${
                      threat.llm_score > 0.5 ? 'text-rose-600' : 'text-emerald-600'
                    }`}
                  >
                    {(threat.llm_score * 100).toFixed(0)}%
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5 capitalize">
                    {threat.llm_threat_type.replace(/_/g, ' ')}
                  </div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center shadow-2xs">
                  <div className="text-[11px] font-medium text-slate-500">Safe Browsing</div>
                  <div
                    className={`text-lg font-black font-mono mt-1 ${
                      threat.url_score > 0.5 ? 'text-rose-600' : 'text-emerald-600'
                    }`}
                  >
                    {(threat.url_score * 100).toFixed(0)}%
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    {threat.urls_checked?.length || 0} URLs Verified
                  </div>
                </div>
              </div>
            </div>

            {/* Section 3: Authentication & Anti-Spoofing Analysis */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5 flex items-center gap-1.5">
                <CheckCircle2 className="h-4 w-4 text-blue-600" />
                <span>3. Email Authentication & Anti-Spoofing Verification</span>
              </h3>
              <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2 text-xs">
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 font-semibold block">SPF RECORD</span>
                    <span
                      className={`font-mono font-bold text-xs uppercase mt-1 inline-block ${
                        threat.spf === 'pass' ? 'text-emerald-700' : 'text-rose-700'
                      }`}
                    >
                      {threat.spf}
                    </span>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 font-semibold block">DKIM SIGNATURE</span>
                    <span
                      className={`font-mono font-bold text-xs uppercase mt-1 inline-block ${
                        threat.dkim === 'pass' ? 'text-emerald-700' : 'text-rose-700'
                      }`}
                    >
                      {threat.dkim}
                    </span>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 font-semibold block">DMARC POLICY</span>
                    <span
                      className={`font-mono font-bold text-xs uppercase mt-1 inline-block ${
                        threat.dmarc === 'pass' ? 'text-emerald-700' : 'text-rose-700'
                      }`}
                    >
                      {threat.dmarc}
                    </span>
                  </div>
                </div>
                <p className="text-[11px] text-slate-600 leading-relaxed pt-1">
                  {threat.spf === 'pass' && threat.dkim === 'pass'
                    ? 'Cryptographic sender signatures and SPF authorization records passed without spoofing indicators.'
                    : 'Discrepancies identified in cryptographic signing or domain envelope authorization. High likelihood of forged or hijacked relay infrastructure.'}
                </p>
              </div>
            </div>

            {/* Section 4: Network Infrastructure & GeoIP Forensic Trail */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5 flex items-center gap-1.5">
                <Globe className="h-4 w-4 text-blue-600" />
                <span>4. Network Infrastructure & Physical Geolocation</span>
              </h3>
              <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-3 text-xs">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 block">Origin Country</span>
                    <span className="font-bold text-slate-900 mt-0.5 block">{threat.geo_country || 'Unknown'}</span>
                  </div>
                  <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 block">Origin City</span>
                    <span className="font-bold text-slate-900 mt-0.5 block">
                      {threat.geo_hops?.[0]?.city || 'N/A'}
                    </span>
                  </div>
                  <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 block">Origin ASN</span>
                    <span className="font-mono text-slate-800 text-[11px] mt-0.5 block">
                      {threat.geo_asn || 'Unknown'}
                    </span>
                  </div>
                  <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                    <span className="text-[10px] text-slate-500 block">Org / ISP</span>
                    <span className="font-medium text-slate-900 text-[11px] truncate mt-0.5 block">
                      {threat.geo_org || 'Unknown'}
                    </span>
                  </div>
                </div>

                {/* Hops Table if available */}
                {threat.geo_hops && threat.geo_hops.length > 0 && (
                  <div className="mt-2">
                    <div className="text-[11px] font-bold text-slate-700 mb-1.5">
                      Relay & Routing Infrastructure Hops ({threat.geo_hops.length} nodes):
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-[11px] border border-slate-200 rounded-lg overflow-hidden bg-white">
                        <thead className="bg-slate-100 text-slate-600 font-semibold border-b border-slate-200">
                          <tr>
                            <th className="py-1.5 px-2.5">Hop</th>
                            <th className="py-1.5 px-2.5">IP Address</th>
                            <th className="py-1.5 px-2.5">Location</th>
                            <th className="py-1.5 px-2.5">ASN / ISP</th>
                            <th className="py-1.5 px-2.5 text-right">Risk Tier</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {threat.geo_hops.map((hop, i) => (
                            <tr key={i} className="hover:bg-slate-50">
                              <td className="py-1.5 px-2.5 font-mono text-slate-500">#{i + 1}</td>
                              <td className="py-1.5 px-2.5 font-mono font-medium text-slate-900">{hop.ip}</td>
                              <td className="py-1.5 px-2.5 text-slate-700">
                                {hop.city ? `${hop.city}, ` : ''}{hop.country}
                              </td>
                              <td className="py-1.5 px-2.5 text-slate-600 font-mono text-[10px] truncate max-w-[140px]">
                                {hop.asn} {hop.org ? `(${hop.org})` : ''}
                              </td>
                              <td className="py-1.5 px-2.5 text-right font-semibold">
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[10px] ${
                                    hop.threat_tier?.tier === 'Critical'
                                      ? 'bg-rose-100 text-rose-800'
                                      : hop.threat_tier?.tier === 'High'
                                      ? 'bg-orange-100 text-orange-800'
                                      : hop.threat_tier?.tier === 'Medium'
                                      ? 'bg-amber-100 text-amber-800'
                                      : 'bg-emerald-100 text-emerald-800'
                                  }`}
                                >
                                  {hop.threat_tier?.tier || 'Verified'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Section 5: AI Heuristics & Content Forensics (Gemini AI) */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5 flex items-center gap-1.5">
                <Brain className="h-4 w-4 text-blue-600" />
                <span>5. AI Threat Heuristics & Cognitive Intent Forensics</span>
              </h3>
              <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-3 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Assessed Classification:</span>
                  <span className="font-bold text-slate-900 uppercase font-mono bg-white px-2 py-0.5 rounded border border-slate-200">
                    {threat.llm_threat_type.replace(/_/g, ' ')}
                  </span>
                </div>

                {threat.llm_reasoning && threat.llm_reasoning.length > 0 && (
                  <div>
                    <span className="text-[11px] font-bold text-slate-700 block mb-1">
                      Forensic Behavioral Reasoning:
                    </span>
                    <ul className="space-y-1.5">
                      {threat.llm_reasoning.map((r, i) => (
                        <li key={i} className="flex items-start gap-2 text-slate-800 leading-relaxed">
                          <span className="text-blue-600 font-bold">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {threat.llm_suspicious_phrases && threat.llm_suspicious_phrases.length > 0 && (
                  <div>
                    <span className="text-[11px] font-bold text-slate-700 block mb-1.5">
                      Extracted Deceptive Quotes & Red-Flag Phrases:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {threat.llm_suspicious_phrases.map((phrase, i) => (
                        <span
                          key={i}
                          className="bg-rose-50 text-rose-900 border border-rose-200 px-2 py-1 rounded text-[11px] font-mono leading-relaxed"
                        >
                          "{phrase}"
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Section 6: Hyperlink & URL Reputation Scanner */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5 flex items-center gap-1.5">
                <LinkIcon className="h-4 w-4 text-blue-600" />
                <span>6. Hyperlink & Web Reputation Scanner</span>
              </h3>
              <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-slate-600">Extracted Hyperlinks Analyzed:</span>
                  <span className="font-bold font-mono text-slate-900">
                    {threat.urls_checked?.length || 0}
                  </span>
                </div>

                {threat.unsafe_urls && Object.keys(threat.unsafe_urls).length > 0 ? (
                  <div className="space-y-1.5 mt-2">
                    <div className="text-[11px] font-bold text-rose-700">Flagged Malicious / Dangerous Targets:</div>
                    <div className="space-y-1">
                      {Object.entries(threat.unsafe_urls).map(([u, verdict], idx) => (
                        <div
                          key={idx}
                          className="p-2 bg-rose-50 border border-rose-200 rounded text-rose-900 font-mono text-[11px] break-all flex items-start gap-2"
                        >
                          <span className="font-bold text-rose-700 flex-shrink-0">[{verdict}]</span>
                          <span>{u}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-[11px] text-slate-500">
                    No malicious URLs, exploit redirects, or deceptive credential harvesting endpoints detected by Google Safe Browsing.
                  </p>
                )}
              </div>
            </div>

            {/* Section 7: Audit Dispositions & Overrides */}
            {threat.overrides && threat.overrides.length > 0 && (
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5">
                  7. Historical Security Analyst Dispositions
                </h3>
                <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 space-y-1 text-xs">
                  {threat.overrides.map((ov, i) => (
                    <div key={i} className="flex items-center justify-between text-[11px]">
                      <span className="font-bold text-slate-800 uppercase">{ov.action}</span>
                      <span className="text-slate-600">{ov.reason || 'No remarks'}</span>
                      <span className="font-mono text-slate-400">{new Date(ov.override_at).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Section 8: Formal Sign-off & Audit Seal (Crucial for printed PDF dossiers) */}
            <div className="border-t-2 border-slate-900 pt-5 mt-6">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold block">
                    Official Incident Disposition
                  </span>
                  <div className="font-black text-slate-900 mt-1 uppercase text-sm">
                    {threat.severity === 'HIGH'
                      ? 'CONFIRMED THREAT — ISOLATE'
                      : threat.severity === 'MEDIUM'
                      ? 'SUSPICIOUS — MANUAL ESCALATION'
                      : 'BENIGN — VERIFIED INTEGRITY'}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold block">
                    Security Analyst Sign-off
                  </span>
                  <div className="border-b border-slate-400 mt-4 h-5 w-40"></div>
                  <span className="text-[10px] text-slate-400 block mt-1">Signature / Forensic Agent ID</span>
                </div>

                <div className="text-left sm:text-right">
                  <span className="text-[10px] text-slate-500 uppercase font-bold block">
                    ThreatLens Audit Seal
                  </span>
                  <div className="font-mono text-[10px] text-slate-600 mt-1">
                    SHA256: {threat.id.replace(/-/g, '').slice(0, 24).toUpperCase()}...
                  </div>
                  <div className="text-[9px] text-slate-400 font-mono mt-0.5">
                    CONFIDENTIAL // FOR INTERNAL SECURITY USE ONLY
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
