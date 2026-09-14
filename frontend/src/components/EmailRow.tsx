import { useNavigate } from 'react-router-dom'
import { EmailSummary } from '../api/client'
import ThreatBadge from './ThreatBadge'
import { formatDistanceToNow } from 'date-fns'
import { Lock, Crosshair } from 'lucide-react'

interface Props {
  email: EmailSummary
}

export default function EmailRow({ email }: Props) {
  const navigate = useNavigate()
  const isUnread = email.labelIds.includes('UNREAD')
  const isQuarantined =
    email.threat.severity === 'HIGH' ||
    email.labelIds.some(l => l.toLowerCase().includes('quarantine'))

  const handleClick = () => {
    navigate(`/email/${email.id}`, { state: { threat: email.threat } })
  }

  let relativeDate = ''
  try {
    relativeDate = formatDistanceToNow(new Date(email.date), { addSuffix: true })
  } catch {
    relativeDate = email.date
  }

  const senderClean = email.from.replace(/<.*>/, '').replace(/"/g, '').trim() || email.from
  const initial = senderClean.charAt(0).toUpperCase() || '?'

  const handleTrackLocation = (e: React.MouseEvent) => {
    e.stopPropagation()
    navigate('/map', {
      state: {
        focusEmailId: email.id,
        threatId: email.threat.threat_id,
        subject: email.subject,
        sender: senderClean,
        lat: email.threat.geo_lat,
        lon: email.threat.geo_lon,
        country: email.threat.geo_country,
        city: email.threat.geo_city,
        ip: email.threat.ip || undefined,
      },
    })
  }

  return (
    <div
      onClick={handleClick}
      className={`
        group relative flex items-start gap-3.5 px-4 py-3 cursor-pointer
        border-b border-slate-200 transition-colors
        ${isUnread ? 'bg-blue-50/20' : 'bg-white'}
        hover:bg-slate-50
        ${isQuarantined ? 'border-l-4 border-l-rose-500 bg-rose-50/20' : ''}
      `}
    >
      {/* Sender Avatar */}
      <div className="flex-shrink-0 mt-0.5">
        <div
          className={`h-8 w-8 rounded-lg flex items-center justify-center text-xs font-semibold ${
            isQuarantined
              ? 'bg-rose-50 text-rose-700 border border-rose-200'
              : 'bg-blue-50 text-blue-700 border border-blue-200'
          }`}
        >
          {initial}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <span
              className={`text-xs truncate ${
                isUnread ? 'font-bold text-slate-900' : 'font-medium text-slate-800'
              }`}
            >
              {senderClean}
            </span>
            {isQuarantined && (
              <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.2 rounded bg-rose-50 text-rose-700 border border-rose-200 font-medium font-mono flex-shrink-0">
                <Lock className="h-2.5 w-2.5 text-rose-600" />
                QUARANTINED
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={handleTrackLocation}
              className="px-2.5 py-1 rounded-lg bg-slate-100 group-hover:bg-blue-50 text-slate-600 group-hover:text-blue-700 border border-slate-200 group-hover:border-blue-200 text-[11px] font-semibold flex items-center gap-1 transition-all shadow-xs"
              title="Track sender origin geolocation on ThreatLens Radar"
            >
              <Crosshair className="h-3 w-3 text-blue-600" />
              <span className="hidden sm:inline">Track Location</span>
            </button>
            <ThreatBadge severity={email.threat.severity} score={email.threat.score} />
            <span className="text-[11px] text-slate-400 whitespace-nowrap font-mono">{relativeDate}</span>
          </div>
        </div>

        <div className="text-xs text-slate-800 truncate mt-0.5 font-medium group-hover:text-blue-700 transition-colors">
          {email.subject || '(no subject)'}
        </div>
        <div className="text-[11px] text-slate-500 truncate mt-0.5">
          {email.snippet}
        </div>
      </div>
    </div>
  )
}
