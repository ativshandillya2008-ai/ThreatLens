import { AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react'

interface Props {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | null
  score?: number | null
  size?: 'sm' | 'md' | 'lg'
  isSpam?: boolean
}

export default function ThreatBadge({ severity, score, size = 'sm', isSpam = false }: Props) {
  if (!severity) {
    if (isSpam) {
      return (
        <span className="inline-flex items-center gap-1.5 rounded-full font-medium text-xs px-2 py-0.5 threat-badge-medium">
          <AlertTriangle className="h-3 w-3" />
          Suspicious (Spam)
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-gray-800 text-gray-400 border border-gray-700">
        <span className="h-1.5 w-1.5 rounded-full bg-gray-400" />
        Unscored
      </span>
    )
  }

  // If message is in Spam folder/quarantined, it must never display as 'Safe'
  const effectiveSeverity = (isSpam && severity === 'LOW') ? 'MEDIUM' : severity

  const config = {
    LOW: {
      classes: 'threat-badge-low',
      Icon: CheckCircle,
      label: 'Safe',
    },
    MEDIUM: {
      classes: 'threat-badge-medium',
      Icon: AlertTriangle,
      label: isSpam ? 'Suspicious (Spam)' : 'Suspicious',
    },
    HIGH: {
      classes: 'threat-badge-high',
      Icon: ShieldAlert,
      label: 'Threat',
    },
  }[effectiveSeverity]

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-3 py-1',
    lg: 'text-base px-4 py-1.5',
  }[size]

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium ${sizeClasses} ${config.classes}`}
    >
      <config.Icon className={size === 'sm' ? 'h-3 w-3' : 'h-4 w-4'} />
      {config.label}
      {score !== null && score !== undefined && (
        <span className="opacity-75">({(score * 100).toFixed(0)}%)</span>
      )}
    </span>
  )
}
