import { useEffect, useState } from 'react'
import { ShieldAlert, AlertTriangle, ShieldCheck, Gauge } from 'lucide-react'
import { api, ThreatStats } from '../api/client'

interface Props {
  onFilterSeverity?: (severity: string) => void
  activeSeverity?: string
  refreshTrigger?: number
}

export default function ThreatStatsCards({ onFilterSeverity, activeSeverity, refreshTrigger }: Props) {
  const [stats, setStats] = useState<ThreatStats | null>(null)
  const [loading, setLoading] = useState(true)

  const loadStats = async () => {
    try {
      const res = await api.threats.stats()
      setStats(res)
    } catch (err) {
      console.error('Failed to load threat stats:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadStats()
  }, [refreshTrigger])

  useEffect(() => {
    const timer = setInterval(loadStats, 30_000)
    return () => clearInterval(timer)
  }, [])

  const total = (stats?.LOW ?? 0) + (stats?.MEDIUM ?? 0) + (stats?.HIGH ?? 0)
  const highAvg = stats?.avg_scores?.HIGH ? (stats.avg_scores.HIGH * 100).toFixed(0) : '0'
  const medAvg = stats?.avg_scores?.MEDIUM ? (stats.avg_scores.MEDIUM * 100).toFixed(0) : '0'

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 mb-5">
      {/* High Threat Card */}
      <div
        onClick={() => onFilterSeverity?.(activeSeverity === 'HIGH' ? '' : 'HIGH')}
        className={`bg-white border p-4 rounded-2xl cursor-pointer shadow-sm transition-all ${
          activeSeverity === 'HIGH'
            ? 'border-rose-500 ring-2 ring-rose-200 bg-rose-50/30'
            : 'border-slate-200 hover:border-slate-300'
        }`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-rose-700">High Threat</span>
          <div className="h-7 w-7 rounded-lg bg-rose-50 border border-rose-200 flex items-center justify-center">
            <ShieldAlert className="h-4 w-4 text-rose-600" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-slate-900 tracking-tight">
            {loading ? '-' : stats?.HIGH ?? 0}
          </span>
          <span className="text-[11px] text-rose-600 font-mono font-medium">
            {highAvg}% avg score
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-500 font-medium">Quarantined / Critical</div>
      </div>

      {/* Suspicious Card */}
      <div
        onClick={() => onFilterSeverity?.(activeSeverity === 'MEDIUM' ? '' : 'MEDIUM')}
        className={`bg-white border p-4 rounded-2xl cursor-pointer shadow-sm transition-all ${
          activeSeverity === 'MEDIUM'
            ? 'border-amber-500 ring-2 ring-amber-200 bg-amber-50/30'
            : 'border-slate-200 hover:border-slate-300'
        }`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-amber-700">Suspicious</span>
          <div className="h-7 w-7 rounded-lg bg-amber-50 border border-amber-200 flex items-center justify-center">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-slate-900 tracking-tight">
            {loading ? '-' : stats?.MEDIUM ?? 0}
          </span>
          <span className="text-[11px] text-amber-600 font-mono font-medium">
            {medAvg}% avg score
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-500 font-medium">Flagged for Review</div>
      </div>

      {/* Safe Card */}
      <div
        onClick={() => onFilterSeverity?.(activeSeverity === 'LOW' ? '' : 'LOW')}
        className={`bg-white border p-4 rounded-2xl cursor-pointer shadow-sm transition-all ${
          activeSeverity === 'LOW'
            ? 'border-emerald-500 ring-2 ring-emerald-200 bg-emerald-50/30'
            : 'border-slate-200 hover:border-slate-300'
        }`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-emerald-700">Verified Safe</span>
          <div className="h-7 w-7 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-slate-900 tracking-tight">
            {loading ? '-' : stats?.LOW ?? 0}
          </span>
          <span className="text-[11px] text-emerald-600 font-mono font-medium">
            Auth verified
          </span>
        </div>
        <div className="mt-1 text-[11px] text-slate-500 font-medium">Clean Deliveries</div>
      </div>

      {/* Total Scanned Card */}
      <div
        onClick={() => onFilterSeverity?.('')}
        className={`bg-white border p-4 rounded-2xl cursor-pointer shadow-sm transition-all ${
          !activeSeverity
            ? 'border-blue-500 ring-2 ring-blue-200 bg-blue-50/30'
            : 'border-slate-200 hover:border-slate-300'
        }`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-blue-700">Total Scanned</span>
          <div className="h-7 w-7 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center">
            <Gauge className="h-4 w-4 text-blue-600" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-slate-900 tracking-tight">
            {loading ? '-' : total}
          </span>
          <span className="text-[11px] text-slate-500 font-medium">emails</span>
        </div>
        <div className="mt-1 text-[11px] text-slate-500 font-medium">
          {activeSeverity ? 'Click to show all' : 'Across all mailboxes'}
        </div>
      </div>
    </div>
  )
}
