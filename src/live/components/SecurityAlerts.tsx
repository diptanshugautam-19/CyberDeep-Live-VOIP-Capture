import React, { useState } from 'react'
import { ShieldAlert, AlertTriangle, Info, Search } from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

export default function SecurityAlerts() {
  const alerts = useCaptureStore(state => state.alerts)
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL')
  const [searchQuery, setSearchQuery] = useState<string>('')

  const getSeverityIcon = (sev: string) => {
    const s = sev.toUpperCase()
    if (s === 'HIGH' || s === 'CRITICAL') return <ShieldAlert className="w-4 h-4 text-rose-500" />
    if (s === 'MEDIUM') return <AlertTriangle className="w-4 h-4 text-amber-500" />
    return <Info className="w-4 h-4 text-sky-500" />
  }

  const getSeverityClass = (sev: string) => {
    const s = sev.toUpperCase()
    if (s === 'HIGH' || s === 'CRITICAL') return 'border-rose-900/40 bg-rose-950/10'
    if (s === 'MEDIUM') return 'border-amber-900/40 bg-amber-950/10'
    return 'border-sky-900/40 bg-sky-950/10'
  }

  const filteredAlerts = alerts.filter(alert => {
    const matchesSev = filterSeverity === 'ALL' || alert.severity.toUpperCase() === filterSeverity
    const matchesSearch = alert.rule.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          alert.description.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSev && matchesSearch
  })

  return (
    <div className="glass-panel p-4 flex flex-col gap-4 min-h-[300px]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-cyan-800/20 pb-2 gap-2">
        <h3 className="text-sm font-bold text-cyan-400 flex items-center gap-1.5 font-mono">
          <ShieldAlert className="w-4 h-4" /> Real-Time Threats
        </h3>
        
        {/* Controls */}
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search threats..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#0b101b] border border-cyan-900/50 rounded pl-7 pr-2 py-0.5 text-[11px] text-slate-200 focus:outline-none focus:border-cyan-400 font-mono w-32"
            />
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-1.5" />
          </div>

          {/* Severity Select */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-[#0b101b] border border-cyan-900/50 rounded px-1.5 py-0.5 text-[11px] text-slate-200 focus:outline-none font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="INFO">Info</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      <div className="flex-grow overflow-y-auto max-h-[350px] flex flex-col gap-1.5 pr-1">
        {filteredAlerts.length === 0 ? (
          <div className="text-xs font-mono text-slate-500 h-24 flex items-center justify-center">
            No active threat indicators detected
          </div>
        ) : (
          [...filteredAlerts].reverse().map(alert => (
            <div 
              key={alert.alert_id} 
              className={`p-2.5 rounded border flex gap-3 transition-colors ${getSeverityClass(alert.severity)}`}
            >
              <div className="flex-shrink-0 mt-0.5">
                {getSeverityIcon(alert.severity)}
              </div>
              <div className="flex-grow min-w-0 font-mono">
                <div className="flex justify-between items-start gap-2">
                  <h4 className="text-xs font-bold text-slate-200 truncate">{alert.rule}</h4>
                  <span className="text-[9px] text-slate-500 flex-shrink-0">{alert.timestamp.split('T')[1]?.substring(0, 8) || ''}</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{alert.description}</p>
                <div className="flex items-center justify-between text-[9px] text-slate-500 mt-2">
                  <span>Confidence: <strong className="text-slate-400">{(alert.confidence * 100).toFixed(0)}%</strong></span>
                  <span>Flow: <strong className="text-slate-400">{alert.flow_id.substring(0, 12)}...</strong></span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
