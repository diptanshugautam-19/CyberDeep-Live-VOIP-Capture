import React, { useEffect, useState } from 'react'
import { Play, Square, Pause, RotateCcw, ShieldAlert, Wifi, Settings } from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

interface InterfaceInfo {
  name: string
  description?: string
  ip?: string
}

export default function ControlPanel({ apiKey, setApiKey, onConnect, onDisconnect }: {
  apiKey: string
  setApiKey: (val: string) => void
  onConnect: (iface: string, bpf: string) => void
  onDisconnect: () => void
}) {
  const isCapturing = useCaptureStore(state => state.isCapturing)
  const isPaused = useCaptureStore(state => state.isPaused)
  const setPaused = useCaptureStore(state => state.setPaused)
  const totalPackets = useCaptureStore(state => state.totalPackets)
  const droppedFrames = useCaptureStore(state => state.droppedFrames)
  const storageFailure = useCaptureStore(state => state.storageFailure)
  
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([])
  const [selectedIface, setSelectedIface] = useState<string>('')


  const [customBpf, setCustomBpf] = useState<string>("udp or (tcp and (port 5060 or port 5061 or port 443 or port 53 or port 5353 or port 3478))")
  const [logMsg, setLogMsg] = useState('')
  const [isPromoting, setIsPromoting] = useState(false)
  const [promotedId, setPromotedId] = useState<string | null>(null)
  const [investigationTitle, setInvestigationTitle] = useState('')

  // Load interfaces on mount/API key update
  useEffect(() => {
    if (!apiKey) return
    fetch('/api/interfaces', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    })
      .then(res => res.json())
      .then(data => {
        if (data.interfaces) {
          setInterfaces(data.interfaces)
          if (data.interfaces.length > 0) {
            setSelectedIface(data.interfaces[0].name)
          }
        }
      })
      .catch(err => console.error("Failed to load interfaces:", err))
  }, [apiKey])

  const handleStart = async () => {
    if (!selectedIface) return
    try {
      const res = await fetch('/api/capture/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          interface: selectedIface,
          filter_expr: customBpf.trim() || "udp or (tcp and (port 5060 or port 5061 or port 443 or port 53 or port 5353 or port 3478))",
          promiscuous: true
        })
      })
      if (res.ok) {
        setLogMsg(`Capture started on ${selectedIface}`)
        onConnect(selectedIface, customBpf.trim() || "udp or (tcp and (port 5060 or port 5061 or port 443 or port 53 or port 5353 or port 3478))")
      } else {
        const err = await res.json()
        setLogMsg(`Start failed: ${err.detail || res.statusText}`)
      }
    } catch (e: any) {
      setLogMsg(`Error: ${e.message}`)
    }
  }

  const handleStop = async () => {
    try {
      const res = await fetch('/api/capture/stop', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (res.ok) {
        setLogMsg("Capture stopped.")
        onDisconnect()
      }
    } catch (e: any) {
      setLogMsg(`Error: ${e.message}`)
    }
  }

  const handlePauseResume = async () => {
    const route = isPaused ? '/api/capture/resume' : '/api/capture/pause'
    try {
      const res = await fetch(route, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (res.ok) {
        setPaused(!isPaused)
        setLogMsg(isPaused ? "Capture resumed." : "Capture paused.")
      }
    } catch (e: any) {
      setLogMsg(`Error: ${e.message}`)
    }
  }

  const handleForceReset = async () => {
    setLogMsg("Resetting capture engine...")
    try {
      const res = await fetch('/api/capture/reset', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (res.ok) {
        setLogMsg("Capture engine successfully reset. You can now start capturing.")
      } else {
        const err = await res.json()
        setLogMsg(`Reset failed: ${err.detail || res.statusText}`)
      }
    } catch (e: any) {
      setLogMsg(`Error: ${e.message}`)
    }
  }



  const handleDownloadPcap = async () => {
    try {
      setLogMsg("Downloading PCAP...")
      const res = await fetch('/api/capture/export?format=pcap', {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (!res.ok) throw new Error("Failed to download PCAP file.")
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `capture_${Date.now()}.pcap`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
      setLogMsg("PCAP downloaded successfully.")
    } catch (e: any) {
      setLogMsg(`Download failed: ${e.message}`)
    }
  }

  const handlePromote = async () => {
    const title = investigationTitle.trim() || `Live Capture - ${new Date().toLocaleString()}`
    setIsPromoting(true)
    setLogMsg("Analyzing and promoting PCAP trace...")
    try {
      const res = await fetch(`/api/capture/promote?title=${encodeURIComponent(title)}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (res.ok) {
        const data = await res.json()
        setPromotedId(data.id)
        setLogMsg(`Investigation successfully promoted! Name: "${title}"`)
      } else {
        const err = await res.json()
        setLogMsg(`Promotion failed: ${err.detail || res.statusText}`)
      }
    } catch (e: any) {
      setLogMsg(`Error: ${e.message}`)
    } finally {
      setIsPromoting(false)
    }
  }



  return (
    <div className="glass-panel p-4 flex flex-col gap-4">
      {/* Status Bar */}
      <div className="flex items-center justify-between border-b border-cyan-800/30 pb-2">
        <div className="flex items-center gap-2">
          <Wifi className={`w-4 h-4 ${isCapturing ? 'text-emerald-400 animate-pulse' : 'text-slate-400'}`} />
          <span className="font-semibold text-sm tracking-wider uppercase text-cyan-400 glow-text-cyan">
            VoIP WireStream Live
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <div>Packets: <span className="text-cyan-300 font-bold">{totalPackets}</span></div>
          {droppedFrames > 0 && <div className="text-red-400">Dropped: {droppedFrames}</div>}
        </div>
      </div>

      {storageFailure && (
        <div className="bg-red-950/60 border border-red-500/50 rounded p-2 text-xs text-red-200 flex items-center gap-2 animate-pulse">
          <ShieldAlert className="w-4 h-4 text-red-500 flex-shrink-0" />
          <span><strong>STORAGE FAILURE:</strong> SQLite write queue stalled. Live stream active but persistence paused.</span>
        </div>
      )}

      {/* Inputs & Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-slate-400 uppercase font-mono">Interface</label>
          <select 
            disabled={isCapturing}
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            className="bg-[#0b101b] border border-cyan-900/50 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-400"
          >
            {interfaces.map(iface => (
              <option key={iface.name} value={iface.name}>
                {iface.description || iface.name} ({iface.ip || 'no IP'})
              </option>
            ))}
            {interfaces.length === 0 && <option value="">No interfaces found</option>}
          </select>
        </div>
        
        <div className="flex flex-col gap-1 flex-1 min-w-[280px]">
          <div className="flex items-center justify-between">
            <label className="text-[10px] text-slate-400 uppercase font-mono">Capture BPF Filter</label>
            <span className="text-[9px] text-slate-600 font-mono">Valid BPF kernel expression</span>
          </div>
          
          {/* Preset quick-filter badges — each maps to a real BPF expression */}
          <div className="flex flex-wrap gap-1.5 mb-1">
            {[
              { label: 'All VoIP',  bpf: 'udp or (tcp and (port 5060 or port 5061 or port 3478))' },
              { label: 'SIP',       bpf: 'tcp port 5060 or tcp port 5061 or udp port 5060 or udp port 5061' },
              { label: 'RTP/STUN',  bpf: 'udp and not (port 53 or port 5353 or port 5060 or port 5061)' },
              { label: 'STUN/TURN', bpf: 'udp port 3478 or tcp port 3478 or udp port 19302' },
              { label: 'DNS',       bpf: 'port 53 or port 5353' },
              { label: 'TLS',       bpf: 'tcp port 443' },
              { label: 'UDP only',  bpf: 'udp' },
              { label: 'All',       bpf: '' },
            ].map(({ label, bpf }) => {
              const isActive = customBpf === bpf
              return (
                <button
                  key={label}
                  disabled={isCapturing}
                  onClick={() => setCustomBpf(bpf)}
                  className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold tracking-wide border transition-all disabled:opacity-40 disabled:cursor-not-allowed ${
                    isActive
                      ? 'bg-cyan-500/25 text-cyan-300 border-cyan-500/50'
                      : 'bg-[#0f172a]/60 text-slate-400 hover:text-slate-200 border-cyan-950/40 hover:border-cyan-800/40'
                  }`}
                >
                  {label}
                </button>
              )
            })}
          </div>

          <input
            type="text"
            disabled={isCapturing}
            value={customBpf}
            onChange={(e) => setCustomBpf(e.target.value)}
            placeholder="Custom BPF: e.g. host 192.168.1.50, udp port 5060"
            className="bg-[#0b101b] border border-cyan-900/50 rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-400 placeholder:text-slate-700 font-mono w-full disabled:opacity-40"
          />
        </div>

        {/* Buttons */}
        <div className="flex items-end gap-2 pt-4">
          {!isCapturing ? (
            <>
              <button 
                onClick={handleStart}
                className="bg-cyan-600 hover:bg-cyan-500 text-white rounded px-3 py-1 text-xs font-semibold flex items-center gap-1 transition-all"
              >
                <Play className="w-3.5 h-3.5" /> Start
              </button>
              

            </>
          ) : (
            <>
              <button 
                onClick={handleStop}
                className="bg-red-600 hover:bg-red-500 text-white rounded px-3 py-1 text-xs font-semibold flex items-center gap-1 transition-all"
              >
                <Square className="w-3.5 h-3.5" /> Stop
              </button>
              <button 
                onClick={handlePauseResume}
                className="bg-amber-600 hover:bg-amber-500 text-white rounded px-3 py-1 text-xs font-semibold flex items-center gap-1 transition-all"
              >
                <Pause className="w-3.5 h-3.5" /> {isPaused ? 'Resume' : 'Pause'}
              </button>
            </>
          )}

          
          {!isCapturing && totalPackets > 0 && (
            <div className="flex items-center gap-2 pl-4 border-l border-cyan-800/30">
              <input 
                type="text"
                placeholder="Investigation Title"
                value={investigationTitle}
                onChange={(e) => setInvestigationTitle(e.target.value)}
                className="bg-[#0b101b] border border-cyan-900/50 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-400 placeholder:text-slate-600"
              />
              <button 
                onClick={handlePromote}
                disabled={isPromoting}
                className="bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-850/50 text-white rounded px-3 py-1 text-xs font-semibold flex items-center gap-1 transition-all"
              >
                {isPromoting ? 'Analyzing...' : 'Analyze Offline 🚀'}
              </button>
              <button 
                onClick={handleDownloadPcap}
                className="bg-sky-600 hover:bg-sky-500 text-white rounded px-3 py-1 text-xs font-semibold flex items-center gap-1 transition-all"
              >
                Save PCAP 📥
              </button>
              {promotedId && (
                <a 
                  href={`/tool?live=true`}
                  target="_self"
                  className="bg-purple-600 hover:bg-purple-500 text-white rounded px-3 py-1 text-xs font-semibold flex items-center gap-1 transition-all"
                >
                  Open Analyzer 🔍
                </a>
              )}
            </div>
          )}
        </div>
      </div>



      {logMsg && (
        <div className="text-[11px] font-mono text-cyan-300/80 bg-[#060a12] p-1.5 rounded border border-cyan-900/20 flex justify-between items-center">
          <span>{logMsg}</span>
          {logMsg.includes("already in progress") && (
            <button 
              onClick={handleForceReset}
              className="bg-red-950/50 border border-red-500/40 text-red-300 hover:bg-red-900/50 hover:border-red-400 rounded px-2.5 py-0.5 text-[10px] font-semibold transition-all flex items-center gap-1 cursor-pointer ml-3 shrink-0"
            >
              Force Reset Sniffer 🔄
            </button>
          )}
        </div>
      )}
    </div>
  )
}
