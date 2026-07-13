import React, { useState, useEffect } from 'react'
import { Phone, ShieldAlert, Activity, WifiOff } from 'lucide-react'
import { useCaptureStore, VoipSessionRecord } from '../store/useCaptureStore'
import { Line } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title as ChartTitle,
  Tooltip,
  Legend,
} from 'chart.js'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ChartTitle,
  Tooltip,
  Legend
)

export default function VoipDashboard() {
  const voipSessions = useCaptureStore(state => state.voipSessions)
  const [selectedCallId, setSelectedCallId] = useState<string | null>(null)
  
  // Local QoS history state for active calls
  const [qosHistory, setQosHistory] = useState<Record<string, { jitter: number[]; loss: number[] }>>({})

  const sessionsList = Object.values(voipSessions)
  const selectedSession = selectedCallId ? voipSessions[selectedCallId] : null

  // Record QoS history values when sessions update
  useEffect(() => {
    if (!selectedSession) return
    const callId = selectedSession.call_id
    const currentJitter = selectedSession.jitter ?? 0
    const currentLoss = selectedSession.loss ?? 0
    
    setQosHistory(prev => {
      const hist = prev[callId] || { jitter: [], loss: [] }
      
      // Avoid inserting duplicates at identical timestamps if no changes
      const lastJitter = hist.jitter[hist.jitter.length - 1]
      const lastLoss = hist.loss[hist.loss.length - 1]
      if (lastJitter === currentJitter && lastLoss === currentLoss && hist.jitter.length > 0) {
        return prev
      }

      const newJitter = [...hist.jitter, currentJitter].slice(-15)
      const newLoss = [...hist.loss, currentLoss].slice(-15)
      return {
        ...prev,
        [callId]: { jitter: newJitter, loss: newLoss }
      }
    })
  }, [selectedSession, voipSessions])

  const getMosColor = (score: number) => {
    if (score >= 4.0) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
    if (score >= 3.0) return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'
    return 'text-red-400 border-red-500/30 bg-red-500/10'
  }

  const renderFlowLadder = (session: VoipSessionRecord) => {
    const caller = session.caller_ip || '10.0.0.10'
    const callee = session.callee_ip || '10.0.0.20'
    
    return (
      <div className="bg-[#050811] p-3 rounded border border-slate-900 font-mono text-[10px] text-slate-300 flex flex-col gap-1.5 overflow-x-auto max-h-[140px]">
        <div className="flex justify-between border-b border-slate-800 pb-1 text-[9px] uppercase text-slate-500 font-bold">
          <span>{caller}</span>
          <span>SIP Signaling Flow</span>
          <span>{callee}</span>
        </div>
        
        {session.joined_mid_session ? (
          <div className="flex flex-col items-center py-4 text-purple-400">
            <div className="text-[9px] uppercase tracking-wider text-purple-300 mb-1 flex items-center gap-1">
              <WifiOff className="w-3 h-3 animate-pulse" /> Joined Mid-Session
            </div>
            <div className="w-full flex justify-between px-4 items-center">
              <span>● RTP Flow</span>
              <div className="flex-1 border-t-2 border-dashed border-purple-500/50 mx-2 text-center text-[9px] text-slate-500">Relay Only / Unresolved</div>
              <span>● RTP Flow</span>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-2 py-2">
            <div className="flex justify-between items-center text-cyan-400">
              <span className="w-20 truncate">INVITE</span>
              <div className="flex-1 border-t border-cyan-500/50 relative mx-2">
                <span className="absolute right-0 -top-1.5 text-cyan-400">➔</span>
              </div>
              <span className="w-20 text-right"></span>
            </div>
            
            <div className="flex justify-between items-center text-slate-400">
              <span className="w-20"></span>
              <div className="flex-1 border-t border-slate-600/50 relative mx-2">
                <span className="absolute left-0 -top-1.5 text-slate-400">←</span>
              </div>
              <span className="w-20 text-right truncate">180 Ringing</span>
            </div>
            
            <div className="flex justify-between items-center text-emerald-400">
              <span className="w-20"></span>
              <div className="flex-1 border-t border-emerald-500/50 relative mx-2">
                <span className="absolute left-0 -top-1.5 text-emerald-400">←</span>
              </div>
              <span className="w-20 text-right truncate">200 OK</span>
            </div>
            
            <div className="flex justify-between items-center text-cyan-400 font-semibold">
              <span className="w-20 truncate">ACK</span>
              <div className="flex-1 border-t border-cyan-500 relative mx-2">
                <span className="absolute right-0 -top-1.5 text-cyan-400">➔</span>
              </div>
              <span className="w-20 text-right"></span>
            </div>
          </div>
        )}
      </div>
    )
  }

  const renderQosChart = (callId: string) => {
    const history = qosHistory[callId] || { jitter: [0], loss: [0] }
    
    const data = {
      labels: history.jitter.map((_, idx) => `${idx + 1}`),
      datasets: [
        {
          label: 'Jitter (ms)',
          data: history.jitter,
          borderColor: 'rgb(34, 211, 238)',
          backgroundColor: 'rgba(34, 211, 238, 0.1)',
          yAxisID: 'y',
          borderWidth: 1.5,
          tension: 0.3,
          pointRadius: 1,
        },
        {
          label: 'Loss (%)',
          data: history.loss,
          borderColor: 'rgb(244, 63, 94)',
          backgroundColor: 'rgba(244, 63, 94, 0.1)',
          yAxisID: 'y1',
          borderWidth: 1.5,
          tension: 0.3,
          pointRadius: 1,
        }
      ]
    }

    const options = {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          display: false,
        },
        y: {
          type: 'linear' as const,
          display: true,
          position: 'left' as const,
          grid: { color: 'rgba(255, 255, 255, 0.03)' },
          ticks: { color: '#94a3b8', font: { size: 9 } }
        },
        y1: {
          type: 'linear' as const,
          display: true,
          position: 'right' as const,
          grid: { drawOnChartArea: false },
          ticks: { color: '#94a3b8', font: { size: 9 } }
        }
      },
      plugins: {
        legend: {
          position: 'top' as const,
          labels: { color: '#94a3b8', font: { size: 9 }, boxWidth: 8 }
        }
      }
    }

    return (
      <div className="h-[100px] w-full mt-2 relative">
        <Line data={data} options={options} />
      </div>
    )
  }

  return (
    <div className="glass-panel p-4 flex flex-col gap-4 min-h-[300px]">
      <div className="flex items-center justify-between border-b border-cyan-800/20 pb-2">
        <h3 className="text-sm font-bold text-cyan-400 flex items-center gap-1.5 font-mono">
          <Phone className="w-4 h-4" /> Live VoIP Analytics
        </h3>
        <span className="text-xs bg-cyan-950 text-cyan-300 font-mono px-2 py-0.5 rounded border border-cyan-800/40">
          Calls: {sessionsList.length}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 flex-1">
        {/* Active Calls List */}
        <div className="border border-cyan-900/30 rounded bg-[#04060a]/30 p-2 overflow-y-auto max-h-[350px]">
          <div className="text-[10px] uppercase text-slate-500 font-mono mb-2">Active Conversations</div>
          {sessionsList.length === 0 ? (
            <div className="text-xs font-mono text-slate-500 h-24 flex items-center justify-center">
              No VoIP signaling detected
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {sessionsList.map(session => (
                <div 
                  key={session.call_id}
                  onClick={() => setSelectedCallId(session.call_id)}
                  className={`p-2 rounded border cursor-pointer transition-all ${
                    selectedCallId === session.call_id 
                      ? 'border-cyan-400 bg-cyan-950/20' 
                      : 'border-slate-800/60 bg-[#060b13] hover:border-cyan-800'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div className="text-xs font-mono font-bold truncate max-w-[70%]">
                      ID: {session.call_id.substring(0, 16)}...
                    </div>
                    {session.joined_mid_session && (
                      <span className="text-[8px] bg-purple-950 border border-purple-800 text-purple-300 font-mono px-1 rounded flex items-center gap-0.5">
                        <WifiOff className="w-2 h-2" /> Mid-Join
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1 font-mono">
                    Caller: {session.caller_ip || 'unknown'} ➔ Callee: {session.callee_ip || 'unknown'}
                  </div>
                  <div className="flex justify-between items-center mt-2 text-[10px] font-mono">
                    <div className="text-slate-500">SSRCs: {session.media_streams.length}</div>
                    <div className={`px-1.5 rounded border text-[9px] ${getMosColor(session.mos ?? 0)}`}>
                      MOS: {(session.mos ?? 0).toFixed(1)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Selected VoIP Stream QoS Details */}
        <div className="border border-cyan-900/30 rounded bg-[#04060a]/30 p-3 flex flex-col gap-3 overflow-y-auto max-h-[350px]">
          <div className="text-[10px] uppercase text-slate-500 font-mono">Selected Call Details</div>
          
          {selectedSession ? (
            <div className="flex flex-col gap-2.5 text-xs font-mono">
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Confidence Score:</span>
                <span className={`font-bold ${(selectedSession.confidence_score ?? 0) > 60 ? 'text-emerald-400' : 'text-purple-400'}`}>
                  {selectedSession.confidence_score ?? 0}% ({selectedSession.confidence_tier || 'unknown'})
                </span>
              </div>
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Jitter (ms):</span>
                <span className="text-cyan-300">{(selectedSession.jitter ?? 0).toFixed(2)} ms</span>
              </div>
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Packet Loss:</span>
                <span className="text-rose-400">{(selectedSession.loss ?? 0).toFixed(2)}%</span>
              </div>
              <div className="flex justify-between border-b border-slate-900 pb-1">
                <span className="text-slate-500">Call Quality Rating:</span>
                <span className="font-bold text-slate-200">{selectedSession.mos_label || 'unknown'}</span>
              </div>

              {selectedSession.warnings.length > 0 && (
                <div className="mt-2 p-2 bg-red-950/20 border border-red-900/40 rounded flex flex-col gap-1">
                  <div className="text-[10px] font-bold text-red-400 flex items-center gap-1">
                    <ShieldAlert className="w-3.5 h-3.5" /> Session Warnings
                  </div>
                  {selectedSession.warnings.map((w, idx) => (
                    <div key={idx} className="text-[10px] text-red-200/80">• {w}</div>
                  ))}
                </div>
              )}

              {/* Real-time QoS Graph */}
              <div className="mt-2">
                <div className="text-[10px] text-slate-500 uppercase">QoS Telemetry Trend</div>
                {renderQosChart(selectedSession.call_id)}
              </div>

              {/* SIP Flow Ladder Diagram */}
              <div className="mt-2">
                <div className="text-[10px] text-slate-500 uppercase mb-1.5">Signaling Ladder</div>
                {renderFlowLadder(selectedSession)}
              </div>

              {/* Classified Endpoints List */}
              <div className="mt-2 border-t border-slate-900 pt-2">
                <div className="text-[10px] text-slate-500 uppercase mb-1.5 font-bold">Classified Endpoints</div>
                <div className="flex flex-col gap-1.5 max-h-[160px] overflow-y-auto pr-1">
                  {selectedSession.endpoints?.map((ep: any) => {
                    const isVpn = ep.role === 'VPN_INTERFACE';
                    return (
                      <div 
                        key={ep.endpoint_id} 
                        className={`p-1.5 rounded border text-[10px] ${
                          isVpn 
                            ? 'border-dashed border-slate-800 bg-slate-950/40 text-slate-400' 
                            : 'border-slate-800 bg-[#080d16] text-slate-200'
                        }`}
                      >
                        <div className="flex justify-between items-center font-bold">
                          <span>{ep.address}</span>
                          <span className={`text-[8px] px-1 py-0.2 rounded font-sans uppercase font-bold tracking-wider ${
                            isVpn ? 'bg-slate-800 text-slate-300' : 'bg-cyan-950 text-cyan-300'
                          }`}>
                            {ep.role}
                          </span>
                        </div>
                        <div className="text-[9px] text-slate-500 mt-0.5 flex justify-between">
                          <span>Confidence: {Math.round(ep.confidence * 100)}%</span>
                          {ep.paired_address && <span>Pair: {ep.paired_address}</span>}
                        </div>
                        {ep.evidence && ep.evidence.length > 0 && (
                          <div className="mt-1 text-[8px] text-slate-500 bg-black/10 p-1 rounded font-sans leading-normal">
                            <span className="font-semibold block text-slate-400 mb-0.5">Evidence Ledger:</span>
                            {ep.evidence.map((ev: string, i: number) => (
                              <div key={i}>• {ev}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* SSRC streams list */}
              <div className="mt-2">
                <div className="text-[10px] text-slate-500 uppercase mb-1">RTP Audio Streams</div>
                <div className="flex flex-col gap-1 max-h-[80px] overflow-y-auto">
                  {selectedSession.media_streams.map(stream => (
                    <div key={stream.ssrc} className="bg-[#0b101b] p-1.5 rounded text-[10px] border border-slate-900 flex justify-between">
                      <span>SSRC: <strong className="text-slate-300">{stream.ssrc}</strong></span>
                      <span>Pkts: <strong className="text-cyan-400">{stream.packets_count}</strong></span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500 h-full flex items-center justify-center font-mono">
              Select a call to inspect QoS & signaling metrics
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
