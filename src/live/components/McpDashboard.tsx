import React, { useState, useEffect } from 'react'
import { Upload, Shield, Play, Loader2, Sparkles, Activity, FileText, List, Network, Database, Info } from 'lucide-react'
import AiPanel from './AiPanel'

export default function McpDashboard() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState<any>(null)
  const [session, setSession] = useState<any>(null)
  const [activeTab, setActiveTab] = useState('summary')
  const [selectedPacket, setSelectedPacket] = useState<any>(null)

  useEffect(() => {
    fetch('/api/mcp/status')
      .then(res => res.json())
      .then(data => setStatus(data))
      .catch(err => console.error(err))
  }, [])

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch('/api/mcp/analyze', {
        method: 'POST',
        body: formData
      })
      if (!res.ok) throw new Error('Analysis failed.')
      const data = await res.json()
      setSession(data)
      setActiveTab('summary')
    } catch (err: any) {
      alert(`Error during PCAP import: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleSelectPacketId = (pid: string) => {
    // pid can be like "p_12" or "12"
    const index = parseInt(pid.replace('p_', ''), 10)
    if (session && session.timeline) {
      const found = session.timeline.find((p: any) => p.packet_index === index)
      if (found) {
        setSelectedPacket(found)
        setActiveTab('packets')
      }
    }
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 gap-4 overflow-hidden h-full">
      {/* Top Banner Status */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0a0f1d]/80 border border-cyan-900/30 p-4 rounded-lg backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-950/40 border border-cyan-800/40 rounded">
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">Offline PCAP Investigation Center</h2>
            <p className="text-xs text-slate-400">Parse PCAPs via TShark MCP Decoders & analyze Call Sessions using Groq Intelligence</p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2 bg-slate-900/60 px-3 py-1.5 rounded border border-slate-800">
            <span className="text-slate-400">TShark Status:</span>
            <span className={`flex items-center gap-1 font-bold ${status?.tshark_available ? 'text-emerald-400' : 'text-red-400'}`}>
              <span className={`w-2 h-2 rounded-full ${status?.tshark_available ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></span>
              {status?.tshark_available ? 'AVAILABLE' : 'MISSING'}
            </span>
          </div>

          <div className="flex items-center gap-2 bg-slate-900/60 px-3 py-1.5 rounded border border-slate-800">
            <span className="text-slate-400">MCP Server:</span>
            <span className="text-cyan-400 font-bold">ONLINE</span>
          </div>
        </div>
      </div>

      {/* Main Split Layout */}
      <div className="flex-grow flex flex-col lg:flex-row gap-4 min-h-0 overflow-hidden">
        
        {/* Left Side: Upload + Tabs view */}
        <div className="flex-grow flex flex-col min-h-0 bg-[#060a13]/60 border border-cyan-950/30 rounded-lg overflow-hidden backdrop-blur">
          
          {/* File Upload Selector */}
          {!session && (
            <div className="flex-grow flex flex-col items-center justify-center p-8 text-center">
              <form onSubmit={handleUpload} className="max-w-md w-full p-8 border-2 border-dashed border-cyan-900/30 bg-[#080d1a]/50 rounded-lg flex flex-col items-center gap-4 hover:border-cyan-500/30 transition-colors">
                <Upload className="w-12 h-12 text-cyan-400 animate-bounce" />
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Import PCAP Evidence</h3>
                  <p className="text-xs text-slate-500 mt-1">Select a trace file containing VoIP, STUN, or SIP signaling packets</p>
                </div>
                <input 
                  type="file" 
                  accept=".pcap,.pcapng" 
                  onChange={e => setFile(e.target.files?.[0] || null)}
                  className="w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-cyan-950/60 file:text-cyan-400 hover:file:bg-cyan-900/60 file:cursor-pointer"
                />
                {file && (
                  <button 
                    type="submit" 
                    disabled={loading}
                    className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold py-2.5 rounded-md flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Running TShark Decoders...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        Start Analysis
                      </>
                    )}
                  </button>
                )}
              </form>
            </div>
          )}

          {session && (
            <>
              {/* Tab Navigation */}
              <div className="flex border-b border-cyan-950/40 bg-[#070b14]/90 p-2 overflow-x-auto gap-1">
                {[
                  { id: 'summary', label: 'Summary', icon: Info },
                  { id: 'packets', label: 'Packet Explorer', icon: List },
                  { id: 'sip', label: 'SIP Calls', icon: FileText },
                  { id: 'rtp', label: 'RTP Sessions', icon: Activity },
                  { id: 'ice', label: 'ICE Candidates', icon: Network },
                  { id: 'stun', label: 'STUN / TURN', icon: Database },
                ].map(tab => {
                  const Icon = tab.icon
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded transition-all font-mono ${activeTab === tab.id ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/40' : 'text-slate-400 hover:text-slate-200'}`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      {tab.label}
                    </button>
                  )
                })}
              </div>

              {/* Tab Content Panels */}
              <div className="flex-1 p-4 overflow-y-auto min-h-0">
                {activeTab === 'summary' && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-[#080d19]/80 border border-cyan-950/30 p-3 rounded">
                        <span className="text-[10px] text-slate-500 font-mono block">SIP CALLS</span>
                        <span className="text-xl font-bold text-white font-mono">{session.sip_calls?.length || 0}</span>
                      </div>
                      <div className="bg-[#080d19]/80 border border-cyan-950/30 p-3 rounded">
                        <span className="text-[10px] text-slate-500 font-mono block">RTP STREAMS</span>
                        <span className="text-xl font-bold text-white font-mono">{session.rtp_sessions?.length || 0}</span>
                      </div>
                      <div className="bg-[#080d19]/80 border border-cyan-950/30 p-3 rounded">
                        <span className="text-[10px] text-slate-500 font-mono block">ICE SESSIONS</span>
                        <span className="text-xl font-bold text-white font-mono">{session.ice_sessions?.length || 0}</span>
                      </div>
                      <div className="bg-[#080d19]/80 border border-cyan-950/30 p-3 rounded">
                        <span className="text-[10px] text-slate-500 font-mono block">CONVERSATIONS</span>
                        <span className="text-xl font-bold text-white font-mono">{session.conversations?.length || 0}</span>
                      </div>
                    </div>

                    <div className="bg-[#080d19]/80 border border-cyan-950/30 p-4 rounded space-y-2">
                      <h3 className="text-sm font-semibold text-slate-200">Session Metadata</h3>
                      <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                        <div>
                          <span className="text-slate-500">Session ID:</span>
                          <span className="text-slate-300 ml-2">{session.session_id}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Unique Endpoints:</span>
                          <span className="text-slate-300 ml-2">{session.endpoints?.length || 0}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'packets' && (
                  <div className="flex flex-col md:flex-row gap-4 h-full">
                    {/* Packet List */}
                    <div className="flex-1 overflow-y-auto max-h-[400px] md:max-h-full border border-cyan-950/30 rounded">
                      <table className="w-full text-xs font-mono text-left">
                        <thead className="bg-[#070b14] text-slate-400 border-b border-cyan-950/30">
                          <tr>
                            <th className="p-2">No.</th>
                            <th className="p-2">Time</th>
                            <th className="p-2">Source</th>
                            <th className="p-2">Destination</th>
                            <th className="p-2">Protocol</th>
                            <th className="p-2">Info</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/40">
                          {session.timeline?.map((p: any) => (
                            <tr
                              key={p.packet_index}
                              onClick={() => setSelectedPacket(p)}
                              className={`hover:bg-cyan-950/20 cursor-pointer ${selectedPacket?.packet_index === p.packet_index ? 'bg-cyan-950/40 border-l-2 border-cyan-500' : ''}`}
                            >
                              <td className="p-2 font-bold">{p.packet_index}</td>
                              <td className="p-2 text-slate-500">{p.timestamp.toFixed(4)}</td>
                              <td className="p-2 text-slate-300">{p.source}</td>
                              <td className="p-2 text-slate-300">{p.destination}</td>
                              <td className="p-2"><span className="bg-cyan-950/60 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-800/30 text-[10px]">{p.protocol}</span></td>
                              <td className="p-2 text-slate-400 truncate max-w-xs">{p.info}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Selected Packet Details */}
                    {selectedPacket && (
                      <div className="w-full md:w-80 bg-[#070b14]/90 border border-cyan-950/40 p-4 rounded flex flex-col gap-3 font-mono text-xs">
                        <h4 className="text-sm font-semibold text-cyan-400 border-b border-cyan-950/30 pb-2 flex items-center justify-between">
                          <span>Packet #{selectedPacket.packet_index} Detail</span>
                          <span className="text-[10px] bg-slate-800 px-2 py-0.5 rounded">{selectedPacket.protocol}</span>
                        </h4>
                        <div className="space-y-2">
                          <div><span className="text-slate-500">Epoch Time:</span> <span className="text-slate-200">{selectedPacket.timestamp}</span></div>
                          <div><span className="text-slate-500">Source Socket:</span> <span className="text-slate-200">{selectedPacket.source}</span></div>
                          <div><span className="text-slate-500">Dest Socket:</span> <span className="text-slate-200">{selectedPacket.destination}</span></div>
                          <div><span className="text-slate-500">Frame Length:</span> <span className="text-slate-200">{selectedPacket.length} bytes</span></div>
                          <div className="pt-2 border-t border-cyan-950/20">
                            <span className="text-slate-500 block mb-1">Payload Summary:</span>
                            <div className="bg-slate-950 p-2 rounded text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-32 select-all">
                              {selectedPacket.info}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'sip' && (
                  <div className="space-y-4">
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-[#070b14] text-slate-400 border-b border-cyan-950/30">
                        <tr>
                          <th className="p-2">Call ID</th>
                          <th className="p-2">Caller</th>
                          <th className="p-2">Callee</th>
                          <th className="p-2">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40 text-slate-300">
                        {session.sip_calls?.map((c: any, idx: number) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-2 font-bold text-cyan-400">{c.call_id}</td>
                            <td className="p-2">{c.caller}</td>
                            <td className="p-2">{c.callee}</td>
                            <td className="p-2"><span className="bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-2 py-0.5 rounded">{c.status}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {activeTab === 'rtp' && (
                  <div className="space-y-4">
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-[#070b14] text-slate-400 border-b border-cyan-950/30">
                        <tr>
                          <th className="p-2">SSRC</th>
                          <th className="p-2">Source Socket</th>
                          <th className="p-2">Dest Socket</th>
                          <th className="p-2">Packets</th>
                          <th className="p-2">Lost Packets</th>
                          <th className="p-2">Jitter</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40 text-slate-300">
                        {session.rtp_sessions?.map((r: any, idx: number) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-2 font-bold text-cyan-400">{r.ssrc}</td>
                            <td className="p-2">{r.source_ip}:{r.source_port}</td>
                            <td className="p-2">{r.dest_ip}:{r.dest_port}</td>
                            <td className="p-2">{r.packet_count}</td>
                            <td className="p-2 text-red-400">{r.lost_packets}</td>
                            <td className="p-2">{r.jitter.toFixed(4)} ms</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {activeTab === 'ice' && (
                  <div className="space-y-4">
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-[#070b14] text-slate-400 border-b border-cyan-950/30">
                        <tr>
                          <th className="p-2">Session ID</th>
                          <th className="p-2">Caller Ufrag</th>
                          <th className="p-2">Callee Ufrag</th>
                          <th className="p-2">State</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40 text-slate-300">
                        {session.ice_sessions?.map((i: any, idx: number) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-2 font-bold text-cyan-400">{i.session_id}</td>
                            <td className="p-2">{i.caller_ufrag}</td>
                            <td className="p-2">{i.callee_ufrag}</td>
                            <td className="p-2"><span className="bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-2 py-0.5 rounded">{i.state}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {activeTab === 'stun' && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">STUN Transactions</h4>
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-[#070b14] text-slate-400 border-b border-cyan-950/30">
                        <tr>
                          <th className="p-2">Transaction ID</th>
                          <th className="p-2">Method</th>
                          <th className="p-2">Class</th>
                          <th className="p-2">Source Socket</th>
                          <th className="p-2">Result</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40 text-slate-300">
                        {session.stun_transactions?.map((s: any, idx: number) => (
                          <tr key={idx} className="hover:bg-slate-900/40">
                            <td className="p-2 font-bold text-cyan-400">{s.transaction_id}</td>
                            <td className="p-2">{s.method}</td>
                            <td className="p-2">{s.class_type}</td>
                            <td className="p-2">{s.source_ip}:{s.source_port}</td>
                            <td className="p-2 text-emerald-400">{s.result}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Right Side: AI Investigation Panel */}
        <div className="w-full lg:w-96 flex flex-col min-h-0 h-[400px] lg:h-full">
          <AiPanel 
            sessionId={session?.session_id} 
            onSelectPacket={handleSelectPacketId}
          />
        </div>
      </div>
    </div>
  )
}
