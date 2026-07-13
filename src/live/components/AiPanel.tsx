import React, { useState } from 'react'
import { Send, Sparkles, MessageSquare, AlertCircle } from 'lucide-react'

interface Citation {
  claim: string
  packet_ids: string[]
}

interface Message {
  role: 'user' | 'assistant'
  content: string
  citations?: Citation[]
}

interface AiPanelProps {
  sessionId: string
  onSelectPacket?: (packetId: string) => void
}

export default function AiPanel({ sessionId, onSelectPacket }: AiPanelProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: 'Hello! I am your AI VoIP Forensics Investigator. Select a packet capture to analyze, then ask me anything about the SIP calls, RTP jitter/loss, or ICE candidate paths.'
    }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSend = async () => {
    if (!input.trim() || !sessionId) return
    const userMsg = input
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: userMsg }])
    setLoading(true)

    try {
      const res = await fetch('/api/mcp/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, message: userMsg })
      })
      if (!res.ok) throw new Error('AI investigation request failed.')
      const data = await res.json()
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.text || 'No response returned.',
        citations: data.citations || []
      }])
    } catch (err: any) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error: ${err.message}`
      }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full bg-[#0a0f1d] border border-cyan-900/30 rounded-lg overflow-hidden backdrop-blur-md">
      <div className="p-4 border-b border-cyan-900/30 bg-[#070b14] flex items-center gap-2">
        <Sparkles className="w-5 h-5 text-cyan-400 animate-pulse" />
        <div>
          <h3 className="text-sm font-semibold text-slate-200">AI Forensics Agent</h3>
          <p className="text-[10px] text-cyan-500 font-mono">LLAMA-3.3-70B-VERSATILE ON GROQ</p>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4">
        {messages.map((m, idx) => (
          <div key={idx} className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
            <div className={`max-w-[85%] p-3 rounded-lg text-sm leading-relaxed ${m.role === 'user' ? 'bg-cyan-600/20 text-cyan-100 border border-cyan-500/30' : 'bg-[#0e1726]/80 text-slate-300 border border-slate-800'}`}>
              <div className="whitespace-pre-line">{m.content}</div>
              
              {/* Citations */}
              {m.citations && m.citations.length > 0 && (
                <div className="mt-3 pt-2 border-t border-slate-800/80 space-y-1.5">
                  <span className="text-[10px] font-mono text-cyan-500 uppercase tracking-wider block">Evidence Citations</span>
                  {m.citations.map((c, cidx) => (
                    <div key={cidx} className="text-[11px] bg-slate-900/60 p-1.5 rounded border border-slate-800 flex flex-col gap-1">
                      <span className="text-slate-400 italic">"{c.claim}"</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {c.packet_ids.map(pid => (
                          <button
                            key={pid}
                            onClick={() => onSelectPacket?.(pid)}
                            className="bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-800/40 text-[9px] font-mono font-bold transition-all"
                          >
                            {pid}
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono animate-pulse">
            <Sparkles className="w-4 h-4 animate-spin" />
            Analyzing telemetry, checking packet integrity...
          </div>
        )}
      </div>

      {/* Input */}
      <div className="p-3 border-t border-cyan-900/30 bg-[#070b14] flex gap-2">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSend()}
          placeholder={sessionId ? "Ask about anomalies, call flows, or jitter..." : "Please analyze a PCAP file first"}
          disabled={!sessionId || loading}
          className="flex-1 bg-slate-950 border border-slate-800 focus:border-cyan-500/50 rounded px-3 py-2 text-sm text-slate-200 outline-none placeholder-slate-600 disabled:opacity-50"
        />
        <button
          onClick={handleSend}
          disabled={!sessionId || loading}
          className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 p-2 rounded flex items-center justify-center font-bold transition-colors disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}
