import React, { useState, useMemo } from 'react'
import { useCaptureStore } from '../store/useCaptureStore'
import { Activity, Globe, Shield, Search } from 'lucide-react'

export default function ConversationsView() {
  const packets = useCaptureStore(state => state.packets)
  const flows = useCaptureStore(state => state.flows)
  const [activeTab, setActiveTab] = useState('TCP')
  const [searchTerm, setSearchTerm] = useState('')

  // Aggregate packets into conversations
  const conversations = useMemo(() => {
    const convoMap = new Map<string, any>()
    
    // Reverse packets to show latest first or just process them in order
    packets.forEach(pkt => {
      if (!pkt.flow_id) return
      
      const protoFilter = activeTab.toLowerCase()
      if (activeTab !== 'All' && pkt.protocol.toLowerCase() !== protoFilter && !pkt.protocol.toLowerCase().includes(protoFilter)) {
          // simple check for tab
          if (activeTab === 'TCP' && pkt.protocol !== 'TCP' && pkt.protocol !== 'TLS' && pkt.protocol !== 'HTTP') return
          if (activeTab === 'UDP' && pkt.protocol !== 'UDP' && pkt.protocol !== 'DNS' && pkt.protocol !== 'RTP' && pkt.protocol !== 'SIP') return
      }

      if (!convoMap.has(pkt.flow_id)) {
        convoMap.set(pkt.flow_id, {
          flow_id: pkt.flow_id,
          src_ip: pkt.source_ip,
          dst_ip: pkt.destination_ip,
          src_port: pkt.source_port,
          dst_port: pkt.destination_port,
          protocol: pkt.protocol,
          start_time: pkt.timestamp,
          end_time: pkt.timestamp,
          packet_count: 0,
          bytes: 0
        })
      }

      const convo = convoMap.get(pkt.flow_id)
      convo.end_time = pkt.timestamp
      convo.packet_count += 1
      convo.bytes += pkt.length
    })

    return Array.from(convoMap.values()).filter(c => 
      (c.src_ip && c.src_ip.includes(searchTerm)) || 
      (c.dst_ip && c.dst_ip.includes(searchTerm)) || 
      (c.protocol && c.protocol.toLowerCase().includes(searchTerm.toLowerCase()))
    ).sort((a, b) => b.end_time - a.end_time) // Sort by latest activity
  }, [packets, activeTab, searchTerm])

  const tabs = ['All', 'TCP', 'UDP', 'IPv4', 'IPv6', 'Ethernet', 'DNS', 'VoIP']

  return (
    <div className="glass-panel flex flex-col h-full overflow-hidden">
      <div className="flex items-center justify-between p-3 border-b border-white/5 bg-white/5">
        <h2 className="text-sm font-semibold tracking-wide text-white/90 flex items-center gap-2 uppercase">
          <Activity className="w-4 h-4 text-cyan-400" />
          Conversations
        </h2>
        <div className="relative">
          <Search className="w-4 h-4 absolute left-2 top-1/2 -translate-y-1/2 text-white/40" />
          <input
            type="text"
            placeholder="Filter IPs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-black/40 border border-white/10 rounded px-8 py-1 text-xs text-white placeholder-white/40 focus:outline-none focus:border-cyan-500 w-48"
          />
        </div>
      </div>
      
      {/* Tabs */}
      <div className="flex gap-1 px-3 pt-3 border-b border-white/5 overflow-x-auto no-scrollbar">
        {tabs.map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-3 py-1.5 text-xs rounded-t transition-colors whitespace-nowrap ${
              activeTab === tab 
                ? 'bg-cyan-500/20 text-cyan-400 border-b-2 border-cyan-400' 
                : 'text-white/60 hover:text-white/90 hover:bg-white/5'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs text-left">
          <thead className="text-white/50 bg-black/40 sticky top-0 uppercase tracking-wider text-[10px]">
            <tr>
              <th className="px-4 py-2 font-medium">Protocol</th>
              <th className="px-4 py-2 font-medium">Address A</th>
              <th className="px-4 py-2 font-medium">Port A</th>
              <th className="px-4 py-2 font-medium">Address B</th>
              <th className="px-4 py-2 font-medium">Port B</th>
              <th className="px-4 py-2 font-medium text-right">Packets</th>
              <th className="px-4 py-2 font-medium text-right">Bytes</th>
              <th className="px-4 py-2 font-medium">Risk / Geo</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {conversations.map((conv) => {
              const flowData = flows[conv.flow_id]
              const threat = flowData?.threat?.level || 'Low'
              const geo = flowData?.geoip?.country || 'Unknown'
              
              return (
                <tr key={conv.flow_id} className="hover:bg-white/5 transition-colors group">
                  <td className="px-4 py-2 text-cyan-400 font-mono">{conv.protocol}</td>
                  <td className="px-4 py-2 font-mono text-white/80">{conv.src_ip}</td>
                  <td className="px-4 py-2 text-white/60">{conv.src_port || '-'}</td>
                  <td className="px-4 py-2 font-mono text-white/80">{conv.dst_ip}</td>
                  <td className="px-4 py-2 text-white/60">{conv.dst_port || '-'}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-white/90">{conv.packet_count.toLocaleString()}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-white/60">{(conv.bytes / 1024).toFixed(1)} KB</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                        threat === 'High' ? 'bg-rose-500/20 text-rose-400' :
                        threat === 'Medium' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-white/5 text-white/40'
                      }`}>
                        {threat}
                      </span>
                      <span className="text-white/40 flex items-center gap-1">
                        <Globe className="w-3 h-3" />
                        {geo}
                      </span>
                    </div>
                  </td>
                </tr>
              )
            })}
            {conversations.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-white/40">
                  No conversations match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
