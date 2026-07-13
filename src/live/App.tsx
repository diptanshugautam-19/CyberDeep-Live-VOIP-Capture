import React, { useEffect, useRef, useState } from 'react'
import { LayoutGrid, ShieldAlert, Phone, HelpCircle, Activity, Home, ArrowLeft, FolderOpen } from 'lucide-react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import ControlPanel from './components/ControlPanel'
import PacketGrid from './components/PacketGrid'
import VoipDashboard from './components/VoipDashboard'
import McpDashboard from './components/McpDashboard'

import Topology3D from './components/Topology3D'
import ConversationsView from './components/ConversationsView'
import TimelineView from './components/TimelineView'
import { useCaptureStore } from './store/useCaptureStore'

export default function App() {
  const isCapturing = useCaptureStore(state => state.isCapturing)
  const setCapturing = useCaptureStore(state => state.setCapturing)
  const addBatch = useCaptureStore(state => state.addBatch)
  const clearStore = useCaptureStore(state => state.clearStore)
  const setDroppedFrames = useCaptureStore(state => state.setDroppedFrames)
  
  const [viewMode, setViewMode] = useState<'live' | 'offline'>('live')
  const [topTab, setTopTab] = useState('topology')

  const [bottomTab, setBottomTab] = useState('packets')
  const [topologyActive, setTopologyActive] = useState(true)

  // Set default API key from localStorage if it exists
  const [apiKey, setApiKey] = useState(() => {
    return localStorage.getItem('wirestream_api_key') || '943b5e69da2130b5d7121dc5d469bf6adbfd60b5'
  })
  
  const [socket, setSocket] = useState<WebSocket | null>(null)
  
  // Save API key when changed
  useEffect(() => {
    localStorage.setItem('wirestream_api_key', apiKey)
  }, [apiKey])

  const handleConnect = async (iface: string, bpf: string) => {
    clearStore()
    setCapturing(true)

    try {
      const ticketRes = await fetch('/api/auth/ticket', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (!ticketRes.ok) {
        throw new Error("Failed to authenticate token and fetch WebSocket ticket.")
      }
      const { ticket } = await ticketRes.json()

      const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${wsProto}//${window.location.host}/api/capture/live?ticket=${ticket}`
      
      const ws = new WebSocket(wsUrl)
      
      ws.onopen = () => {
        console.log("WebSocket connection established.")
      }
      
      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data)
          
          if (payload.type === "batch") {
            if (typeof payload.dropped_frames === "number") {
              setDroppedFrames(payload.dropped_frames)
            }
            
            const batchData = payload.data || []
            const packetsBatch: any[] = []
            const alertsBatch: any[] = []
            
            for (const item of batchData) {
              if (item.type === "packet") {
                packetsBatch.push(item)
              } else if (item.type === "alert") {
                alertsBatch.push(item.alert)
              } else if (item.type === "voip_update") {
                addBatch({ voip: item.session })
              } else if (item.type === "enrichment") {
                addBatch({
                  flow_updates: {
                    [item.flow_id]: {
                      ip: item.ip,
                      geoip: item.geoip,
                      threat: item.threat,
                      classification: item.classification,
                      history_count: item.history_count
                    }
                  }
                })
              }
            }
            
            if (packetsBatch.length > 0 || alertsBatch.length > 0) {
              addBatch({ packets: packetsBatch, alerts: alertsBatch })
            }
          }
        } catch (err) {
          console.error("Failed to parse WS frame:", err)
        }
      }
      
      ws.onclose = () => {
        console.log("WebSocket connection closed.")
        setCapturing(false)
      }
      
      ws.onerror = (err) => {
        console.error("WebSocket error:", err)
        setCapturing(false)
      }
      
      setSocket(ws)

    } catch (e: any) {
      console.error(e)
      setCapturing(false)
    }
  }

  const handleDisconnect = () => {
    setCapturing(false)
    if (socket) {
      socket.close()
      setSocket(null)
    }
  }

  useEffect(() => {
    return () => {
      if (socket) {
        socket.close()
      }
    }
  }, [socket])

  return (
    <div className="min-h-screen bg-[#020408] cyber-grid flex overflow-hidden h-screen text-slate-200">
      
      {/* 1. Left Sidebar Navigation */}
      <div className="w-16 bg-[#04060a]/90 border-r border-cyan-950/40 flex flex-col items-center py-6 gap-6 z-20">
        <div className="w-9 h-9 rounded bg-cyan-950/20 border border-cyan-800/40 flex items-center justify-center text-cyan-400 font-bold font-mono text-sm tracking-wider">
          CD
        </div>
        
        <div className="flex-1 flex flex-col gap-4 w-full px-2">
          <button 
            onClick={() => setViewMode('live')}
            className={`w-full aspect-square rounded flex items-center justify-center transition-colors ${viewMode === 'live' ? 'text-cyan-400 bg-cyan-950/20 border border-cyan-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'}`}
            title="Live Capture Mode"
          >
            <Activity className="w-5 h-5" />
          </button>
          
          <button 
            onClick={() => setViewMode('offline')}
            className={`w-full aspect-square rounded flex items-center justify-center transition-colors ${viewMode === 'offline' ? 'text-cyan-400 bg-cyan-950/20 border border-cyan-500/20' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'}`}
            title="Offline PCAP Mode (MCP)"
          >
            <FolderOpen className="w-5 h-5" />
          </button>

          <a href="/tool" className="w-full aspect-square rounded flex items-center justify-center text-slate-400 hover:text-slate-200 hover:bg-slate-900/50 transition-colors" title="Offline IP Intel Tool">
            <Home className="w-5 h-5" />
          </a>
          <a href="/" className="w-full aspect-square rounded flex items-center justify-center text-slate-400 hover:text-slate-200 hover:bg-slate-900/50 transition-colors" title="CyberDeep Home">
            <ArrowLeft className="w-5 h-5" />
          </a>
        </div>
        
        <div className="w-9 h-9 rounded-full bg-slate-900/80 border border-slate-800 flex items-center justify-center text-slate-500 hover:text-slate-300 cursor-pointer">
          <HelpCircle className="w-4 h-4" />
        </div>
      </div>

      {/* 2. Main content area */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden p-4 gap-4">
        
        {viewMode === 'live' ? (
          <>
            {/* Top Control Panel Banner */}
            <ControlPanel 
              apiKey={apiKey}
              setApiKey={setApiKey}
              onConnect={handleConnect}
              onDisconnect={handleDisconnect}
            />

            {/* Resizable Panel Workspace */}
            <div className="flex-grow min-h-0 relative">
              <PanelGroup direction="horizontal">
                {/* Left Area (Workspace): Topo/Timeline + Packet List/Conversations */}
                <Panel defaultSize={65} minSize={30}>
                  <PanelGroup direction="vertical">
                    {/* Top Half: 3D Topology or Timeline */}
                    <Panel defaultSize={50} minSize={20}>
                      <div className="h-full flex flex-col min-h-0 relative">
                        <div className="absolute top-2 left-2 z-10 flex items-center gap-2 bg-black/40 p-1 rounded border border-white/10 backdrop-blur">
                          <button onClick={() => setTopTab('topology')} className={`px-2 py-1 text-xs rounded transition-colors ${topTab === 'topology' ? 'bg-cyan-500/20 text-cyan-400' : 'text-white/60 hover:text-white/90'}`}>3D Topology</button>
                          <button onClick={() => setTopTab('timeline')} className={`px-2 py-1 text-xs rounded transition-colors ${topTab === 'timeline' ? 'bg-cyan-500/20 text-cyan-400' : 'text-white/60 hover:text-white/90'}`}>Timeline</button>
                          
                          {topTab === 'topology' && (
                            <div className="flex items-center gap-1 pl-2 border-l border-white/10">
                              <span className="text-[10px] text-slate-400 font-mono">Render:</span>
                              <button 
                                onClick={() => setTopologyActive(!topologyActive)}
                                className={`px-1.5 py-0.5 text-[9px] rounded font-semibold transition-colors ${topologyActive ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}
                              >
                                {topologyActive ? 'ON' : 'OFF'}
                              </button>
                            </div>
                          )}
                        </div>
                        {topTab === 'topology' ? (
                          topologyActive ? (
                            <Topology3D />
                          ) : (
                            <div className="h-full flex flex-col items-center justify-center bg-[#04060a]/20 border border-cyan-900/10 rounded font-mono text-xs text-slate-500">
                              <span>3D Topology is paused to save memory & CPU</span>
                              <button 
                                onClick={() => setTopologyActive(true)}
                                className="mt-2 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-[11px] font-semibold transition-all"
                              >
                                Resume Render ▶️
                              </button>
                            </div>
                          )
                        ) : (
                          <TimelineView />
                        )}
                      </div>
                    </Panel>
                    
                    <PanelResizeHandle className="h-1 bg-cyan-950/20 hover:bg-cyan-500/50 active:bg-cyan-400 transition-colors cursor-row-resize my-1 rounded" />
                    
                    {/* Bottom Half: Raw Packets or Conversations */}
                    <Panel defaultSize={50} minSize={20}>
                      <div className="h-full flex flex-col min-h-0 relative">
                         <div className="absolute top-2 left-2 z-10 flex gap-1 bg-black/40 p-1 rounded border border-white/10 backdrop-blur">
                          <button onClick={() => setBottomTab('packets')} className={`px-2 py-1 text-xs rounded transition-colors ${bottomTab === 'packets' ? 'bg-cyan-500/20 text-cyan-400' : 'text-white/60 hover:text-white/90'}`}>Raw Packets</button>
                          <button onClick={() => setBottomTab('conversations')} className={`px-2 py-1 text-xs rounded transition-colors ${bottomTab === 'conversations' ? 'bg-cyan-500/20 text-cyan-400' : 'text-white/60 hover:text-white/90'}`}>Conversations</button>
                        </div>
                        {bottomTab === 'packets' ? <PacketGrid apiKey={apiKey} /> : <ConversationsView />}
                      </div>
                    </Panel>
                  </PanelGroup>
                </Panel>
                
                <PanelResizeHandle className="w-1 bg-cyan-950/20 hover:bg-cyan-500/50 active:bg-cyan-400 transition-colors cursor-col-resize mx-1.5 rounded" />
                
                {/* Right Area: VoIP Analysis & Scrolling Alerts */}
                <Panel defaultSize={35} minSize={20}>
                  <div className="h-full flex flex-col min-h-0 overflow-hidden">
                    <VoipDashboard />
                  </div>
                </Panel>
              </PanelGroup>
            </div>
          </>
        ) : (
          <McpDashboard />
        )}
      </div>
    </div>
  )
}

