import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react'
import { FixedSizeList as List } from 'react-window'
import { useCaptureStore, PacketRecord } from '../store/useCaptureStore'
import { Eye, FileText, X, Filter, ChevronRight, ChevronDown } from 'lucide-react'

// ---- Wireshark-style Display Filter Engine ----

const KNOWN_PROTOCOLS = ['sip', 'rtp', 'stun', 'turn', 'tls', 'dns', 'tcp', 'udp', 'icmp', 'ip', 'http']

type FilterNode =
  | { type: 'protocol'; value: string }
  | { type: 'field'; field: string; op: string; value: string }
  | { type: 'and'; left: FilterNode; right: FilterNode }
  | { type: 'or'; left: FilterNode; right: FilterNode }
  | { type: 'not'; child: FilterNode }
  | { type: 'true' }

function tokenize(expr: string): string[] {
  const tokens: string[] = []
  let i = 0
  while (i < expr.length) {
    if (expr[i] === ' ' || expr[i] === '\t') { i++; continue }
    if (expr[i] === '(' || expr[i] === ')') { tokens.push(expr[i]); i++; continue }
    if (expr[i] === '!' && expr[i + 1] === '=') { tokens.push('!='); i += 2; continue }
    if (expr[i] === '!' ) { tokens.push('not'); i++; continue }
    if (expr[i] === '=' && expr[i + 1] === '=') { tokens.push('=='); i += 2; continue }
    if (expr[i] === '>' && expr[i + 1] === '=') { tokens.push('>='); i += 2; continue }
    if (expr[i] === '<' && expr[i + 1] === '=') { tokens.push('<='); i += 2; continue }
    if (expr[i] === '>') { tokens.push('>'); i++; continue }
    if (expr[i] === '<') { tokens.push('<'); i++; continue }
    // Read a word
    let word = ''
    while (i < expr.length && expr[i] !== ' ' && expr[i] !== '\t' && expr[i] !== '(' && expr[i] !== ')') {
      word += expr[i]; i++
    }
    tokens.push(word)
  }
  return tokens
}

function parseFilter(expr: string): { node: FilterNode | null; valid: boolean } {
  const trimmed = expr.trim()
  if (!trimmed) return { node: { type: 'true' }, valid: true }
  try {
    const tokens = tokenize(trimmed)
    let pos = 0

    function parseOr(): FilterNode {
      let left = parseAnd()
      while (pos < tokens.length && (tokens[pos] === 'or' || tokens[pos] === '||')) {
        pos++
        const right = parseAnd()
        left = { type: 'or', left, right }
      }
      return left
    }

    function parseAnd(): FilterNode {
      let left = parseNot()
      while (pos < tokens.length && (tokens[pos] === 'and' || tokens[pos] === '&&')) {
        pos++
        const right = parseNot()
        left = { type: 'and', left, right }
      }
      return left
    }

    function parseNot(): FilterNode {
      if (pos < tokens.length && (tokens[pos] === 'not' || tokens[pos] === '!')) {
        pos++
        const child = parseNot()
        return { type: 'not', child }
      }
      return parsePrimary()
    }

    function parsePrimary(): FilterNode {
      if (pos < tokens.length && tokens[pos] === '(') {
        pos++ // skip (
        const node = parseOr()
        if (pos < tokens.length && tokens[pos] === ')') pos++ // skip )
        return node
      }

      const tok = tokens[pos] || ''
      
      // Check if next token is an operator (field == value)
      if (pos + 2 < tokens.length && ['==', '!=', '>', '<', '>=', '<=', 'contains', 'matches'].includes(tokens[pos + 1])) {
        const field = tokens[pos]
        const op = tokens[pos + 1]
        const value = tokens[pos + 2]
        pos += 3
        return { type: 'field', field: field.toLowerCase(), op, value }
      }

      // Protocol name
      pos++
      return { type: 'protocol', value: tok.toLowerCase() }
    }

    const node = parseOr()
    if (pos < tokens.length) return { node: null, valid: false }
    return { node, valid: true }
  } catch {
    return { node: null, valid: false }
  }
}

function evalFilter(node: FilterNode, p: PacketRecord): boolean {
  switch (node.type) {
    case 'true': return true
    case 'and': return evalFilter(node.left, p) && evalFilter(node.right, p)
    case 'or': return evalFilter(node.left, p) || evalFilter(node.right, p)
    case 'not': return !evalFilter(node.child, p)
    case 'protocol': {
      const v = node.value
      const proto = (p.protocol || '').toLowerCase()
      if (KNOWN_PROTOCOLS.includes(v)) return proto === v
      // Also try matching as IP address substring
      return (p.source_ip && p.source_ip.includes(v)) ||
             (p.destination_ip && p.destination_ip.includes(v)) || false
    }
    case 'field': {
      const { field, op, value } = node
      let actual: string | number | undefined

      // Wireshark-style field mappings
      if (field === 'ip.src') actual = p.source_ip
      else if (field === 'ip.dst') actual = p.destination_ip
      else if (field === 'ip.addr') {
        // ip.addr matches either src or dst
        return compareField(p.source_ip, op, value) || compareField(p.destination_ip, op, value)
      }
      else if (field === 'tcp.port' || field === 'udp.port' || field === 'port') {
        const portNum = parseInt(value, 10)
        return p.source_port === portNum || p.destination_port === portNum
      }
      else if (field === 'tcp.srcport' || field === 'udp.srcport') actual = p.source_port
      else if (field === 'tcp.dstport' || field === 'udp.dstport') actual = p.destination_port
      else if (field === 'frame.len' || field === 'length') actual = p.length
      else if (field === 'tcp.flags') actual = p.tcp_flags
      else actual = undefined

      return compareField(actual, op, value)
    }
  }
}

function compareField(actual: any, op: string, value: string): boolean {
  if (actual === undefined || actual === null) return false
  const strActual = String(actual).toLowerCase()
  const strValue = value.toLowerCase()
  
  if (op === '==' || op === 'eq') return strActual === strValue
  if (op === '!=' || op === 'ne') return strActual !== strValue
  if (op === 'contains') return strActual.includes(strValue)
  
  // Numeric comparisons
  const numA = Number(actual)
  const numV = Number(value)
  if (isNaN(numA) || isNaN(numV)) return false
  if (op === '>') return numA > numV
  if (op === '<') return numA < numV
  if (op === '>=') return numA >= numV
  if (op === '<=') return numA <= numV
  return false
}

// ---- Protocol Color Map (Wireshark-style) ----

const PROTO_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  SIP:  { bg: 'bg-purple-950/30', border: 'border-l-2 border-purple-500', text: 'text-purple-400' },
  RTP:  { bg: 'bg-emerald-950/20', border: 'border-l-2 border-emerald-500', text: 'text-emerald-400' },
  STUN: { bg: 'bg-blue-950/20', border: 'border-l-2 border-blue-500', text: 'text-blue-400' },
  TURN: { bg: 'bg-blue-950/20', border: 'border-l-2 border-blue-400', text: 'text-blue-300' },
  DNS:  { bg: 'bg-amber-950/20', border: 'border-l-2 border-amber-500', text: 'text-amber-400' },
  TLS:  { bg: 'bg-sky-950/20', border: 'border-l-2 border-sky-500', text: 'text-sky-400' },
  TCP:  { bg: 'bg-slate-900/30', border: 'border-l-2 border-slate-500', text: 'text-slate-300' },
  UDP:  { bg: 'bg-cyan-950/20', border: 'border-l-2 border-cyan-600', text: 'text-cyan-400' },
  ICMP: { bg: 'bg-rose-950/20', border: 'border-l-2 border-rose-500', text: 'text-rose-400' },
}

const DEFAULT_COLOR = { bg: '', border: 'border-l-2 border-slate-700', text: 'text-slate-400' }

// ---- Component ----

export default function PacketGrid({ apiKey }: { apiKey: string }) {
  const packets = useCaptureStore(state => state.packets)
  const displayFilter = useCaptureStore(state => state.displayFilter)
  const setDisplayFilter = useCaptureStore(state => state.setDisplayFilter)

  const [selectedPkt, setSelectedPkt] = useState<PacketRecord | null>(null)
  const [streamData, setStreamData] = useState<any[] | null>(null)
  const [loadingStream, setLoadingStream] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    frame: true, ip: true, transport: true, payload: false
  })

  const containerRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<any>(null)
  const [dimensions, setDimensions] = useState({ width: 600, height: 350 })

  useEffect(() => {
    if (!containerRef.current) return
    const resizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) {
        setDimensions({
          width: entry.contentRect.width,
          height: entry.contentRect.height
        })
      }
    })
    resizeObserver.observe(containerRef.current)
    return () => resizeObserver.disconnect()
  }, [])

  // Parse the display filter once
  const parsedFilter = useMemo(() => parseFilter(displayFilter), [displayFilter])

  // Apply parsed filter to packets
  const filteredPackets = useMemo(() => {
    if (!displayFilter.trim()) return packets
    if (!parsedFilter.valid || !parsedFilter.node) return []
    return packets.filter(p => evalFilter(parsedFilter.node!, p))
  }, [packets, displayFilter, parsedFilter])

  // Determine filter bar state
  const filterBarState = useMemo(() => {
    if (!displayFilter.trim()) return 'empty'  // no filter
    if (!parsedFilter.valid) return 'invalid'    // red
    return 'valid'                               // green
  }, [displayFilter, parsedFilter])

  useEffect(() => {
    if (autoScroll && listRef.current && filteredPackets.length > 0) {
      listRef.current.scrollToItem(filteredPackets.length - 1, 'end')
    }
  }, [filteredPackets.length, autoScroll])

  const handleFollowStream = async (flowId: string) => {
    setLoadingStream(true)
    setStreamData(null)
    try {
      const res = await fetch(`/api/capture/stream/follow?flow_id=${encodeURIComponent(flowId)}`, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      })
      if (res.ok) {
        const data = await res.json()
        setStreamData(data.stream || [])
      }
    } catch (err) {
      console.error("Failed to load stream follow:", err)
    } finally {
      setLoadingStream(false)
    }
  }

  const toggleSection = useCallback((key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }))
  }, [])

  const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => {
    const pkt = filteredPackets[index]
    if (!pkt) return null
    const colors = PROTO_COLORS[pkt.protocol?.toUpperCase()] || DEFAULT_COLOR
    const isSelected = selectedPkt?.flow_id === pkt.flow_id && selectedPkt?.timestamp === pkt.timestamp
    
    return (
      <div 
        style={style}
        onClick={() => {
          setSelectedPkt(pkt)
          setStreamData(null)
        }}
        className={`flex items-center text-xs font-mono border-b border-slate-900/50 cursor-pointer transition-colors ${colors.border} ${colors.bg} ${
          isSelected ? 'bg-cyan-900/40 ring-1 ring-cyan-500/30' : 'hover:bg-slate-800/40'
        }`}
      >
        <div className="w-14 px-2 truncate text-slate-500 tabular-nums">{index + 1}</div>
        <div className="w-24 px-2 truncate text-slate-400 tabular-nums">{(pkt.timestamp % 1000).toFixed(3)}</div>
        <div className="w-36 px-2 truncate text-slate-200">{pkt.source_ip}{pkt.source_port ? `:${pkt.source_port}` : ''}</div>
        <div className="w-10 px-1 text-center text-slate-600">→</div>
        <div className="w-36 px-2 truncate text-slate-200">{pkt.destination_ip}{pkt.destination_port ? `:${pkt.destination_port}` : ''}</div>
        <div className={`w-14 px-2 truncate text-center font-bold ${colors.text}`}>{pkt.protocol}</div>
        <div className="w-14 px-2 truncate text-right text-slate-500 tabular-nums">{pkt.length}</div>
        <div className="flex-1 px-2 truncate text-slate-400">{pkt.summary}</div>
      </div>
    )
  }

  // Wireshark-style tree section header
  const TreeSection = ({ label, sectionKey, children }: { label: string; sectionKey: string; children: React.ReactNode }) => {
    const open = expandedSections[sectionKey] ?? false
    return (
      <div className="border-b border-slate-800/50">
        <button onClick={() => toggleSection(sectionKey)} className="flex items-center gap-1 w-full text-left py-1 px-2 hover:bg-slate-800/30 text-xs font-mono text-slate-300">
          {open ? <ChevronDown className="w-3 h-3 text-slate-500" /> : <ChevronRight className="w-3 h-3 text-slate-500" />}
          <span className="font-bold text-cyan-400">{label}</span>
        </button>
        {open && <div className="pl-5 pb-1">{children}</div>}
      </div>
    )
  }

  const DetailRow = ({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) => (
    <div className="flex text-[11px] font-mono py-0.5">
      <span className="text-slate-500 w-32 flex-shrink-0">{label}:</span>
      <span className={color || 'text-slate-200'}>{value}</span>
    </div>
  )

  return (
    <div className="glass-panel flex-1 flex flex-col min-h-[300px] overflow-hidden">
      {/* ===== WIRESHARK-STYLE DISPLAY FILTER BAR ===== */}
      <div className="bg-[#04060a] border-b border-cyan-800/40 p-1.5 flex items-center gap-2">
        <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider flex-shrink-0 px-1">Display Filter</span>
        <div className={`flex items-center gap-2 rounded px-2 py-1 flex-1 border transition-all ${
          filterBarState === 'valid'   ? 'bg-emerald-950/30 border-emerald-600/50' :
          filterBarState === 'invalid' ? 'bg-rose-950/30 border-rose-600/50' :
                                         'bg-black/40 border-cyan-900/50'
        }`}>
          <Filter className={`w-3.5 h-3.5 flex-shrink-0 ${
            filterBarState === 'valid' ? 'text-emerald-400' :
            filterBarState === 'invalid' ? 'text-rose-400' : 'text-cyan-500'
          }`} />
          <input 
            type="text"
            placeholder="sip || rtp || stun    ip.src == 10.0.0.1    tcp.port == 5060    dns and ip.dst == 8.8.8.8"
            value={displayFilter}
            onChange={(e) => setDisplayFilter(e.target.value)}
            className="bg-transparent text-xs text-slate-200 focus:outline-none w-full placeholder:text-slate-600 font-mono"
          />
          {displayFilter && (
            <button onClick={() => setDisplayFilter('')} className="text-slate-500 hover:text-white flex-shrink-0">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
        
        {/* Quick Protocol Badges */}
        <div className="flex gap-1 items-center flex-shrink-0">
          {['SIP', 'RTP', 'STUN', 'DNS', 'TLS', 'TCP', 'UDP'].map(proto => {
            const isSelected = displayFilter.toLowerCase() === proto.toLowerCase()
            const colors = PROTO_COLORS[proto] || DEFAULT_COLOR
            return (
              <button
                key={proto}
                onClick={() => setDisplayFilter(isSelected ? '' : proto.toLowerCase())}
                className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border transition-all cursor-pointer ${
                  isSelected
                    ? `bg-cyan-500/20 ${colors.text} border-cyan-500/40`
                    : 'bg-[#0f172a]/60 text-slate-500 hover:text-slate-300 border-transparent hover:border-slate-700'
                }`}
              >
                {proto}
              </button>
            )
          })}
        </div>

        <div className="flex items-center gap-3 text-[10px] text-slate-500 font-mono flex-shrink-0 border-l border-slate-800 pl-2">
          <label className="flex items-center gap-1 cursor-pointer select-none">
            <input 
              type="checkbox" 
              checked={autoScroll} 
              onChange={(e) => setAutoScroll(e.target.checked)} 
              className="accent-cyan-500"
            />
            Auto
          </label>
          <span className="tabular-nums">{filteredPackets.length}/{packets.length}</span>
        </div>
      </div>

      {/* Column Header */}
      <div className="bg-[#0b101b] border-b border-cyan-800/20 px-0 py-1.5 flex items-center text-[10px] uppercase tracking-wider font-mono text-cyan-500/80 font-semibold select-none">
        <div className="w-14 px-2">No.</div>
        <div className="w-24 px-2">Time</div>
        <div className="w-36 px-2">Source</div>
        <div className="w-10 px-1 text-center"></div>
        <div className="w-36 px-2">Destination</div>
        <div className="w-14 px-2 text-center">Proto</div>
        <div className="w-14 px-2 text-right">Len</div>
        <div className="flex-1 px-2">Info</div>
      </div>

      {/* Packet List */}
      <div ref={containerRef} className="flex-1 min-h-0 bg-[#04060a]/40">
        {filteredPackets.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-xs text-slate-500 font-mono gap-1">
            {packets.length === 0 ? (
              <>
                <span className="text-slate-400">Waiting for packets...</span>
                <span className="text-[10px] text-slate-600">Start a capture to see live traffic</span>
              </>
            ) : filterBarState === 'invalid' ? (
              <>
                <span className="text-rose-400">Invalid display filter expression</span>
                <span className="text-[10px] text-slate-600">Examples: sip, ip.src == 10.0.0.1, rtp or stun</span>
              </>
            ) : (
              <span>No packets match the display filter.</span>
            )}
          </div>
        ) : (
          <List
            ref={listRef}
            height={dimensions.height || 350}
            itemCount={filteredPackets.length}
            itemSize={24}
            width="100%"
          >
            {Row}
          </List>
        )}
      </div>

      {/* ===== WIRESHARK-STYLE PACKET DETAIL PANE ===== */}
      {selectedPkt && (
        <div className="border-t border-cyan-800/40 bg-[#090d16] flex flex-col md:flex-row h-[280px] overflow-hidden">
          {/* Left: Protocol Tree */}
          <div className="flex-1 overflow-y-auto border-r border-slate-800/40">
            <div className="flex items-center justify-between bg-[#0b101b] border-b border-slate-800 px-2 py-1">
              <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider font-bold">Packet Details</span>
              <button onClick={() => setSelectedPkt(null)} className="text-slate-500 hover:text-white">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Frame */}
            <TreeSection label={`Frame ${filteredPackets.indexOf(selectedPkt) + 1}: ${selectedPkt.length} bytes`} sectionKey="frame">
              <DetailRow label="Arrival Time" value={(selectedPkt.timestamp % 1000).toFixed(6)} />
              <DetailRow label="Frame Length" value={`${selectedPkt.length} bytes`} />
              <DetailRow label="Flow ID" value={selectedPkt.flow_id} color="text-slate-400" />
            </TreeSection>

            {/* IP Layer */}
            <TreeSection label={`Internet Protocol, Src: ${selectedPkt.source_ip || '?'}, Dst: ${selectedPkt.destination_ip || '?'}`} sectionKey="ip">
              <DetailRow label="Source Address" value={selectedPkt.source_ip} color="text-emerald-400" />
              <DetailRow label="Destination Address" value={selectedPkt.destination_ip} color="text-emerald-400" />
            </TreeSection>

            {/* Transport Layer */}
            <TreeSection label={`${selectedPkt.protocol === 'UDP' || selectedPkt.protocol === 'DNS' || selectedPkt.protocol === 'RTP' || selectedPkt.protocol === 'STUN' ? 'User Datagram Protocol' : 'Transmission Control Protocol'}, Src Port: ${selectedPkt.source_port || '?'}, Dst Port: ${selectedPkt.destination_port || '?'}`} sectionKey="transport">
              <DetailRow label="Source Port" value={selectedPkt.source_port} color="text-cyan-400" />
              <DetailRow label="Destination Port" value={selectedPkt.destination_port} color="text-cyan-400" />
              {selectedPkt.tcp_flags && (
                <DetailRow label="Flags" value={selectedPkt.tcp_flags} color="text-amber-400" />
              )}
              {selectedPkt.tcp_state && (
                <DetailRow label="Connection State" value={selectedPkt.tcp_state} color="text-emerald-400" />
              )}
            </TreeSection>

            {/* Application Layer */}
            {selectedPkt.payload_preview && (
              <TreeSection label={`${selectedPkt.protocol} Payload`} sectionKey="payload">
                <pre className="text-[10px] font-mono text-emerald-300/80 whitespace-pre-wrap break-all px-1 max-h-[120px] overflow-y-auto">
                  {selectedPkt.payload_preview}
                </pre>
              </TreeSection>
            )}
          </div>

          {/* Right: Follow Stream */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="flex items-center justify-between bg-[#0b101b] border-b border-slate-800 px-2 py-1">
              <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider font-bold flex items-center gap-1">
                <FileText className="w-3 h-3" /> Follow Stream
              </span>
              <button
                onClick={() => handleFollowStream(selectedPkt.flow_id)}
                className="bg-cyan-900/50 hover:bg-cyan-800 text-cyan-300 border border-cyan-700/30 rounded px-2 py-0.5 text-[9px] transition-colors font-semibold"
              >
                Reconstruct
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-2 text-[11px] font-mono">
              {loadingStream && <div className="text-slate-500">Reconstructing stream...</div>}
              {streamData && streamData.length === 0 && <div className="text-slate-500">No payloads recorded.</div>}
              {streamData && streamData.map((s, idx) => {
                const isSent = s.sport === selectedPkt.source_port
                return (
                  <div key={idx} className="mb-2">
                    <div className={`text-[10px] ${isSent ? 'text-cyan-400' : 'text-purple-400'} font-semibold mb-0.5`}>
                      {isSent ? '→ Client' : '← Server'}
                    </div>
                    <div className="pl-3 text-slate-300 break-all whitespace-pre-wrap">{s.payload}</div>
                  </div>
                )
              })}
              {!streamData && !loadingStream && <div className="text-slate-600 text-center mt-4">Click "Reconstruct" to follow stream</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
