import { create } from 'zustand'

export interface PacketRecord {
  flow_id: string
  source_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  protocol: string
  length: number
  timestamp: number
  summary: string
  tcp_flags?: string
  payload_preview?: string
  tcp_state?: string
}

export interface AlertRecord {
  alert_id: string
  flow_id: string
  severity: string
  rule: string
  description: string
  confidence: number
  timestamp: string
}

export interface VoipSessionRecord {
  call_id: string
  start_time: string
  end_time: string
  caller_ip?: string
  callee_ip?: string
  turn_servers: string[]
  confidence_score: number
  confidence_tier: string
  joined_mid_session: boolean
  jitter: number
  loss: number
  mos: number
  mos_label: string
  warnings: string[]
  media_streams: {
    ssrc: number
    payload_type: number
    packets_count: number
    bytes_count: number
  }[]
  graph?: any
  endpoints?: any[]
}

interface CaptureState {
  packets: PacketRecord[]
  flows: Record<string, any>
  alerts: AlertRecord[]
  voipSessions: Record<string, VoipSessionRecord>
  
  isCapturing: boolean
  isPaused: boolean
  currentInterface: string | null
  totalPackets: number
  droppedFrames: number
  storageFailure: boolean
  displayFilter: string
  
  setDisplayFilter: (filter: string) => void
  setCapturing: (val: boolean) => void
  setPaused: (val: boolean) => void
  setInterface: (iface: string | null) => void
  setDroppedFrames: (count: number) => void
  setStorageFailure: (fail: boolean) => void
  
  addBatch: (batch: { packets?: PacketRecord[], alerts?: AlertRecord[], voip?: VoipSessionRecord, flow_updates?: Record<string, any> }) => void
  clearStore: () => void
}

const PACKET_LIMIT = 50000
const EVICTION_SIZE = 5000 // Evict oldest 10%

export const useCaptureStore = create<CaptureState>((set) => ({
  packets: [],
  flows: {},
  alerts: [],
  voipSessions: {},
  
  isCapturing: false,
  isPaused: false,
  currentInterface: null,
  totalPackets: 0,
  droppedFrames: 0,
  storageFailure: false,
  displayFilter: '',

  setDisplayFilter: (filter) => set({ displayFilter: filter }),
  setCapturing: (val) => set({ isCapturing: val }),
  setPaused: (val) => set({ isPaused: val }),
  setInterface: (iface) => set({ currentInterface: iface }),
  setDroppedFrames: (count) => set({ droppedFrames: count }),
  setStorageFailure: (fail) => set({ storageFailure: fail }),

  addBatch: (batch) => set((state) => {
    let newPackets = [...state.packets]
    if (batch.packets && batch.packets.length > 0) {
      newPackets.push(...batch.packets)
      // Enforce hard memory limits and GC safety
      if (newPackets.length > PACKET_LIMIT) {
        newPackets.splice(0, EVICTION_SIZE)
      }
    }

    const newFlows = { ...state.flows }
    if (batch.flow_updates) {
      Object.assign(newFlows, batch.flow_updates)
    }

    const newAlerts = [...state.alerts]
    if (batch.alerts && batch.alerts.length > 0) {
      newAlerts.push(...batch.alerts)
      if (newAlerts.length > 1000) {
        newAlerts.splice(0, 100)
      }
      // Check for STORAGE_FAILURE alerts
      const hasStorageFail = batch.alerts.some(a => a.rule === "STORAGE_FAILURE")
      if (hasStorageFail) {
        state.storageFailure = true // fallback but let's return it cleanly
      }
    }

    const newVoip = { ...state.voipSessions }
    if (batch.voip) {
      newVoip[batch.voip.call_id] = batch.voip
    }

    return {
      packets: newPackets,
      flows: newFlows,
      alerts: newAlerts,
      voipSessions: newVoip,
      storageFailure: batch.alerts && batch.alerts.some(a => a.rule === "STORAGE_FAILURE") ? true : state.storageFailure,
      totalPackets: state.totalPackets + (batch.packets?.length || 0)
    }
  }),

  clearStore: () => set({
    packets: [],
    flows: {},
    alerts: [],
    voipSessions: {},
    totalPackets: 0,
    droppedFrames: 0,
    storageFailure: false
  })
}))
