import React, { useMemo, useRef } from 'react'
import { useCaptureStore } from '../store/useCaptureStore'
import { Line } from 'react-chartjs-2'
import { Activity } from 'lucide-react'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Filler,
  Legend,
} from 'chart.js'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Filler,
  Legend
)

// Stable empty chart data to avoid recreating objects
const EMPTY_DATA = {
  labels: [] as string[],
  datasets: [
    {
      fill: true,
      label: 'Packets/s',
      data: [] as number[],
      borderColor: 'rgb(34, 211, 238)',
      backgroundColor: 'rgba(34, 211, 238, 0.1)',
      tension: 0.4,
      pointRadius: 0,
      borderWidth: 2,
    },
    {
      fill: true,
      label: 'Alerts/s',
      data: [] as number[],
      borderColor: 'rgb(244, 63, 94)',
      backgroundColor: 'rgba(244, 63, 94, 0.2)',
      tension: 0.4,
      pointRadius: 0,
      borderWidth: 2,
    },
  ],
}

const OPTIONS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 0 },
  plugins: {
    legend: {
      display: false,
    },
    tooltip: {
      mode: 'index' as const,
      intersect: false,
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      titleColor: '#fff',
      bodyColor: '#fff',
      borderColor: 'rgba(255,255,255,0.1)',
      borderWidth: 1
    },
  },
  scales: {
    x: {
      display: false,
      grid: {
        display: false,
        drawBorder: false,
      }
    },
    y: {
      display: true,
      grid: {
        color: 'rgba(255, 255, 255, 0.05)',
        drawBorder: false,
      },
      ticks: {
        color: 'rgba(255, 255, 255, 0.5)',
        font: { size: 10 }
      }
    },
  },
  interaction: {
    mode: 'nearest' as const,
    axis: 'x' as const,
    intersect: false,
  },
}

export default function TimelineView() {
  const packets = useCaptureStore(state => state.packets)
  const alerts = useCaptureStore(state => state.alerts)
  const lastComputeRef = useRef<number>(0)
  const cachedDataRef = useRef(EMPTY_DATA)

  const data = useMemo(() => {
    // Throttle: only recompute every 2 seconds
    const now = Date.now()
    if (now - lastComputeRef.current < 2000 && cachedDataRef.current.labels.length > 0) {
      return cachedDataRef.current
    }
    lastComputeRef.current = now

    if (packets.length === 0) return EMPTY_DATA

    // Only scan the last 500 packets for timestamp range (much cheaper than all 50k)
    const recentPackets = packets.slice(-500)

    const packetsByTime = new Map<number, number>()
    const alertsByTime = new Map<number, number>()

    // Get last 30 seconds relative to latest packet (narrower window = fewer chart points)
    let maxTime = 0
    recentPackets.forEach(p => { if (p.timestamp > maxTime) maxTime = p.timestamp })
    if (maxTime === 0) maxTime = Date.now() / 1000

    const minTime = maxTime - 30

    recentPackets.forEach(p => {
      if (p.timestamp >= minTime) {
        const sec = Math.floor(p.timestamp)
        packetsByTime.set(sec, (packetsByTime.get(sec) || 0) + 1)
      }
    })

    // Only process recent alerts
    const recentAlerts = alerts.slice(-100)
    recentAlerts.forEach(a => {
      if (!a || !a.timestamp) return
      const ts = new Date(a.timestamp).getTime() / 1000
      if (ts >= minTime) {
        const sec = Math.floor(ts)
        alertsByTime.set(sec, (alertsByTime.get(sec) || 0) + 1)
      }
    })

    const labels: string[] = []
    const packetData: number[] = []
    const alertData: number[] = []

    for (let i = Math.floor(minTime); i <= Math.floor(maxTime); i++) {
      const d = new Date(i * 1000)
      labels.push(`${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`)
      packetData.push(packetsByTime.get(i) || 0)
      alertData.push(alertsByTime.get(i) || 0)
    }

    const result = {
      labels,
      datasets: [
        {
          fill: true,
          label: 'Packets/s',
          data: packetData,
          borderColor: 'rgb(34, 211, 238)',
          backgroundColor: 'rgba(34, 211, 238, 0.1)',
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          fill: true,
          label: 'Alerts/s',
          data: alertData,
          borderColor: 'rgb(244, 63, 94)',
          backgroundColor: 'rgba(244, 63, 94, 0.2)',
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    }
    cachedDataRef.current = result
    return result
  }, [packets, alerts])

  return (
    <div className="glass-panel flex flex-col h-full overflow-hidden">
      <div className="flex items-center justify-between p-3 border-b border-white/5 bg-white/5">
        <h2 className="text-sm font-semibold tracking-wide text-white/90 flex items-center gap-2 uppercase">
          <Activity className="w-4 h-4 text-cyan-400" />
          Real-Time Timeline
        </h2>
        <div className="flex gap-4 text-xs font-mono">
          <span className="text-cyan-400 flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-cyan-400"></div> Packets
          </span>
          <span className="text-rose-400 flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-rose-500"></div> Alerts
          </span>
        </div>
      </div>
      <div className="flex-1 p-4 min-h-[150px]">
        <Line options={OPTIONS} data={data} />
      </div>
    </div>
  )
}
