import React, { useEffect, useRef, useCallback } from 'react'
import * as THREE from 'three'
import { Activity } from 'lucide-react'
import { useCaptureStore } from '../store/useCaptureStore'

const MAX_NODES = 100
const MAX_PARTICLES = 200
const MAX_LINKS = 150
const THROTTLE_MS = 1000

export default function Topology3D() {
  const containerRef = useRef<HTMLDivElement>(null)
  const packets = useCaptureStore(state => state.packets)

  // Three.js object references — persist across renders
  const sceneRef = useRef<THREE.Scene | null>(null)
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null)
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null)
  const nodesMeshRef = useRef<THREE.InstancedMesh | null>(null)
  const particlesMeshRef = useRef<THREE.InstancedMesh | null>(null)
  const animIdRef = useRef<number>(0)

  // Physics and graph structure references
  const nodesMap = useRef<Map<string, { pos: THREE.Vector3; color: THREE.Color; rank: number }>>(new Map())
  const velocities = useRef<Map<string, THREE.Vector3>>(new Map())
  const links = useRef<{ source: string; target: string }[]>([])
  const particles = useRef<{ start: THREE.Vector3; end: THREE.Vector3; progress: number; speed: number }[]>([])
  const lastUpdate = useRef<number>(0)

  // Stable color function — no alert dependency, just IP classification
  const getIPColor = useCallback((ip: string): THREE.Color => {
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
      return new THREE.Color('#00d2ff') // Local: Cyan
    }
    if (ip.includes(':')) {
      return new THREE.Color('#a78bfa') // IPv6: Purple
    }
    return new THREE.Color('#475569') // External: Dark Slate
  }, [])

  // === EFFECT 1: Create the scene ONCE on mount, destroy on unmount ===
  useEffect(() => {
    if (!containerRef.current) return

    const container = containerRef.current
    const width = container.clientWidth || 400
    const height = container.clientHeight || 300

    const scene = new THREE.Scene()
    sceneRef.current = scene
    scene.background = new THREE.Color('#04060a')

    const camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000)
    camera.position.set(0, 0, 80)
    cameraRef.current = camera

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(width, height)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    container.appendChild(renderer.domElement)
    rendererRef.current = renderer

    const ambientLight = new THREE.AmbientLight(0xffffff, 0.6)
    scene.add(ambientLight)
    const dirLight = new THREE.DirectionalLight(0x00d2ff, 1.2)
    dirLight.position.set(10, 20, 15)
    scene.add(dirLight)

    // InstancedMesh for Nodes
    const nodeGeometry = new THREE.SphereGeometry(1.2, 16, 16)
    const nodeMaterial = new THREE.MeshPhongMaterial({ shininess: 100 })
    const nodesMesh = new THREE.InstancedMesh(nodeGeometry, nodeMaterial, MAX_NODES)
    scene.add(nodesMesh)
    nodesMeshRef.current = nodesMesh

    // InstancedMesh for Transmission Particles
    const partGeometry = new THREE.BoxGeometry(0.3, 0.3, 0.3)
    const partMaterial = new THREE.MeshBasicMaterial({ color: 0x22d3ee })
    const particlesMesh = new THREE.InstancedMesh(partGeometry, partMaterial, MAX_PARTICLES)
    scene.add(particlesMesh)
    particlesMeshRef.current = particlesMesh

    const dummy = new THREE.Object3D()

    // Animation Loop — runs at browser refresh rate
    const animate = () => {
      animIdRef.current = requestAnimationFrame(animate)

      const nodesList = Array.from(nodesMap.current.entries())
      if (nodesList.length > 0) {
        const k = 20.0
        const friction = 0.8

        // Reset forces
        const forces = new Map<string, THREE.Vector3>()
        nodesList.forEach(([ip]) => {
          forces.set(ip, new THREE.Vector3(0, 0, 0))
          if (!velocities.current.has(ip)) {
            velocities.current.set(ip, new THREE.Vector3(0, 0, 0))
          }
        })

        // A. Repulsive Forces (Coulomb's Law)
        for (let i = 0; i < nodesList.length; i++) {
          const [ipA, nodeA] = nodesList[i]
          const forceA = forces.get(ipA)!

          for (let j = i + 1; j < nodesList.length; j++) {
            const [ipB, nodeB] = nodesList[j]
            const forceB = forces.get(ipB)!

            const dir = new THREE.Vector3().subVectors(nodeA.pos, nodeB.pos)
            const dist = dir.length() || 0.1
            if (dist < 120) {
              const mag = (k * k) / dist
              dir.normalize().multiplyScalar(mag * 0.05)
              forceA.add(dir)
              forceB.sub(dir)
            }
          }
        }

        // B. Attractive Forces (Hooke's Law)
        links.current.forEach(link => {
          const nodeA = nodesMap.current.get(link.source)
          const nodeB = nodesMap.current.get(link.target)
          if (nodeA && nodeB) {
            const forceA = forces.get(link.source)
            const forceB = forces.get(link.target)
            if (forceA && forceB) {
              const dir = new THREE.Vector3().subVectors(nodeB.pos, nodeA.pos)
              const dist = dir.length() || 0.1
              const mag = dist / k
              dir.normalize().multiplyScalar(mag * 0.08)
              forceA.add(dir)
              forceB.sub(dir)
            }
          }
        })

        // C. Apply Forces, Velocities, and Gravity
        nodesList.forEach(([ip, node]) => {
          const f = forces.get(ip)!
          const vel = velocities.current.get(ip)!

          // Gravity pull to origin
          const gravity = new THREE.Vector3().copy(node.pos).multiplyScalar(-0.01)
          f.add(gravity)

          vel.add(f).multiplyScalar(friction)
          vel.clampLength(0, 1.2)
          node.pos.add(vel)
        })

        // Update nodes InstancedMesh matrices and colors (colors are cached on the node)
        for (let i = 0; i < MAX_NODES; i++) {
          if (i < nodesList.length) {
            const [, n] = nodesList[i]
            dummy.position.copy(n.pos)
            dummy.updateMatrix()
            nodesMesh.setMatrixAt(i, dummy.matrix)
            nodesMesh.setColorAt(i, n.color)
          } else {
            dummy.position.set(9999, 9999, 9999)
            dummy.updateMatrix()
            nodesMesh.setMatrixAt(i, dummy.matrix)
          }
        }
        nodesMesh.instanceMatrix.needsUpdate = true
        if (nodesMesh.instanceColor) {
          nodesMesh.instanceColor.needsUpdate = true
        }
      }

      // Update transmission particles
      let activePartCount = 0
      for (let i = 0; i < particles.current.length; i++) {
        const p = particles.current[i]
        p.progress += p.speed

        if (p.progress >= 1.0) {
          particles.current.splice(i, 1)
          i--
          continue
        }

        dummy.position.lerpVectors(p.start, p.end, p.progress)
        dummy.updateMatrix()
        particlesMesh.setMatrixAt(activePartCount, dummy.matrix)
        activePartCount++

        if (activePartCount >= MAX_PARTICLES) break
      }

      for (let i = activePartCount; i < MAX_PARTICLES; i++) {
        dummy.position.set(9999, 9999, 9999)
        dummy.updateMatrix()
        particlesMesh.setMatrixAt(i, dummy.matrix)
      }

      particlesMesh.instanceMatrix.needsUpdate = true

      // Slow camera orbit
      nodesMesh.rotation.y += 0.001

      renderer.render(scene, camera)
    }
    animate()

    const handleResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return
      const w = container.clientWidth
      const h = container.clientHeight
      cameraRef.current.aspect = w / h
      cameraRef.current.updateProjectionMatrix()
      rendererRef.current.setSize(w, h)
    }
    window.addEventListener('resize', handleResize)

    // === Cleanup: destroy everything on unmount ===
    return () => {
      cancelAnimationFrame(animIdRef.current)
      window.removeEventListener('resize', handleResize)
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
      renderer.dispose()
      nodeGeometry.dispose()
      nodeMaterial.dispose()
      partGeometry.dispose()
      partMaterial.dispose()
      sceneRef.current = null
      rendererRef.current = null
      nodesMeshRef.current = null
      particlesMeshRef.current = null
      nodesMap.current.clear()
      velocities.current.clear()
      links.current = []
      particles.current = []
    }
  }, []) // Empty deps — mount once only

  // === EFFECT 2: Throttled graph data update from packets ===
  useEffect(() => {
    const now = Date.now()
    if (now - lastUpdate.current < THROTTLE_MS) return
    lastUpdate.current = now

    if (!nodesMeshRef.current) return

    // Only process the last 40 packets
    const recentPkts = packets.slice(-40)

    recentPkts.forEach(p => {
      if (!p.source_ip || !p.destination_ip) return

      // Create source node if new and under limit
      if (nodesMap.current.size < MAX_NODES && !nodesMap.current.has(p.source_ip)) {
        nodesMap.current.set(p.source_ip, {
          pos: new THREE.Vector3(
            (Math.random() - 0.5) * 50,
            (Math.random() - 0.5) * 50,
            (Math.random() - 0.5) * 20
          ),
          color: getIPColor(p.source_ip),
          rank: 1
        })
      }

      // Create destination node if new and under limit
      if (nodesMap.current.size < MAX_NODES && !nodesMap.current.has(p.destination_ip)) {
        nodesMap.current.set(p.destination_ip, {
          pos: new THREE.Vector3(
            (Math.random() - 0.5) * 50,
            (Math.random() - 0.5) * 50,
            (Math.random() - 0.5) * 20
          ),
          color: getIPColor(p.destination_ip),
          rank: 1
        })
      }

      // Add link between them if not already created
      const linkExists = links.current.some(l =>
        (l.source === p.source_ip && l.target === p.destination_ip) ||
        (l.source === p.destination_ip && l.target === p.source_ip)
      )
      if (!linkExists && links.current.length < MAX_LINKS) {
        links.current.push({ source: p.source_ip, target: p.destination_ip })
      }

      // Schedule particle animation (capped)
      const srcNode = nodesMap.current.get(p.source_ip)
      const dstNode = nodesMap.current.get(p.destination_ip)
      if (srcNode && dstNode && particles.current.length < MAX_PARTICLES) {
        particles.current.push({
          start: srcNode.pos.clone(),
          end: dstNode.pos.clone(),
          progress: 0,
          speed: 0.02 + Math.random() * 0.02
        })
      }
    })
  }, [packets, getIPColor])

  return (
    <div className="glass-panel flex-1 flex flex-col min-h-[300px] overflow-hidden relative">
      <div className="absolute top-3 left-4 z-10 flex items-center gap-1.5 pointer-events-none">
        <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
        <span className="text-xs font-bold text-slate-200 font-mono tracking-wider">
          3D Force-Directed Physics Mesh (WebGL)
        </span>
      </div>
      <div ref={containerRef} className="w-full h-full flex-grow min-h-[250px]" />
    </div>
  )
}
