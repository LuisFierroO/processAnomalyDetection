import { useRef, useEffect, useState, useCallback } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { getNodeColor, getNodeRadius } from '../services/processService'

export default function GraphCanvas({ nodes, onNodeClick, selectedNodeId }) {
  const containerRef = useRef()
  const graphRef     = useRef()
  const [size, setSize] = useState({ width: 800, height: 600 })

  /*
   * nodeMapRef: pid → stable node object.
   * D3 attaches x, y, vx, vy directly onto these objects. As long as we never
   * replace the object (only mutate its properties), D3 keeps the position state
   * and the simulation does NOT restart.
   */
  const nodeMapRef = useRef(new Map())

  /*
   * graphData is only updated when the PID set changes (process added or removed).
   * For data-only updates we mutate in place and skip setGraphData entirely —
   * ForceGraph2D never gets a new prop reference and the simulation never reheats.
   */
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver(([e]) =>
      setSize({ width: e.contentRect.width, height: e.contentRect.height })
    )
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    const fg = graphRef.current
    if (!fg) return
    fg.d3Force('charge').strength(-220)
    fg.d3Force('link').distance(90)
  }, [graphData])

  useEffect(() => {
    if (!nodes || nodes.length === 0) return

    const incomingPids = new Set(nodes.map(n => n.pid))
    const currentPids  = new Set(nodeMapRef.current.keys())

    const added      = nodes.filter(n => !currentPids.has(n.pid))
    const removed    = [...currentPids].filter(p => !incomingPids.has(p))
    const structural = added.length > 0 || removed.length > 0

    for (const n of nodes) {
      const obj = nodeMapRef.current.get(n.pid)
      if (obj) {
        obj.anomalyScore = n.anomalyScore
        obj.cpuPercent   = n.cpuPercent
        obj.rssKb        = n.rssKb
        obj.suspicious   = n.suspicious
        obj.state        = n.state
        obj.threads      = n.threads
        obj.name         = n.name
        obj.ppid         = n.ppid
      }
    }

    if (!structural) return

    for (const n of added)   nodeMapRef.current.set(n.pid, { ...n, id: n.pid })
    for (const pid of removed) nodeMapRef.current.delete(pid)

    const allNodes = [...nodeMapRef.current.values()]
    const pidSet   = new Set(allNodes.map(n => n.id))
    const links    = allNodes
      .filter(n => n.ppid > 0 && pidSet.has(n.ppid) && n.ppid !== n.id)
      .map(n => ({ source: n.ppid, target: n.id }))

    setGraphData({ nodes: allNodes, links })
  }, [nodes])

  const paintNode = useCallback((node, ctx, globalScale) => {
    const r        = getNodeRadius(node.rssKb)
    const color    = getNodeColor(node.anomalyScore)
    const selected = node.id === selectedNodeId

    if (selected || node.anomalyScore >= 0.30) {
      ctx.shadowBlur  = selected ? 20 : 10
      ctx.shadowColor = selected ? '#58a6ff' : color
    }

    ctx.fillStyle = color
    ctx.beginPath()
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
    ctx.fill()
    ctx.shadowBlur = 0

    if (selected) {
      ctx.strokeStyle = '#58a6ff'
      ctx.lineWidth   = 1.5 / globalScale
      ctx.stroke()
    }

    if (globalScale >= 2.5) {
      const fs = 9 / globalScale
      ctx.font         = `${fs}px 'Consolas', monospace`
      ctx.fillStyle    = 'rgba(230,237,243,0.85)'
      ctx.textAlign    = 'center'
      ctx.textBaseline = 'top'
      ctx.fillText(node.name, node.x, node.y + r + fs * 0.3)
    }
  }, [selectedNodeId])

  const paintPointer = useCallback((node, color, ctx) => {
    ctx.fillStyle = color
    ctx.beginPath()
    ctx.arc(node.x, node.y, getNodeRadius(node.rssKb) + 3, 0, 2 * Math.PI)
    ctx.fill()
  }, [])

  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%' }}>
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={size.width}
        height={size.height}
        backgroundColor="#0d1117"
        nodeCanvasObject={paintNode}
        nodeCanvasObjectMode={() => 'replace'}
        nodePointerAreaPaint={paintPointer}
        nodeLabel={n => `${n.name}  (PID ${n.pid})  score: ${(n.anomalyScore * 100).toFixed(1)}%`}
        linkColor={() => '#21262d'}
        linkWidth={0.6}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        linkDirectionalArrowColor={() => '#30363d'}
        onNodeClick={onNodeClick}
        warmupTicks={80}
        cooldownTime={8_000}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.35}
      />
    </div>
  )
}
