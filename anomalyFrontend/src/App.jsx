import { useState, useEffect } from 'react'
import GraphCanvas from './components/GraphCanvas'
import NodeDetail  from './components/NodeDetail'

const API = '/api'

const LEGEND = [
  { color: 'var(--c-critical)',   label: 'Critical    ≥ 0.60' },
  { color: 'var(--c-suspicious)', label: 'Suspicious  ≥ 0.30' },
  { color: 'var(--c-notable)',    label: 'Notable     ≥ 0.05' },
  { color: 'var(--c-normal)',     label: 'Normal' },
  { color: 'var(--c-idle)',       label: 'Idle' },
]

export default function App() {
  const [cycle,      setCycle]      = useState(null)
  const [nodes,      setNodes]      = useState([])
  const [selected,   setSelected]   = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)

  useEffect(() => {
    const source = new EventSource(`${API}/stream`)

    source.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setCycle({
          id:                data.id,
          agentId:           data.agentId,
          cycleNumber:       data.cycleNumber,
          timestamp:         data.timestamp,
          totalProcesses:    data.totalProcesses,
          suspiciousCount:   data.suspiciousCount,
          notableCount:      data.notableCount,
          topResourcesCount: data.topResourcesCount,
        })
        if (data.tree) setNodes(data.tree)
        setLastUpdate(new Date())
        setLoading(false)
        setError(null)
      } catch {
        // ignore malformed events
      }
    }

    source.onerror = () => {
      setError('Cannot connect to backend at localhost:8080')
      setLoading(false)
      // EventSource auto-reconnects — keep source open
    }

    return () => source.close()
  }, [])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') setSelected(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="app">

      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <span className="header-title">Process Anomaly Detection</span>
          {cycle && (
            <span className="header-meta">
              {cycle.agentId} &nbsp;·&nbsp; cycle #{cycle.cycleNumber}
            </span>
          )}
        </div>
        <div className="header-right">
          {cycle && (
            <>
              <Pill value={cycle.totalProcesses}  label="processes"  color="var(--c-idle)"       />
              <Pill value={cycle.notableCount}     label="notable"    color="var(--c-notable)"    />
              <Pill value={cycle.suspiciousCount}  label="suspicious" color="var(--c-suspicious)" />
            </>
          )}
          <div className="live-badge">
            <span className="pulse-dot" />
            {lastUpdate ? lastUpdate.toLocaleTimeString() : 'connecting…'}
          </div>
        </div>
      </header>

      {/* ── Main canvas ── */}
      <main className="main">
        {loading ? (
          <Centered>Waiting for first cycle…</Centered>
        ) : error ? (
          <Centered error>{error}</Centered>
        ) : nodes.length === 0 ? (
          <Centered>No process data yet. Is the agent running?</Centered>
        ) : (
          <>
            <GraphCanvas
              nodes={nodes}
              onNodeClick={setSelected}
              selectedNodeId={selected?.pid ?? null}
            />
            <div className="legend">
              {LEGEND.map(({ color, label }) => (
                <div key={label} className="legend-item">
                  <span className="legend-dot" style={{ background: color }} />
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </main>

      {/* ── Detail panel ── */}
      {selected && (
        <NodeDetail node={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}

function Pill({ value, label, color }) {
  return (
    <span className="pill" style={{ '--pc': color }}>
      <span className="pill-dot" />
      <b>{value}</b>&nbsp;{label}
    </span>
  )
}

function Centered({ children, error }) {
  return (
    <div className="centered" style={{ color: error ? 'var(--c-critical)' : 'var(--text-muted)' }}>
      {children}
    </div>
  )
}
