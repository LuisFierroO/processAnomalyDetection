import { getSeverityInfo, getActiveFlags } from '../services/processService'

function MetricBar({ label, value, max, unit, color }) {
  const pct = Math.min(100, max > 0 ? (value / max) * 100 : 0)
  return (
    <div className="mbar">
      <div className="mbar-header">
        <span className="mbar-label">{label}</span>
        <span className="mbar-value">{value.toFixed(1)}{unit}</span>
      </div>
      <div className="mbar-track">
        <div className="mbar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

function Badge({ label, color }) {
  return (
    <span className="nd-badge" style={{ '--bc': color }}>{label}</span>
  )
}

function Row({ k, v }) {
  return (
    <>
      <span className="dg-key">{k}</span>
      <span className="dg-val">{v}</span>
    </>
  )
}

export default function NodeDetail({ node, onClose }) {
  const sev    = getSeverityInfo(node.anomalyScore)
  const flags  = getActiveFlags(node.alertFlags)
  const ramMb  = (node.rssKb / 1024).toFixed(1)
  const ramMax = Math.max(node.rssKb / 1024, 256)

  return (
    <aside className="nd-panel">

      <div className="nd-header">
        <div>
          <p className="nd-pid">PID {node.pid}</p>
          <h2 className="nd-name">{node.name}</h2>
        </div>
        <button className="nd-close" onClick={onClose} title="Close (Esc)">✕</button>
      </div>

      <div className="nd-badges">
        <Badge label={sev.label}                    color={sev.color}              />
        <Badge label={`State: ${node.state}`}       color="var(--c-muted)"         />
        <Badge label={`${node.threads} threads`}    color="var(--c-muted)"         />
        {node.suspicious && <Badge label="⚠ Suspicious" color="var(--c-suspicious)" />}
      </div>

      <section className="nd-section">
        <p className="nd-section-title">Anomaly Score</p>
        <div className="nd-score-row">
          <span className="nd-score-big" style={{ color: sev.color }}>
            {(node.anomalyScore * 100).toFixed(1)}%
          </span>
          <span className="nd-score-tag" style={{ color: sev.color }}>
            {sev.label}
          </span>
        </div>
        <MetricBar label="" value={node.anomalyScore} max={1} unit="" color={sev.color} />
      </section>

      {flags.length > 0 && (
        <section className="nd-section">
          <p className="nd-section-title">Alert Flags</p>
          <div className="nd-badges">
            {flags.map(([, label, color]) => (
              <Badge key={label} label={label} color={color} />
            ))}
          </div>
        </section>
      )}

      <section className="nd-section">
        <p className="nd-section-title">Resources</p>
        <MetricBar label="CPU" value={node.cpuPercent} max={100}    unit="%" color="var(--c-cpu)" />
        <MetricBar label="RAM" value={parseFloat(ramMb)} max={ramMax} unit=" MB" color="var(--c-ram)" />
      </section>

      <section className="nd-section">
        <p className="nd-section-title">Identity</p>
        <div className="nd-grid">
          <Row k="Owner"   v={node.username || '—'} />
          <Row k="PID"     v={node.pid}     />
          <Row k="PPID"    v={node.ppid}    />
          <Row k="State"   v={node.state}   />
          <Row k="Threads" v={node.threads} />
          <Row k="RSS"     v={`${ramMb} MB`} />
          <Row k="CPU"     v={`${node.cpuPercent.toFixed(2)}%`} />
        </div>
      </section>

    </aside>
  )
}
