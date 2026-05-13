import { useState, useEffect, useCallback } from 'react'
import { fetchEvents, acknowledgeEvent } from '../services/eventService'
import { onAlert }                        from '../services/sseService'
import { resolveFlags, formatDateTime }   from '../services/processService'

const SEV_COLOR = {
  CRITICAL:   'var(--c-critical)',
  SUSPICIOUS: 'var(--c-suspicious)',
  NOTABLE:    'var(--c-notable)',
}

export default function EventHistory() {
  const [data,       setData]       = useState({ content: [], totalElements: 0, totalPages: 0, number: 0 })
  const [loading,    setLoading]    = useState(true)
  const [expanded,   setExpanded]   = useState(null)
  const [filter,     setFilter]     = useState('ALL')
  const [sortBy,     setSortBy]     = useState('time')
  const [page,       setPage]       = useState(0)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    fetchEvents({ page, sort: sortBy, severity: filter })
      .then(d => { if (!cancelled) { setData(d); setLoading(false) } })
      .catch(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [page, sortBy, filter, refreshKey])

  useEffect(() => {
    return onAlert(() => {
      if (page === 0) setRefreshKey(k => k + 1)
    })
  }, [page])

  const acknowledge = useCallback((id, current) => {
    const next = !current
    acknowledgeEvent(id, next).then(ok => {
      if (ok) setData(prev => ({
        ...prev,
        content: prev.content.map(ev => ev.id === id ? { ...ev, isAcknowledged: next } : ev),
      }))
    })
  }, [])

  const handleFilter = (f) => { setFilter(f); setPage(0); setExpanded(null) }
  const handleSort   = (s) => { setSortBy(s); setPage(0); setExpanded(null) }

  const { content, totalElements, totalPages, number } = data

  return (
    <div className="eh-root">

      {/* Toolbar */}
      <div className="eh-toolbar">
        <span className="eh-title">Alert History</span>
        <div className="eh-filters">
          {['ALL', 'CRITICAL', 'SUSPICIOUS', 'NOTABLE'].map(f => (
            <button
              key={f}
              className={`eh-filter-btn ${filter === f ? 'active' : ''}`}
              style={{ '--fc': f === 'ALL' ? 'var(--c-accent)' : SEV_COLOR[f] }}
              onClick={() => handleFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="eh-spacer" />
        <div className="eh-sort-btns">
          <button
            className={`eh-sort-btn ${sortBy === 'time' ? 'active' : ''}`}
            onClick={() => handleSort('time')}
            title="Sort by date, newest first"
          >Date ↓</button>
          <button
            className={`eh-sort-btn ${sortBy === 'score' ? 'active' : ''}`}
            onClick={() => handleSort('score')}
            title="Sort by anomaly score, highest first"
          >Score ↓</button>
        </div>
        <span className="eh-count">{totalElements.toLocaleString()} events</span>
      </div>

      {/* Table */}
      {loading ? (
        <div className="eh-empty">Loading…</div>
      ) : content.length === 0 ? (
        <div className="eh-empty">No events recorded yet.</div>
      ) : (
        <>
          <div className="eh-table-wrap">
            <table className="eh-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Process</th>
                  <th>PID</th>
                  <th>Score</th>
                  <th>Flags</th>
                  <th>Agent</th>
                  <th>Ack</th>
                </tr>
              </thead>
              <tbody>
                {content.map(ev => (
                  <>
                    <tr
                      key={ev.id}
                      className={`eh-row ${ev.isAcknowledged ? 'acked' : ''} ${expanded === ev.id ? 'expanded' : ''}`}
                      onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}
                    >
                      <td className="mono">{formatDateTime(ev.detectedAt)}</td>
                      <td>
                        <span className="sev-badge" style={{ '--sc': SEV_COLOR[ev.severity] ?? 'var(--c-idle)' }}>
                          {ev.severity}
                        </span>
                      </td>
                      <td className="proc-name">{ev.name}</td>
                      <td className="mono">{ev.pid}</td>
                      <td className="mono score-cell" style={{ color: SEV_COLOR[ev.severity] }}>
                        {ev.anomalyScore.toFixed(3)}
                      </td>
                      <td className="flags-cell">
                        {resolveFlags(ev.triggeredRules, ev.alertFlags).map(f => (
                          <span key={f} className="flag-tag">{f}</span>
                        ))}
                      </td>
                      <td className="mono agent-cell">{ev.agentId}</td>
                      <td onClick={e => e.stopPropagation()}>
                        <button
                          className={`ack-btn ${ev.isAcknowledged ? 'acked' : ''}`}
                          title={ev.isAcknowledged ? 'Mark unacknowledged' : 'Acknowledge'}
                          onClick={() => acknowledge(ev.id, ev.isAcknowledged)}
                        >
                          {ev.isAcknowledged ? '✓' : '○'}
                        </button>
                      </td>
                    </tr>
                    {expanded === ev.id && (
                      <tr key={`${ev.id}-detail`} className="eh-detail-row">
                        <td colSpan={8}>
                          <div className="eh-detail">
                            <div className="eh-detail-grid">
                              <DetailField label="Exe path"   value={ev.exePath   || '—'} />
                              <DetailField label="Exe hash"   value={ev.exeHash   || '—'} mono />
                              <DetailField label="Cmdline"    value={ev.cmdline   || '—'} mono />
                              <DetailField label="User"       value={`${ev.username || '?'} (uid ${ev.uid} / euid ${ev.euid})`} mono />
                              <DetailField label="CPU"        value={`${ev.cpuPercent.toFixed(1)} %`} mono />
                              <DetailField label="RSS"        value={`${(ev.rssKb / 1024).toFixed(1)} MB`} mono />
                              <DetailField label="IO write"   value={`${(ev.ioWriteBps / 1024).toFixed(1)} KB/s`} mono />
                              <DetailField label="FDs"        value={String(ev.openFdCount)} mono />
                              <DetailField label="Conns"      value={String(ev.openConnections)} mono />
                              {ev.isDeletedExe  && <DetailField label="Warning" value="Executable deleted after launch" warn />}
                              {ev.hasPtrace     && <DetailField label="Warning" value="Process is being traced (ptrace)" warn />}
                            </div>
                            {ev.notes && (
                              <div className="eh-notes">
                                <span className="eh-notes-label">Notes:</span> {ev.notes}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="eh-pagination">
            <button
              className="pg-btn"
              disabled={number === 0}
              onClick={() => setPage(p => p - 1)}
            >← Prev</button>
            <span className="pg-info">Page {number + 1} of {totalPages}</span>
            <button
              className="pg-btn"
              disabled={number >= totalPages - 1}
              onClick={() => setPage(p => p + 1)}
            >Next →</button>
          </div>
        </>
      )}
    </div>
  )
}

function DetailField({ label, value, mono, warn }) {
  return (
    <div className="dfield">
      <span className="dfield-key">{label}</span>
      <span className={`dfield-val ${mono ? 'mono' : ''} ${warn ? 'warn' : ''}`}>{value}</span>
    </div>
  )
}
