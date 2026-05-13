// Pure domain logic for process/anomaly data — no HTTP, no side effects

/* Must mirror ALERT_* defines in processAgent.h exactly. */
export const FLAG_BITS = [
  [1 << 0,  'PRIV_ESC',      'var(--c-critical)'],
  [1 << 1,  'DELETED_EXE',   'var(--c-critical)'],
  [1 << 2,  'SUSP_PATH',     'var(--c-suspicious)'],
  [1 << 3,  'HIGH_FD',       'var(--c-notable)'],
  [1 << 4,  'PTRACE',        'var(--c-critical)'],
  [1 << 5,  'NET_SCAN',      'var(--c-notable)'],
  [1 << 6,  'HIGH_CPU',      'var(--c-notable)'],
  [1 << 7,  'FORK_BOMB',     'var(--c-suspicious)'],
  [1 << 8,  'HIGH_IO_W',     'var(--c-notable)'],
  [1 << 9,  'HIGH_IO_R',     'var(--c-notable)'],
  [1 << 10, 'ZOMBIE',        'var(--c-suspicious)'],
  [1 << 11, 'ZOMBIE_PARENT', 'var(--c-critical)'],
]

export function getSeverityInfo(score) {
  if (score >= 0.60) return { label: 'Critical',   color: 'var(--c-critical)'   }
  if (score >= 0.30) return { label: 'Suspicious', color: 'var(--c-suspicious)' }
  if (score >= 0.05) return { label: 'Notable',    color: 'var(--c-notable)'    }
  return { label: 'Normal', color: 'var(--c-normal)' }
}

export function getNodeColor(score) {
  if (score >= 0.60) return '#f85149'
  if (score >= 0.30) return '#f0883e'
  if (score >= 0.05) return '#d29922'
  if (score >  0)   return '#3fb950'
  return '#30363d'
}

export function getNodeRadius(rssKb) {
  return Math.max(3, Math.log2(Math.max(rssKb, 512) / 512) * 2.2 + 3)
}

// Returns active flag tuples [bit, name, color] from a bitmask
export function getActiveFlags(alertFlags) {
  if (!alertFlags) return []
  return FLAG_BITS.filter(([bit]) => alertFlags & bit)
}

// Prefers triggeredRules string; falls back to bitmask decoding
export function resolveFlags(triggeredRules, alertFlags) {
  if (triggeredRules) return triggeredRules.split(',').filter(Boolean)
  return FLAG_BITS.filter(([bit]) => alertFlags & bit).map(([, name]) => name)
}

export function formatDateTime(isoStr) {
  if (!isoStr) return '—'
  return new Date(isoStr).toLocaleString(undefined, {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function parseCycleData(data) {
  return {
    id:                data.id,
    agentId:           data.agentId,
    cycleNumber:       data.cycleNumber,
    timestamp:         data.timestamp,
    totalProcesses:    data.totalProcesses,
    suspiciousCount:   data.suspiciousCount,
    notableCount:      data.notableCount,
    topResourcesCount: data.topResourcesCount,
  }
}
