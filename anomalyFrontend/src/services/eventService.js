// HTTP operations for the events/alerts REST API

const API       = '/api'
const PAGE_SIZE = 50

export async function fetchEvents({ page = 0, size = PAGE_SIZE, sort = 'time', severity = 'ALL' } = {}) {
  const res = await fetch(`${API}/events?page=${page}&size=${size}&sort=${sort}&severity=${severity}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function acknowledgeEvent(id, value) {
  const res = await fetch(`${API}/events/${id}/acknowledge?value=${value}`, { method: 'PUT' })
  return res.ok
}
