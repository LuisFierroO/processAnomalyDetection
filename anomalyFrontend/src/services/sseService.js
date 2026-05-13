// Manages the single SSE connection to the backend.
// App.jsx owns the connection lifecycle (connect/disconnect).
// Any component can subscribe to events with onCycle / onAlert / onError.

const API = '/api'

let _source = null
const _subs = {
  cycle: new Set(),
  alert: new Set(),
  error: new Set(),
}

export function connect() {
  if (_source) return
  _source = new EventSource(`${API}/stream`)

  _source.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      _subs.cycle.forEach(fn => fn(data))
    } catch { /* ignore malformed frames */ }
  }

  _source.addEventListener('alert', () => {
    _subs.alert.forEach(fn => fn())
  })

  _source.onerror = () => {
    _subs.error.forEach(fn => fn())
  }
}

export function disconnect() {
  if (_source) {
    _source.close()
    _source = null
  }
}

// Returns an unsubscribe function.
export function onCycle(fn) {
  _subs.cycle.add(fn)
  return () => _subs.cycle.delete(fn)
}

export function onAlert(fn) {
  _subs.alert.add(fn)
  return () => _subs.alert.delete(fn)
}

export function onError(fn) {
  _subs.error.add(fn)
  return () => _subs.error.delete(fn)
}
