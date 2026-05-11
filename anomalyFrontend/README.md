# Anomaly Frontend

Dashboard de visualización en tiempo real para detección de anomalías en procesos del sistema. Muestra un grafo de procesos con métricas de CPU, RAM y puntuaciones de anomalía recibidas vía Server-Sent Events desde un agente de monitoreo.

## Tech Stack

| Capa | Tecnología |
|------|------------|
| UI Framework | React 18 |
| Build Tool | Vite 5 |
| Visualización | react-force-graph-2d (D3) |
| Comunicación | EventSource (SSE) |
| Estilos | CSS3 con custom properties |

## Requisitos

- Node.js 16+
- Backend corriendo en `http://localhost:8080` con endpoint `/api/stream`

## Instalación y uso

```bash
# Instalar dependencias
npm install

# Servidor de desarrollo (http://localhost:5173)
npm run dev

# Build de producción
npm run build

# Preview del build
npm run preview
```

## Estructura del proyecto

```
anomalyFrontend/
├── src/
│   ├── main.jsx              # Entry point de React
│   ├── App.jsx               # Componente raíz, manejo de SSE y estado global
│   ├── App.css               # Design tokens y estilos globales
│   └── components/
│       ├── GraphCanvas.jsx   # Grafo de procesos con D3 force-directed
│       └── NodeDetail.jsx    # Panel lateral de detalle de proceso
├── index.html
├── vite.config.js            # Proxy /api → localhost:8080
└── package.json
```

## Funcionalidades

### Grafo de procesos
- Nodos representan procesos del sistema; el tamaño refleja el uso de RAM (escala logarítmica)
- Las aristas representan relaciones padre-hijo (PPID → PID)
- Color del nodo según puntuación de anomalía:

| Color | Umbral | Clasificación |
|-------|--------|---------------|
| Rojo `#f85149` | ≥ 0.60 | Critical |
| Naranja `#f0883e` | ≥ 0.30 | Suspicious |
| Dorado `#d29922` | ≥ 0.05 | Notable |
| Verde `#3fb950` | > 0 | Normal |
| Gris `#30363d` | 0 | Idle |

### Panel de detalle
- Se abre al hacer clic en un nodo
- Muestra PID, nombre, estado, owner, threads, CPU%, RAM y puntuación de anomalía
- Se cierra con `Esc` o el botón de cierre

### Stream en tiempo real
- Conexión SSE a `/api/stream` con reconexión automática
- Actualización in-place del grafo D3 (sin re-simulación) cuando solo cambian métricas
- Re-simulación solo cuando cambia la lista de PIDs

## Formato de datos esperado (SSE)

```json
{
  "id": "...",
  "agentId": "...",
  "cycleNumber": 42,
  "timestamp": "2026-05-11T12:00:00Z",
  "totalProcesses": 150,
  "suspiciousCount": 3,
  "notableCount": 12,
  "tree": [
    {
      "pid": 1234,
      "ppid": 1,
      "name": "nginx",
      "state": "S",
      "username": "www-data",
      "threads": 4,
      "rssKb": 20480,
      "cpuPercent": 2.5,
      "anomalyScore": 0.12,
      "suspicious": false
    }
  ]
}
```

## Configuración del proxy

El proxy de Vite redirige `/api` al backend en desarrollo. Para cambiar el host o puerto del backend, editar `vite.config.js`:

```js
server: {
  proxy: {
    '/api': 'http://localhost:8080'
  }
}
```
