# Process Anomaly Detection Agent

A three-tier system for real-time Linux process monitoring and anomaly detection.
A native C agent reads `/proc`, scores every running process with fuzzy logic, and streams
structured JSON to a Spring Boot backend that persists the data and pushes live updates to a
React dashboard via Server-Sent Events.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Linux host                         │
│                                                         │
│   ┌──────────────┐   JSON stdout   ┌─────────────────┐  │
│   │  C Agent     │ ─────────────── │  Spring Boot    │  │
│   │  (agentC/)   │                 │  Backend        │  │
│   │              │                 │  (anomalyBackend│  │
│   │  /proc       │                 │  port 8080)     │  │
│   │  reader      │                 │                 │  │
│   └──────────────┘                 │  H2 in-memory   │  │
│                                    │  database       │  │
│                                    └────────┬────────┘  │
└─────────────────────────────────────────────│───────────┘
                                              │ SSE  /api/stream
                                    ┌─────────▼────────┐
                                    │  React Frontend  │
                                    │  (anomalyFrontend│
                                    │  port 5173)      │
                                    │  Process graph   │
                                    └──────────────────┘
```

---

## Components

### 1. C Agent (`agentC/`)

A Linux-native binary written in C11 that inspects every process via the `/proc` virtual
filesystem. It takes two snapshots separated by ~250 ms to derive accurate CPU and I/O rates,
then scores each process using fuzzy logic.

**Binary alert flags** (triggered or not):

| Flag | Trigger | Score impact |
|------|---------|-------------|
| `PRIV_ESC` | `uid != euid` — possible privilege escalation | +35% |
| `DELETED_EXE` | Executable deleted after process launch | +40% |
| `PTRACE` | `TracerPid != 0` — process is being traced | +20% |
| `SUSP_PATH` | Open FD pointing to `/tmp`, `/dev/shm`, etc. | +15% |
| `ZOMBIE` | Process state `Z` — terminated but not reaped | +35% |

**Fuzzy alert flags** (weight proportional to metric value):

| Flag | Metric | Ramp | Max impact |
|------|--------|------|-----------|
| `HIGH_FD` | Open file descriptors | 250 → 500 | +15% |
| `NET_SCAN` | Active TCP/UDP connections | 25 → 50 | +10% |
| `HIGH_CPU` | CPU usage | 60% → 90% | +10% |
| `FORK_BOMB` | Fork rate (calls/s) | 50 → 100 | +25% |
| `HIGH_IO_W` | Write throughput | 5 → 10 MB/s | +20% |
| `HIGH_IO_R` | Read throughput | 25 → 50 MB/s | +10% |

**Three-tier classification:**

| Tier | Score range | Description |
|------|------------|-------------|
| Suspicious | ≥ 0.30 | Reported as anomalous |
| Notable | 0.05 – 0.29 | Elevated but not critical |
| Top resources | any | Top-N by CPU / RSS / I/O write |

**CLI usage:**

```
anomaly_detection_agent [OPTION]...

  (none)                   Run one analysis cycle.
  -i, --inspect <PID>      Inspect a single process and print all metrics.
  -j, --json               Output as JSON (one envelope per cycle).
  -n, --cycles <N>         Run N cycles then exit (default: 1).
  -w, --interval-ms <N>    Sleep N ms between cycles (default: 0).
  -a, --include-all        Include full process tree in JSON output.
  -h, --help               Show help and exit.
```

**Examples:**

```bash
# One cycle, human-readable output
./anomaly_detection_agent

# Continuous JSON stream: 6 cycles every ~10 s, full process tree
./anomaly_detection_agent -n 6 -w 9000 --json -a

# Inspect a specific process
./anomaly_detection_agent -i 1234 --json
```

**Build:**

```bash
cd agentC
make
```

Requires GCC, `libssl-dev` (OpenSSL), and `libm`. Must be compiled and run on Linux.

---

### 2. Spring Boot Backend (`anomalyBackend/`)

A Spring Boot 3.2.5 application (Java 17) that acts as the bridge between the C agent and
the frontend.

**Responsibilities:**

- Launches the C agent as a subprocess on startup (`AgentProcessManager`)
- Reads newline-delimited JSON envelopes from the agent's stdout
- Persists analysis cycles and process records in an H2 in-memory database via JPA
- Exposes a Server-Sent Events endpoint (`GET /api/stream`) so the frontend receives live
  updates without polling
- Exposes a REST API (`/api/cycles`) for manual data ingestion and historical queries

**Key configuration** (`src/main/resources/application.properties`):

```properties
server.port=8080

# Path to the compiled C agent binary
agent.binary.path=/path/to/anomaly_detection_agent

# Milliseconds between analysis cycles
agent.interval-ms=500

# Set to false to disable the agent subprocess (manual ingestion only)
agent.enabled=true
```

**Build and run:**

```bash
cd anomalyBackend
./mvnw spring-boot:run
```

The H2 console is available at `http://localhost:8080/h2-console` (JDBC URL:
`jdbc:h2:mem:anomalydb`).

---

### 3. React Frontend (`anomalyFrontend/`)

A Vite + React single-page application that visualises the process tree in real time.

**Features:**

- Connects to the backend via SSE — no manual refresh needed
- Interactive graph canvas showing all running processes as nodes
- Color-coded by anomaly score:

| Color | Score | Meaning |
|-------|-------|---------|
| Critical | ≥ 0.60 | Highly anomalous |
| Suspicious | ≥ 0.30 | Anomalous |
| Notable | ≥ 0.05 | Elevated |
| Normal | — | Clean |
| Idle | — | Minimal activity |

- Click any node to open a detail panel with full metrics, alert flags, network info,
  and open file descriptors
- Press `Escape` to close the detail panel
- Live badge showing last update time and cycle number

**Run:**

```bash
cd anomalyFrontend
npm install
npm run dev
```

Opens at `http://localhost:5173`. The Vite dev server proxies `/api` requests to
`http://localhost:8080`.

---

## Requirements

| Component | Requirement |
|-----------|------------|
| C agent | Linux, GCC ≥ 9, libssl-dev, libm |
| Backend | Java 17+, Maven |
| Frontend | Node.js 18+, npm |

The C agent **must run on Linux** — it reads from `/proc` which is a Linux-specific
virtual filesystem. The backend and frontend can run anywhere with network access to the
Linux host.

---

## Quick Start (Linux)

```bash
# 1. Build the C agent
cd agentC && make && cd ..

# 2. Update the agent path in the backend config
#    Edit anomalyBackend/src/main/resources/application.properties
#    and set agent.binary.path to the absolute path of the compiled binary

# 3. Start the backend
cd anomalyBackend && ./mvnw spring-boot:run &

# 4. Start the frontend
cd anomalyFrontend && npm install && npm run dev
```

Then open `http://localhost:5173` in your browser.

---

## Project Structure

```
agenteDeteccionAnomalias/
├── agentC/                  # C agent (Linux, /proc reader)
│   ├── main.c               # Entry point, CLI parsing, output loop
│   ├── processAgent.c/h     # Core analysis logic and data structures
│   ├── funtions.c/h         # Utility functions (SHA-256, fuzzy scoring, etc.)
│   └── Makefile
├── anomalyBackend/          # Spring Boot backend
│   └── src/main/java/com/anomaly/detection/
│       ├── agent/           # AgentProcessManager (subprocess launcher)
│       ├── controller/      # REST + SSE endpoints
│       ├── service/         # CycleService, SseService
│       ├── repository/      # JPA repositories
│       ├── model/           # JPA entities
│       └── dto/             # JSON DTOs
└── anomalyFrontend/         # React + Vite frontend
    └── src/
        ├── App.jsx           # Root component, SSE connection, layout
        └── components/
            ├── GraphCanvas.jsx   # Process tree graph
            └── NodeDetail.jsx    # Process detail side panel
```

---

## Author

Luis Fierro — luisfierroor@gmail.com
