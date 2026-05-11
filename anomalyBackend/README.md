# anomaly-backend

Backend REST API para detección de anomalías en procesos del sistema. Recibe, persiste y expone ciclos de análisis generados por un agente externo de detección en C, con soporte de streaming en tiempo real vía Server-Sent Events.

## Stack tecnológico

| Capa | Tecnología |
|------|-----------|
| Lenguaje | Java 17 |
| Framework | Spring Boot 3.2.5 |
| ORM | Spring Data JPA / Hibernate |
| Base de datos | H2 (in-memory) |
| Build | Maven |
| Serialización | Jackson |

## Arquitectura

```
anomalyBackend/
├── src/main/java/com/anomaly/detection/
│   ├── AnomalyDetectionApplication.java   # Punto de entrada
│   ├── agent/
│   │   └── AgentProcessManager.java       # Lanza y lee el agente externo en C
│   ├── controller/
│   │   ├── CycleController.java           # Endpoints REST para ciclos
│   │   └── SseController.java             # Endpoint SSE (streaming)
│   ├── dto/                               # Objetos de transferencia de datos
│   ├── model/                             # Entidades JPA
│   ├── repository/                        # Spring Data repositories
│   └── service/
│       ├── CycleService.java              # Lógica de negocio de ciclos
│       └── SseService.java                # Gestión de conexiones SSE
└── src/main/resources/
    └── application.properties             # Configuración
```

### Modelos de datos

- **AnalysisCycle** — Metadatos de un ciclo de detección (agente, número de ciclo, conteos, timestamp).
- **ProcessRecord** — Detalle de un proceso analizado: PID, PPID, nombre, CPU, memoria, I/O, hash del ejecutable, puntuación de anomalía, reglas disparadas.
- **ProcessTreeRecord** — Jerarquía de procesos del ciclo.
- **ProcessTier** — Enum: `SUSPICIOUS`, `NOTABLE`, `TOP_RESOURCE`.

## API REST

Base URL: `http://localhost:8080`

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/api/cycles` | Ingesta un ciclo completo desde el agente |
| `GET` | `/api/cycles` | Lista todos los ciclos (resumen) |
| `GET` | `/api/cycles/latest` | Último ciclo recibido |
| `GET` | `/api/cycles/{id}` | Ciclo completo con todos sus procesos |
| `GET` | `/api/cycles/{id}/tree` | Árbol de procesos de un ciclo |
| `GET` | `/api/stream` | Stream SSE — actualizaciones en tiempo real |

CORS habilitado para todos los orígenes (`*`).

### Formato de entrada — `POST /api/cycles`

```json
{
  "schema_version": "1.0",
  "agent_id": "agent-1",
  "cycle": 123,
  "timestamp": 1234567890.5,
  "total_processes": 250,
  "suspicious_count": 5,
  "notable_count": 12,
  "top_resources_count": 8,
  "suspicious_processes": [...],
  "notable_processes": [...],
  "top_resources": [...],
  "process_tree": [...]
}
```

### Formato de salida — `GET /api/cycles/{id}`

```json
{
  "summary": {
    "id": 1,
    "agentId": "agent-1",
    "cycleNumber": 123,
    "timestamp": 1234567890.5,
    "totalProcesses": 250,
    "suspiciousCount": 5,
    "notableCount": 12,
    "topResourcesCount": 8,
    "receivedAt": "2026-05-11T06:21:00"
  },
  "suspiciousProcesses": [...],
  "notableProcesses": [...],
  "topResources": [...]
}
```

## Integración con el agente externo

Al arrancar, `AgentProcessManager` lanza automáticamente el binario de detección en C:

```
./anomaly_detection_agent --json --include-all --cycles 999999 --interval-ms 500
```

El agente escribe ciclos JSON en `stdout`; el manager los parsea usando seguimiento de profundidad de llaves y los persiste vía `CycleService`, que a su vez los emite por SSE a los clientes conectados.

Para deshabilitar la integración automática (modo manual vía `POST /api/cycles`):

```properties
agent.enabled=false
```

## Configuración

`src/main/resources/application.properties`:

```properties
# Servidor
server.port=8080

# Base de datos H2 in-memory
spring.datasource.url=jdbc:h2:mem:anomalydb;DB_CLOSE_DELAY=-1
spring.datasource.driver-class-name=org.h2.Driver
spring.datasource.username=sa
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.hibernate.ddl-auto=create-drop

# Agente externo
agent.binary.path=/media/sf_CarpetaCompartidaDebian/agenteDeteccionAnomalias/anomaly_detection_agent
agent.interval-ms=500
agent.enabled=true
```

Consola H2 disponible en `http://localhost:8080/h2-console` durante el desarrollo.

## Build y ejecución

```bash
# Compilar y empaquetar
mvn clean package

# Ejecutar
java -jar target/anomaly-backend-0.0.1-SNAPSHOT.jar
```

Requiere **Java 17** y **Maven 3.6+**.

## Notas

- La base de datos es `create-drop`: los datos no persisten entre reinicios. Para persistencia usar un perfil con PostgreSQL o MySQL.
- El esquema de tablas lo genera Hibernate automáticamente al arrancar.
- El path del agente externo está pensado para un entorno Linux con carpeta compartida de VirtualBox (`/media/sf_*`).
