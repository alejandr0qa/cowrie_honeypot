# 🛡️ Cowrie Honeypot Dashboard

![Docker](https://img.shields.io/badge/Docker-Cowrie-2496ED?logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/API-FastAPI_3.11-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://img.shields.io/github/actions/workflow/status/TU_USUARIO/cowrie_honeypot/docker-test.yml?label=CI)

Plataforma de inteligencia de amenazas (Threat Intelligence) basada en el honeypot SSH [Cowrie](https://github.com/cowrie/cowrie). Captura intentos de intrusión en tiempo real y los visualiza en un **dashboard web** con análisis de IA local via [Ollama](https://ollama.ai).

---

## ✨ Características

- 🔌 **Honeypot SSH/Telnet** — Basado en Cowrie, desplegado en Docker
- 📊 **Dashboard en tiempo real** — Stats, gráficas, tabla de eventos con filtros
- 🤖 **Análisis con IA** — Integración con Ollama (TinyLlama, Llama 3, Mistral...)
- 🔄 **Auto-refresh** — Actualización automática configurable (10s / 30s / 1min)
- 🛡️ **Datos de demo** — Funciona sin Docker para explorar la interfaz
- 🐧 **Multi-plataforma** — Scripts para Windows (PowerShell) y Linux/Mac (bash)

---

## 📸 Screenshots

> Dashboard con datos de demo en modo oscuro cyberpunk

```
┌─────────────────────────────────────────────────────────────┐
│  🛡 Cowrie Honeypot    [🟢 Activo]  ⚡ Live   Refresh: 30s  │
├─────────┬──────────┬───────────┬──────────┬──────┬──────────┤
│ 47 evts │  3 IPs   │ 2 Logins  │ 8 Cmds   │4 ses │ 12 fail  │
├─────────┴──────────┴───────────┴──────────┴──────┴──────────┤
│  📈 Actividad por Hora          🍩 Tipos de Eventos          │
│  ▄█ ██ ▂▃ ▄█ ▅▃ ▂▁...          (doughnut chart)            │
├────────────────────────────────────────────────────────────-─┤
│  Top IPs   │  Top Comandos   │  🤖 Análisis IA               │
│  203.0.113 │  whoami ×8      │  [TinyLlama ▼] [▶ Analizar]   │
│  198.51.100│  cat /etc/passwd│  (reporte aquí)               │
├────────────┴─────────────────┴───────────────────────────────┤
│  📋 Registro de Eventos en Tiempo Real   [Filtros...]        │
│  Timestamp  │ IP Origen  │ Evento      │ Detalle │ Sesión    │
│  ...        │ ...        │ 🔴 Login OK │ ...     │ ...       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### Requisitos
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (para el honeypot)
- Python 3.11+ (para el dashboard/API)
- [Ollama](https://ollama.ai) + modelo descargado (para el análisis IA — **opcional**)

### 3 pasos para levantarlo

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU_USUARIO/cowrie_honeypot.git
cd cowrie_honeypot

# 2. Levantar el honeypot (en segundo plano)
docker compose up -d cowrie

# 3. Levantar el dashboard
pip install -r api/requirements.txt
python api/server.py
```

🌐 Abre tu navegador en **http://localhost:8000**

---

## 📁 Estructura del Proyecto

```
cowrie_honeypot/
├── 🐳 docker-compose.yml         # Orquestación: Cowrie + Dashboard
├── cowrie-etc/
│   └── cowrie.cfg                # Configuración personalizada del honeypot
├── cowrie-var/                   # Logs reales (excluidos de Git)
├── dashboard/                    # Frontend web
│   ├── index.html                # Estructura del dashboard
│   ├── style.css                 # Tema dark cyberpunk
│   └── app.js                    # Lógica: fetch, charts, filtros, IA
├── api/
│   ├── server.py                 # API FastAPI (4 endpoints)
│   └── requirements.txt
├── scripts/
│   ├── Analizador-Honeypot.ps1   # Análisis CLI para Windows
│   └── analyze.sh                # Análisis CLI para Linux/Mac/WSL
├── sample-data/
│   └── cowrie_sample.json        # Datos de demo sanitizados
├── .github/workflows/
│   └── docker-test.yml           # CI/CD: validación automática
├── .gitignore
└── README.md
```

---

## 🌐 API Endpoints

El servidor corre en `http://localhost:8000`.

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/` | GET | Dashboard web |
| `/api/status` | GET | Estado del contenedor Docker |
| `/api/logs` | GET | Eventos del log (con filtros) |
| `/api/stats` | GET | Estadísticas agregadas |
| `/api/analyze` | POST | Análisis IA con Ollama |
| `/docs` | GET | Documentación interactiva (Swagger) |

### Ejemplos

```bash
# Ver estadísticas
curl http://localhost:8000/api/stats

# Filtrar logins exitosos
curl "http://localhost:8000/api/logs?event_type=cowrie.login.success"

# Analizar con IA
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"model":"tinyllama","max_events":50}'
```

---

## 🤖 Análisis con IA (Ollama)

El dashboard incluye un botón para enviar los eventos al LLM local y obtener un **reporte ejecutivo de seguridad** en español.

```bash
# Instalar Ollama (Linux/Mac)
curl https://ollama.ai/install.sh | sh

# Descargar modelo (solo la primera vez)
ollama pull tinyllama    # Ligero (~0.6GB), ideal para pruebas
ollama pull llama3       # Más preciso (~4GB)

# Iniciar servicio
ollama serve
```

---

## 🖥️ Scripts de Línea de Comando

### Windows (PowerShell)

```powershell
# Con Docker (live)
.\scripts\Analizador-Honeypot.ps1

# Modo demo (sin Docker)
.\scripts\Analizador-Honeypot.ps1 -Demo

# Solo estadísticas (sin Ollama)
.\scripts\Analizador-Honeypot.ps1 -NoAI

# Con Llama 3 y guardar reporte
.\scripts\Analizador-Honeypot.ps1 -ModelName "llama3" -OutputFile
```

### Linux / Mac / WSL (bash)

```bash
chmod +x scripts/analyze.sh

./scripts/analyze.sh              # Con Docker (live)
./scripts/analyze.sh --demo       # Modo demo
./scripts/analyze.sh --no-ai      # Solo estadísticas
./scripts/analyze.sh --model llama3 --max-events 100
```

---

## 🧪 Probar el Honeypot

Una vez que el contenedor esté activo, puedes probar que funciona:

```bash
# Intentar conectarse (usa cualquier credencial)
ssh root@localhost -p 2222

# Ver los eventos en tiempo real en el dashboard
# http://localhost:8000
```

---

## ⚠️ Consideraciones de Seguridad

- **No exponer el puerto 2222 a Internet** sin entender las implicaciones — el honeypot trapeará conexiones reales.
- Los logs reales están **excluidos de Git** (`.gitignore`). Solo `sample-data/` se sube al repositorio.
- El dashboard **no tiene autenticación** — úsalo solo en redes locales de confianza o agrega un proxy con autenticación.
- Las credenciales capturadas son datos sensibles — trátalas como tal.

---

## 📄 Licencia

MIT — Ver [LICENSE](LICENSE) para detalles.

---

## 🔗 Referencias

- [Cowrie GitHub](https://github.com/cowrie/cowrie)
- [Cowrie Documentation](https://cowrie.readthedocs.io/)
- [Ollama](https://ollama.ai)
- [FastAPI](https://fastapi.tiangolo.com/)
