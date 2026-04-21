"""
==============================================================================
Cowrie Honeypot Dashboard — API Server
Backend FastAPI que expone logs de Cowrie y análisis con IA via Ollama
==============================================================================
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# ─── Configuración ─────────────────────────────────────────────────────────────
COWRIE_LOG_PATH = Path(
    os.getenv("COWRIE_LOG_PATH", "./cowrie-var/log/cowrie/cowrie.json")
)
SAMPLE_LOG_PATH = Path("./sample-data/cowrie_sample.json")
OLLAMA_ENDPOINT = os.getenv(
    "OLLAMA_ENDPOINT", "http://localhost:11434/api/generate"
)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "cowrie_honeypot")

app = FastAPI(
    title="Cowrie Honeypot Dashboard API",
    description="API para visualizar y analizar eventos del honeypot Cowrie",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Modelos ───────────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    model: Optional[str] = None
    max_events: Optional[int] = 50


# ─── Helpers ───────────────────────────────────────────────────────────────────
def _load_logs() -> list[dict]:
    """Carga logs de Cowrie desde el volumen Docker o usa datos de muestra."""
    path = COWRIE_LOG_PATH if COWRIE_LOG_PATH.exists() else SAMPLE_LOG_PATH
    if not path.exists():
        return []

    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def _is_using_sample() -> bool:
    return not COWRIE_LOG_PATH.exists()


def _get_container_status() -> dict:
    """Verifica si el contenedor Docker está corriendo."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", CONTAINER_NAME],
            capture_output=True,
            text=True,
            timeout=5,
        )
        status = result.stdout.strip()
        return {"running": status == "running", "status": status or "not_found"}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"running": False, "status": "docker_unavailable"}


# ─── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/status")
def get_status():
    """Estado del contenedor Docker y del servidor."""
    container = _get_container_status()
    using_sample = _is_using_sample()
    return {
        "server": "online",
        "container": container,
        "log_source": "sample_data" if using_sample else "live_cowrie",
        "log_path": str(COWRIE_LOG_PATH),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api/logs")
def get_logs(
    limit: int = Query(default=200, ge=1, le=5000),
    event_type: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
):
    """
    Retorna eventos del log de Cowrie con filtros opcionales.
    - **limit**: máximo número de eventos a retornar
    - **event_type**: filtrar por tipo de evento (ej: `cowrie.login.success`)
    - **src_ip**: filtrar por IP de origen
    """
    events = _load_logs()

    if event_type:
        events = [e for e in events if e.get("eventid") == event_type]
    if src_ip:
        events = [e for e in events if e.get("src_ip") == src_ip]

    # Más recientes primero
    events = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "total": len(events),
        "limit": limit,
        "source": "sample_data" if _is_using_sample() else "live",
        "events": events[:limit],
    }


@app.get("/api/stats")
def get_stats():
    """
    Estadísticas agregadas del honeypot:
    - IPs únicas, top IPs
    - Logins exitosos vs fallidos
    - Comandos más ejecutados
    - Actividad por hora
    """
    events = _load_logs()
    if not events:
        return {"error": "No hay eventos disponibles"}

    # Conteos por tipo
    event_counts = Counter(e.get("eventid", "unknown") for e in events)

    # IPs
    all_ips = [e.get("src_ip") for e in events if e.get("src_ip")]
    unique_ips = len(set(all_ips))
    top_ips = Counter(all_ips).most_common(10)

    # Logins
    logins_ok = [
        {"ip": e.get("src_ip"), "user": e.get("username"), "pass": e.get("password"), "ts": e.get("timestamp")}
        for e in events if e.get("eventid") == "cowrie.login.success"
    ]
    logins_fail = sum(1 for e in events if e.get("eventid") == "cowrie.login.failed")

    # Comandos
    commands = [e.get("input", "") for e in events if e.get("eventid") == "cowrie.command.input" and e.get("input")]
    top_commands = Counter(commands).most_common(10)

    # Sesiones
    sessions_unique = len({e.get("session") for e in events if e.get("session")})

    # Actividad por hora (últimas 24h)
    hourly = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if ts and len(ts) >= 13:
            hour = ts[11:13]
            hourly[hour] += 1

    return {
        "total_events": len(events),
        "unique_ips": unique_ips,
        "unique_sessions": sessions_unique,
        "logins_success": len(logins_ok),
        "logins_failed": logins_fail,
        "total_commands": len(commands),
        "event_breakdown": dict(event_counts),
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_commands": [{"command": cmd, "count": c} for cmd, c in top_commands],
        "successful_logins": logins_ok[:20],
        "hourly_activity": dict(sorted(hourly.items())),
        "source": "sample_data" if _is_using_sample() else "live",
    }


@app.post("/api/analyze")
async def analyze_with_ai(req: AnalyzeRequest):
    """
    Envía eventos críticos a Ollama para análisis de inteligencia de amenazas.
    Requiere que Ollama esté corriendo localmente con el modelo configurado.
    """
    events = _load_logs()

    # Filtrar solo los eventos relevantes para análisis
    critical_events = [
        e for e in events
        if e.get("eventid") in ("cowrie.login.success", "cowrie.command.input", "cowrie.login.failed")
    ]
    critical_events = critical_events[: (req.max_events or 50)]

    if not critical_events:
        raise HTTPException(status_code=404, detail="No hay eventos críticos para analizar")

    # Formatear para el LLM
    lines = []
    for e in critical_events:
        eid = e.get("eventid", "")
        ip = e.get("src_ip", "N/A")
        ts = e.get("timestamp", "")[:19].replace("T", " ")
        if eid == "cowrie.login.success":
            lines.append(f"[{ts}] LOGIN EXITOSO | IP: {ip} | User: {e.get('username')} | Pass: {e.get('password')}")
        elif eid == "cowrie.login.failed":
            lines.append(f"[{ts}] LOGIN FALLIDO | IP: {ip} | User: {e.get('username')} | Pass: {e.get('password')}")
        elif eid == "cowrie.command.input":
            lines.append(f"[{ts}] COMANDO | IP: {ip} | CMD: {e.get('input')}")

    report_data = "\n".join(lines)
    model = req.model or OLLAMA_MODEL

    prompt = f"""Eres un analista experto en ciberseguridad. Analiza el siguiente registro de eventos de un honeypot SSH y proporciona:

1. **Resumen ejecutivo**: Cuántas IPs distintas atacaron y el nivel de riesgo general.
2. **Credenciales utilizadas**: Lista de usuarios/contraseñas probados, ¿son ataques dirigidos o de diccionario?
3. **Comandos ejecutados**: ¿Qué intentaron hacer? ¿Cuál era el objetivo probable (minería, botnet, exfiltración)?
4. **Indicadores de Compromiso (IoC)**: IPs y patrones sospechosos.
5. **Recomendaciones**: Acciones inmediatas a tomar.

REGLA ESTRICTA: Responde ÚNICAMENTE en español. Sé conciso y profesional.

REGISTROS:
{report_data}
"""

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 800},
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(OLLAMA_ENDPOINT, json=payload)
            response.raise_for_status()
            data = response.json()
            return {
                "model": model,
                "analysis": data.get("response", ""),
                "events_analyzed": len(critical_events),
                "source": "sample_data" if _is_using_sample() else "live",
            }
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail="No se pudo conectar con Ollama. Asegúrate de que esté corriendo: `ollama serve`",
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Ollama tardó demasiado en responder")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar: {str(e)}")


# ─── Archivos estáticos del Dashboard ──────────────────────────────────────────
_dashboard_path = Path("./dashboard")
if _dashboard_path.exists():
    app.mount("/static", StaticFiles(directory=str(_dashboard_path)), name="static")

    @app.get("/", response_class=FileResponse)
    def serve_dashboard():
        return FileResponse(str(_dashboard_path / "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "message": "Cowrie Honeypot API v2.0",
            "docs": "/docs",
            "endpoints": ["/api/status", "/api/logs", "/api/stats", "/api/analyze"],
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
