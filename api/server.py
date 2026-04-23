"""
==============================================================================
Cowrie Honeypot Dashboard — API Server v2.2
Cambios en esta versión:
  - Integración RAG (ChromaDB) para memoria histórica de ataques
  - Prompt Engineering avanzado (chain-of-thought + few-shot + MITRE ATT&CK)
  - Pre-análisis automático: timing, credenciales, técnicas MITRE detectadas
  - Nuevo endpoint GET  /api/rag/stats
  - Nuevo endpoint POST /api/rag/index  (indexación manual)
  - Nuevo endpoint GET  /api/history/{ip}
  - Nuevo endpoint GET  /api/search (búsqueda semántica)
  - /api/analyze enriquecido con contexto RAG + prompt estructurado
==============================================================================
"""

import json
import logging
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

# ─── Importar módulos locales ────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from rag    import CowrieRAG                            # noqa: E402
from prompt import pre_analyze, build_prompt            # noqa: E402

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(levelname)s │ %(name)s │ %(message)s")
logger = logging.getLogger("cowrie_api")

# ─── Configuración ────────────────────────────────────────────────────────────
COWRIE_LOG_PATH = Path(
    os.getenv("COWRIE_LOG_PATH", "./cowrie-var/log/cowrie/cowrie.json")
)
SAMPLE_LOG_PATH = Path("./sample-data/cowrie_sample.json")
OLLAMA_ENDPOINT = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434/api/generate")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "tinyllama")
CONTAINER_NAME  = os.getenv("CONTAINER_NAME", "cowrie_honeypot")
RAG_DIR         = os.getenv("RAG_DIR", "./rag_db")

# ─── Motores de IA cloud (prioridad: OpenAI → Groq → Ollama) ─────────────────
OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "")
OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL    = os.getenv("OPENAI_MODEL", "gpt-4o-mini")   # barato y rápido

GROQ_API_KEY    = os.getenv("GROQ_API_KEY", "")
GROQ_ENDPOINT   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL      = os.getenv("GROQ_MODEL", "llama3-8b-8192")

if OPENAI_API_KEY:
    _AI_ENDPOINT, _AI_KEY, _AI_MODEL = OPENAI_ENDPOINT, OPENAI_API_KEY, OPENAI_MODEL
    logger_mode = f"OpenAI ({OPENAI_MODEL})"
elif GROQ_API_KEY:
    _AI_ENDPOINT, _AI_KEY, _AI_MODEL = GROQ_ENDPOINT, GROQ_API_KEY, GROQ_MODEL
    logger_mode = f"Groq ({GROQ_MODEL})"
else:
    _AI_ENDPOINT, _AI_KEY, _AI_MODEL = "", "", ""
    logger_mode = "Ollama (local)"

USE_CLOUD_AI = bool(OPENAI_API_KEY or GROQ_API_KEY)

# ─── Instancia RAG global ─────────────────────────────────────────────────────
rag = CowrieRAG(persist_dir=RAG_DIR)


# ─── Lifespan (startup) ───────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Al arrancar: auto-indexar los logs actuales en ChromaDB."""
    logger.info("🚀 Cowrie Honeypot API iniciando...")
    if rag.is_available:
        events = _load_logs()
        if events:
            added = rag.index_events(events)
            logger.info(
                f"RAG startup: {len(events)} eventos procesados, "
                f"{added} nuevos. Total DB: {rag.indexed_count}"
            )
        else:
            logger.warning("RAG startup: sin logs disponibles para indexar.")
    else:
        logger.warning("RAG no disponible. Instala: pip install chromadb")
    yield
    logger.info("👋 API detenida.")


# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Cowrie Honeypot Dashboard API",
    description=(
        "API para visualizar y analizar eventos del honeypot Cowrie. "
        "Incluye análisis con IA local (Ollama), memoria histórica RAG (ChromaDB) "
        "y prompt engineering avanzado con MITRE ATT&CK."
    ),
    version="2.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Modelos ──────────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    model:      Optional[str] = None
    max_events: Optional[int] = 15      # CPU-only: reducido de 50 → 15
    use_rag:    Optional[bool] = True


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _load_logs() -> list[dict]:
    """Carga logs de Cowrie. Prioridad: log real > datos de muestra."""
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
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5,
        )
        status = result.stdout.strip()
        return {"running": status == "running", "status": status or "not_found"}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"running": False, "status": "docker_unavailable"}


def _index_in_background(events: list[dict]):
    """Función para indexar en segundo plano (no bloquea la respuesta HTTP)."""
    if rag.is_available and events:
        added = rag.index_events(events)
        if added > 0:
            logger.info(f"RAG background: {added} eventos nuevos indexados.")


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/status", summary="Estado del contenedor y del sistema RAG")
def get_status():
    return {
        "server":     "online",
        "container":  _get_container_status(),
        "log_source": "sample_data" if _is_using_sample() else "live_cowrie",
        "log_path":   str(COWRIE_LOG_PATH),
        "rag": {
            "available":     rag.is_available,
            "indexed_count": rag.indexed_count,
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api/logs", summary="Eventos del log con filtros opcionales")
def get_logs(
    background_tasks: BackgroundTasks,
    limit:      int            = Query(default=200, ge=1, le=5000),
    event_type: Optional[str]  = Query(default=None),
    src_ip:     Optional[str]  = Query(default=None),
):
    events = _load_logs()

    # Auto-indexar en segundo plano (sin bloquear la respuesta)
    background_tasks.add_task(_index_in_background, events)

    # Aplicar filtros
    if event_type:
        events = [e for e in events if e.get("eventid") == event_type]
    if src_ip:
        events = [e for e in events if e.get("src_ip") == src_ip]

    events = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "total":  len(events),
        "limit":  limit,
        "source": "sample_data" if _is_using_sample() else "live",
        "events": events[:limit],
    }


@app.get("/api/stats", summary="Estadísticas agregadas del honeypot")
def get_stats():
    events = _load_logs()
    if not events:
        return {"error": "Sin eventos disponibles"}

    event_counts  = Counter(e.get("eventid", "unknown") for e in events)
    all_ips       = [e.get("src_ip") for e in events if e.get("src_ip")]
    unique_ips    = len(set(all_ips))
    top_ips       = Counter(all_ips).most_common(10)

    logins_ok     = [
        {"ip": e.get("src_ip"), "user": e.get("username"),
         "pass": e.get("password"), "ts": e.get("timestamp")}
        for e in events if e.get("eventid") == "cowrie.login.success"
    ]
    logins_fail   = sum(1 for e in events if e.get("eventid") == "cowrie.login.failed")
    commands      = [
        e.get("input", "") for e in events
        if e.get("eventid") == "cowrie.command.input" and e.get("input")
    ]
    top_commands  = Counter(commands).most_common(10)
    sessions      = len({e.get("session") for e in events if e.get("session")})

    hourly = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if ts and len(ts) >= 13:
            hourly[ts[11:13]] += 1

    return {
        "total_events":     len(events),
        "unique_ips":       unique_ips,
        "unique_sessions":  sessions,
        "logins_success":   len(logins_ok),
        "logins_failed":    logins_fail,
        "total_commands":   len(commands),
        "event_breakdown":  dict(event_counts),
        "top_ips":          [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_commands":     [{"command": cmd, "count": c} for cmd, c in top_commands],
        "successful_logins": logins_ok[:20],
        "hourly_activity":  dict(sorted(hourly.items())),
        "source":           "sample_data" if _is_using_sample() else "live",
        # RAG: cuántos tienen historial
        "rag_indexed":      rag.indexed_count,
        "rag_available":    rag.is_available,
    }


@app.post("/api/analyze", summary="Análisis de IA con prompt avanzado + RAG + MITRE ATT&CK")
async def analyze_with_ai(req: AnalyzeRequest):
    """
    Análisis completo de threat intelligence:
    1. Pre-análisis automático (timing, credenciales, MITRE auto-detect)
    2. Contexto histórico RAG inyectado en el prompt
    3. Prompt chain-of-thought con few-shot example + 6 secciones estructuradas
    4. Mapeo MITRE ATT&CK automático (20+ técnicas para SSH honeypot)
    """
    events = _load_logs()

    critical = [
        e for e in events
        if e.get("eventid") in (
            "cowrie.login.success", "cowrie.command.input", "cowrie.login.failed",
            "cowrie.session.connect",
        )
    ]
    critical = critical[: (req.max_events or 50)]

    if not critical:
        raise HTTPException(status_code=404, detail="Sin eventos críticos para analizar")

    # ─── Pre-análisis estadístico ──────────────────────────────────────────────
    pre = pre_analyze(critical)
    logger.info(
        f"Pre-análisis: {len(pre['mitre'])} técnicas MITRE, "
        f"{pre['credentials'].get('total_attempts',0)} credenciales, "
        f"timing={pre['timing'].get('avg_interval_s')}s"
    )

    # ─── Formatear eventos para el prompt ─────────────────────────────────────
    lines = []
    for e in critical:
        eid = e.get("eventid", "")
        ip  = e.get("src_ip", "N/A")
        ts  = str(e.get("timestamp", ""))[:19].replace("T", " ")
        if eid == "cowrie.login.success":
            lines.append(f"[{ts}] LOGIN EXITOSO | IP: {ip} | {e.get('username')}/{e.get('password')}")
        elif eid == "cowrie.login.failed":
            lines.append(f"[{ts}] LOGIN FALLIDO | IP: {ip} | {e.get('username')}/{e.get('password')}")
        elif eid == "cowrie.command.input":
            lines.append(f"[{ts}] COMANDO       | IP: {ip} | {e.get('input')}")
        elif eid == "cowrie.session.connect":
            lines.append(f"[{ts}] CONEXION SSH  | IP: {ip} | :{e.get('src_port','?')}")

    events_text = "\n".join(lines)

    # ─── Contexto RAG ─────────────────────────────────────────────────────────
    rag_context  = ""
    rag_was_used = False

    if req.use_rag and rag.is_available:
        rag_context = rag.build_rag_context(critical)
        if rag_context:
            rag_was_used = True
            logger.info("RAG: contexto histórico incluido en el prompt.")

    # ─── Construir prompt con técnicas avanzadas ───────────────────────────────
    prompt = build_prompt(
        events_text=events_text,
        pre_analysis=pre,
        rag_context=rag_context,
    )

    # ─── Elegir motor: Groq (rápido/cloud) u Ollama (local) ──────────────────
    mitre_summary = [{"id": t["id"], "name": t["name"]} for t in pre["mitre"]]

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            if USE_GROQ:
                # ── Groq: OpenAI-compatible, ~3-5 segundos ────────────────────
                groq_payload = {
                    "model":       GROQ_MODEL,
                    "messages":    [{"role": "user", "content": prompt}],
                    "max_tokens":  800,
                    "temperature": 0.15,
                }
                response = await client.post(
                    GROQ_ENDPOINT,
                    json=groq_payload,
                    headers={
                        "Authorization": f"Bearer {GROQ_API_KEY}",
                        "Content-Type":  "application/json",
                    },
                )
                response.raise_for_status()
                analysis_text = response.json()["choices"][0]["message"]["content"]
                engine_used   = f"groq/{GROQ_MODEL}"
            else:
                # ── Ollama: local, sin API key ─────────────────────────────────
                model   = req.model or OLLAMA_MODEL
                payload = {
                    "model":   model,
                    "prompt":  prompt,
                    "stream":  False,
                    "options": {"temperature": 0.15, "num_predict": 450},
                }
                response = await client.post(OLLAMA_ENDPOINT, json=payload)
                response.raise_for_status()
                analysis_text = response.json().get("response", "")
                engine_used   = f"ollama/{model}"

            return {
                "model":            engine_used,
                "analysis":         analysis_text,
                "events_analyzed":  len(critical),
                "source":           "sample_data" if _is_using_sample() else "live",
                "rag_context_used": rag_was_used,
                "rag_indexed":      rag.indexed_count,
                "pre_analysis": {
                    "timing":          pre["timing"],
                    "credential_type": pre["credentials"].get("type", ""),
                    "mitre_detected":  mitre_summary,
                    "success_logins":  len(pre["success_logins"]),
                    "commands_count":  len(pre["commands"]),
                    "unique_ips":      len(pre["unique_ips"]),
                },
            }

    except httpx.ConnectError:
        detail = (
            "No se pudo conectar con Groq. Verifica tu GROQ_API_KEY."
            if USE_GROQ else
            "No se pudo conectar con Ollama. Ejecuta: `ollama serve`"
        )
        raise HTTPException(status_code=503, detail=detail)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="El motor de IA tardó demasiado.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


# ─── Endpoints RAG ────────────────────────────────────────────────────────────

@app.get("/api/rag/stats", summary="Estadísticas de la base de datos vectorial ChromaDB")
def get_rag_stats():
    """Muestra cuántos eventos están indexados en la memoria histórica RAG."""
    return rag.get_stats()


@app.post("/api/rag/index", summary="Indexar logs actuales en ChromaDB manualmente")
def trigger_rag_index():
    """
    Fuerza la re-indexación de los logs actuales.
    Útil cuando se quieren indexar datos nuevos sin reiniciar el servidor.
    """
    if not rag.is_available:
        raise HTTPException(
            status_code=503,
            detail="ChromaDB no disponible. Instala: pip install chromadb",
        )
    events = _load_logs()
    if not events:
        raise HTTPException(status_code=404, detail="Sin logs disponibles para indexar.")

    added = rag.index_events(events)
    return {
        "status":  "ok",
        "total_events_processed": len(events),
        "new_events_added": added,
        "total_indexed": rag.indexed_count,
    }


@app.get("/api/history/{ip}", summary="Historial completo de una IP en la memoria RAG")
def get_ip_history(ip: str):
    """
    Recupera todo el historial de ataques de una IP específica desde la base
    de datos vectorial. Incluye credenciales históricas, comandos y timeline.
    """
    if not rag.is_available:
        raise HTTPException(
            status_code=503,
            detail="ChromaDB no disponible. Instala: pip install chromadb",
        )
    history = rag.get_ip_history(ip)
    if "error" in history:
        raise HTTPException(status_code=500, detail=history["error"])
    return history


@app.get("/api/search", summary="Búsqueda semántica en la memoria histórica")
def search_similar(q: str = Query(..., description="Texto de búsqueda"), n: int = Query(default=5, ge=1, le=20)):
    """
    Búsqueda semántica en todos los eventos históricos.
    Ejemplo: /api/search?q=curl+descarga+malware
    """
    if not rag.is_available:
        raise HTTPException(status_code=503, detail="ChromaDB no disponible.")
    results = rag.search_similar(q, n_results=n)
    return {"query": q, "results": results, "count": len(results)}


# ─── Archivos estáticos del Dashboard ─────────────────────────────────────────
# IMPORTANTE: este bloque DEBE ir al final. Los endpoints /api/* se registran
# antes, por lo que no son interceptados por los mounts.
_dashboard_path = Path("./dashboard")

if _dashboard_path.exists():
    # index.html en la raíz
    @app.get("/", response_class=FileResponse, include_in_schema=False)
    def serve_dashboard():
        return FileResponse(str(_dashboard_path / "index.html"))

    # style.css y app.js serán pedidos con paths RELATIVOS desde index.html,
    # así que deben estar disponibles en "/" (no bajo "/static/")
    @app.get("/style.css", include_in_schema=False)
    def serve_css():
        return FileResponse(str(_dashboard_path / "style.css"), media_type="text/css")

    @app.get("/app.js", include_in_schema=False)
    def serve_js():
        return FileResponse(str(_dashboard_path / "app.js"), media_type="application/javascript")

    # Resto de assets estáticos opcionales
    app.mount("/assets", StaticFiles(directory=str(_dashboard_path)), name="assets")

else:
    @app.get("/", include_in_schema=False)
    def root():
        return {
            "message":   "Cowrie Honeypot API v2.2",
            "docs":      "/docs",
            "endpoints": [
                "/api/status", "/api/logs", "/api/stats", "/api/analyze",
                "/api/rag/stats", "/api/rag/index", "/api/history/{ip}", "/api/search",
            ],
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
