"""
==============================================================================
CowrieRAG — Memoria histórica de ataques via ChromaDB + Embeddings locales
Fuente de inspiración: h4cker/ai-research/RAG/ + vector-databases/

Indexa eventos de Cowrie como vectores para:
  - Buscar si una IP atacó antes
  - Enriquecer el prompt del LLM con contexto histórico
  - Detectar patrones recurrentes entre sesiones
==============================================================================
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Tipos de eventos a indexar (los más significativos)
INDEXABLE_EVENTS = {
    "cowrie.session.connect",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
    "cowrie.session.closed",
}


class CowrieRAG:
    """
    Memoria vectorial de ataques del honeypot Cowrie.

    Usa ChromaDB como vector store local (sin cloud, sin APIs externas).
    El modelo de embeddings es all-MiniLM-L6-v2 vía ONNX (incluido en chromadb).

    Flujo:
      1. index_events(events)    → almacena eventos como vectores
      2. build_rag_context(...)  → busca historial de las IPs actuales
      3. El contexto se inyecta en el prompt antes de llamar a Ollama
    """

    def __init__(self, persist_dir: str = "./rag_db"):
        self._client = None
        self._collection = None
        self._persist_dir = str(Path(persist_dir).resolve())
        self._available = False

        try:
            import chromadb  # noqa: F401 — importación lazy
            self._init_db()
        except ImportError:
            logger.warning(
                "⚠ chromadb no está instalado. RAG desactivado.\n"
                "  Instalar: pip install chromadb"
            )

    def _init_db(self):
        """Inicializa el cliente ChromaDB y crea/carga la colección."""
        import chromadb

        Path(self._persist_dir).mkdir(parents=True, exist_ok=True)

        self._client = chromadb.PersistentClient(path=self._persist_dir)
        self._collection = self._client.get_or_create_collection(
            name="cowrie_events",
            metadata={"hnsw:space": "cosine"},
        )
        self._available = True
        count = self._collection.count()
        logger.info(f"✅ ChromaDB listo en '{self._persist_dir}' — {count} eventos indexados.")

    # ─── Propiedades ──────────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def indexed_count(self) -> int:
        if self._available and self._collection:
            return self._collection.count()
        return 0

    # ─── Conversión evento → texto/metadata ───────────────────────────────────

    def _event_to_text(self, event: dict) -> str:
        """Texto legible que se convierte en embedding. Optimizado para relevancia semántica."""
        eid = event.get("eventid", "")
        ip  = event.get("src_ip", "desconocida")
        ts  = str(event.get("timestamp", ""))[:10]

        if eid == "cowrie.login.success":
            return (
                f"Login SSH exitoso desde {ip} el {ts} "
                f"con usuario '{event.get('username', '?')}' y contraseña '{event.get('password', '?')}'"
            )
        if eid == "cowrie.login.failed":
            return (
                f"Intento de login fallido desde {ip} el {ts} "
                f"con usuario '{event.get('username', '?')}' y contraseña '{event.get('password', '?')}'"
            )
        if eid == "cowrie.command.input":
            return f"Comando SSH ejecutado desde {ip} el {ts}: {event.get('input', '')}"
        if eid == "cowrie.session.connect":
            return f"Nueva conexión SSH desde {ip} el {ts} puerto {event.get('src_port', '?')}"
        if eid == "cowrie.session.closed":
            return f"Sesión SSH cerrada desde {ip} el {ts}, duración {event.get('duration', '?')}s"

        return f"Evento {eid} desde {ip} el {ts}: {event.get('message', '')}"

    def _event_to_metadata(self, event: dict) -> dict:
        """Metadata estructurada para filtros exactos por IP, tipo de evento, etc.
        IMPORTANTE: ChromaDB solo acepta str/int/float/bool en metadata."""
        return {
            "src_ip":    str(event.get("src_ip", "")),
            "eventid":   str(event.get("eventid", "")),
            "session":   str(event.get("session", "")),
            "timestamp": str(event.get("timestamp", ""))[:19],
            "date":      str(event.get("timestamp", ""))[:10],
            "username":  str(event.get("username", "")),
            "password":  str(event.get("password", "")),
            "command":   str(event.get("input", "")),
            "duration":  str(event.get("duration", "")),
        }

    def _event_id(self, event: dict) -> str:
        """ID único y estable para un evento (basado en UUID + timestamp + eventid)."""
        raw = "|".join([
            str(event.get("uuid", "")),
            str(event.get("eventid", "")),
            str(event.get("timestamp", "")),
            str(event.get("session", "")),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    # ─── Indexación ───────────────────────────────────────────────────────────

    def index_events(self, events: list[dict]) -> int:
        """
        Indexa una lista de eventos en ChromaDB.
        Usa upsert para evitar duplicados si se llama varias veces sobre los mismos datos.
        Retorna cuántos eventos nuevos se agregaron.
        """
        if not self._available:
            return 0

        # Filtrar solo eventos relevantes
        to_index = [e for e in events if e.get("eventid") in INDEXABLE_EVENTS]
        if not to_index:
            return 0

        before = self._collection.count()

        try:
            # Procesar en lotes de 200 para eficiencia
            batch_size = 200
            for i in range(0, len(to_index), batch_size):
                batch = to_index[i: i + batch_size]
                self._collection.upsert(
                    ids=[self._event_id(e) for e in batch],
                    documents=[self._event_to_text(e) for e in batch],
                    metadatas=[self._event_to_metadata(e) for e in batch],
                )

            after   = self._collection.count()
            added   = after - before
            logger.info(f"RAG: {len(to_index)} eventos procesados, {added} nuevos. Total: {after}")
            return max(added, 0)

        except Exception as e:
            logger.error(f"Error al indexar eventos en ChromaDB: {e}")
            return 0

    # ─── Consultas ────────────────────────────────────────────────────────────

    def get_ip_history(self, ip: str) -> dict:
        """
        Recupera todo el historial de eventos de una IP específica.
        Usa filtro de metadata exacto (no búsqueda semántica).
        """
        if not self._available:
            return {"available": False, "ip": ip}

        total = self._collection.count()
        if total == 0:
            return {"ip": ip, "total_events": 0, "events": [], "available": True}

        try:
            result = self._collection.get(
                where={"src_ip": {"$eq": ip}},
                include=["documents", "metadatas"],
            )

            events = [
                {"text": doc, "metadata": result["metadatas"][i]}
                for i, doc in enumerate(result["documents"])
            ]

            # Ordenar cronológicamente
            events.sort(key=lambda x: x["metadata"].get("timestamp", ""))

            # Derivar estadísticas
            sessions  = {e["metadata"].get("session")  for e in events if e["metadata"].get("session")}
            ok_events = [e for e in events if e["metadata"].get("eventid") == "cowrie.login.success"]
            fail_evts = [e for e in events if e["metadata"].get("eventid") == "cowrie.login.failed"]
            cmd_evts  = [e for e in events if e["metadata"].get("eventid") == "cowrie.command.input"]

            credentials = list({
                f"{e['metadata'].get('username')}/{e['metadata'].get('password')}"
                for e in ok_events + fail_evts
                if e["metadata"].get("username")
            })[:15]

            commands = list({
                e["metadata"].get("command")
                for e in cmd_evts
                if e["metadata"].get("command")
            })[:15]

            return {
                "available": True,
                "ip": ip,
                "total_events":    len(events),
                "unique_sessions": len(sessions),
                "logins_success":  len(ok_events),
                "logins_failed":   len(fail_evts),
                "commands_count":  len(cmd_evts),
                "first_seen":  events[0]["metadata"].get("timestamp", "")  if events else "",
                "last_seen":   events[-1]["metadata"].get("timestamp", "") if events else "",
                "credentials_tried": credentials,
                "commands":    commands,
                "events":      events[:60],   # Máx 60 eventos en la respuesta para no inflar
            }

        except Exception as e:
            logger.error(f"Error al consultar historial de {ip}: {e}")
            return {"available": True, "ip": ip, "error": str(e)}

    def search_similar(self, query_text: str, n_results: int = 5) -> list[dict]:
        """Búsqueda semántica: eventos similares al texto de consulta."""
        if not self._available:
            return []
        total = self._collection.count()
        if total == 0:
            return []
        try:
            result = self._collection.query(
                query_texts=[query_text],
                n_results=min(n_results, total),
                include=["documents", "metadatas", "distances"],
            )
            return [
                {
                    "text":     result["documents"][0][i],
                    "metadata": result["metadatas"][0][i],
                    "distance": round(result["distances"][0][i], 4),
                }
                for i in range(len(result["documents"][0]))
            ]
        except Exception as e:
            logger.error(f"Error en búsqueda semántica: {e}")
            return []

    def build_rag_context(self, current_events: list[dict]) -> str:
        """
        Construye el bloque de contexto histórico para incluir en el prompt del LLM.

        Para cada IP presente en los eventos actuales, recupera su historial
        y formatea un resumen que el LLM pueda usar para comparar.

        Retorna string vacío si no hay historial relevante.
        """
        if not self._available or self._collection.count() == 0:
            return ""

        unique_ips = list({e.get("src_ip") for e in current_events if e.get("src_ip")})
        if not unique_ips:
            return ""

        # Contar eventos actuales por IP para excluirlos del "historial previo"
        current_ip_counts = {}
        for e in current_events:
            ip = e.get("src_ip", "")
            current_ip_counts[ip] = current_ip_counts.get(ip, 0) + 1

        parts = ["╔═══ MEMORIA HISTÓRICA DE ATAQUES (contexto RAG) ═══╗"]
        has_real_history = False

        for ip in unique_ips[:5]:
            history = self.get_ip_history(ip)
            total_hist = history.get("total_events", 0)
            current_n  = current_ip_counts.get(ip, 0)

            # Si los eventos históricos son solo los actuales, es primera vez
            if total_hist <= current_n:
                parts.append(f"\n  📍 IP {ip}: Primera aparición en el sistema.")
                continue

            has_real_history = True
            block = [f"\n  🔴 IP {ip} — YA VISTA ANTERIORMENTE:"]
            block.append(f"     Primera aparición  : {history.get('first_seen', 'N/A')[:19].replace('T',' ')}")
            block.append(f"     Última actividad   : {history.get('last_seen',  'N/A')[:19].replace('T',' ')}")
            block.append(f"     Sesiones históricas: {history.get('unique_sessions', 0)}")
            block.append(f"     Logins exitosos    : {history.get('logins_success', 0)}")
            block.append(f"     Intentos fallidos  : {history.get('logins_failed', 0)}")

            creds = history.get("credentials_tried", [])
            if creds:
                block.append(f"     Credenciales previas: {' | '.join(creds[:6])}")

            cmds = history.get("commands", [])
            if cmds:
                block.append(f"     Comandos previos   : {' | '.join(cmds[:5])}")

            parts.append("\n".join(block))

        if not has_real_history:
            return ""

        parts.append("\n╚═══ FIN DE LA MEMORIA HISTÓRICA ═══╝")
        return "\n".join(parts)

    # ─── Estadísticas ─────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Estadísticas de la base de datos vectorial."""
        if not self._available:
            return {"available": False, "reason": "chromadb no instalado"}

        try:
            total = self._collection.count()

            if total == 0:
                return {"available": True, "total_indexed": 0, "unique_ips": 0,
                        "event_breakdown": {}, "persist_dir": self._persist_dir}

            # Obtener una muestra para estadísticas
            limit   = min(total, 2000)
            sample  = self._collection.get(limit=limit, include=["metadatas"])
            metas   = sample.get("metadatas", [])

            unique_ips    = len({m.get("src_ip")  for m in metas if m.get("src_ip")})
            event_counts  = {}
            for m in metas:
                eid = m.get("eventid", "unknown")
                event_counts[eid] = event_counts.get(eid, 0) + 1

            # IP más frecuente
            ip_counts = {}
            for m in metas:
                ip = m.get("src_ip", "")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else ""

            return {
                "available":      True,
                "total_indexed":  total,
                "unique_ips":     unique_ips,
                "event_breakdown": event_counts,
                "top_attacker":   top_ip,
                "top_attacker_count": ip_counts.get(top_ip, 0),
                "persist_dir":    self._persist_dir,
            }

        except Exception as e:
            logger.error(f"Error en get_stats RAG: {e}")
            return {"available": True, "total_indexed": 0, "error": str(e)}
