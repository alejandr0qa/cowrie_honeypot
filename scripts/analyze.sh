#!/usr/bin/env bash
# ==============================================================================
# analyze.sh — Analizador de Cowrie Honeypot para Linux/Mac/WSL
# Versión: 2.0
#
# USO:
#   ./scripts/analyze.sh
#   ./scripts/analyze.sh --demo
#   ./scripts/analyze.sh --model llama3 --max-events 100
#   ./scripts/analyze.sh --no-ai
# ==============================================================================

set -euo pipefail

# ─── Colores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; GRAY='\033[0;37m'
BOLD='\033[1m'; NC='\033[0m'

# ─── Defaults ─────────────────────────────────────────────────────────────────
CONTAINER_NAME="cowrie_honeypot"
MODEL_NAME="tinyllama"
OLLAMA_ENDPOINT="http://localhost:11434/api/generate"
MAX_EVENTS=50
DEMO=false
NO_AI=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_DATA="$SCRIPT_DIR/../sample-data/cowrie_sample.json"
LOG_INSIDE="/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
LOCAL_LOG="$SCRIPT_DIR/../cowrie-var/log/cowrie/cowrie.json"
TEMP_LOG="/tmp/cowrie_temp_$$.json"

ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${WHITE}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; }
section() { echo -e "\n${CYAN}${BOLD}─────────────────────────────────────────────────────────────${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"; }

# ─── Parseo de argumentos ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --demo)       DEMO=true ;;
        --no-ai)      NO_AI=true ;;
        --model)      MODEL_NAME="$2"; shift ;;
        --max-events) MAX_EVENTS="$2"; shift ;;
        --container)  CONTAINER_NAME="$2"; shift ;;
        --endpoint)   OLLAMA_ENDPOINT="$2"; shift ;;
        *) warn "Argumento desconocido: $1" ;;
    esac
    shift
done

# ─── Banner ───────────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         🛡  COWRIE HONEYPOT — ANALIZADOR DE AMENAZAS         ║"
echo "║                    Linux/Mac/WSL v2.0                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── 1. Cargar logs ───────────────────────────────────────────────────────────
section "PASO 1: Obtención de Logs"

LOG_SOURCE=""

if $DEMO; then
    warn "Modo DEMO activo — usando datos de muestra."
    if [[ ! -f "$SAMPLE_DATA" ]]; then
        fail "No se encontró: $SAMPLE_DATA"; exit 1
    fi
    LOG_SOURCE="$SAMPLE_DATA"
    ok "Datos de muestra cargados."
elif docker inspect "$CONTAINER_NAME" --format "{{.State.Status}}" 2>/dev/null | grep -q "running"; then
    info "Extrayendo logs del contenedor '$CONTAINER_NAME'..."
    docker cp "${CONTAINER_NAME}:${LOG_INSIDE}" "$TEMP_LOG" 2>/dev/null || {
        warn "Log aún no existe en el contenedor (¿sin ataques aún?)"
        exit 0
    }
    LOG_SOURCE="$TEMP_LOG"
    ok "Logs extraídos del contenedor."
elif [[ -f "$LOCAL_LOG" ]]; then
    warn "Contenedor no activo. Usando logs locales."
    LOG_SOURCE="$LOCAL_LOG"
    ok "Logs locales cargados."
else
    fail "No se encontraron logs. Sube el honeypot con: docker compose up -d"
    fail "O usa: ./scripts/analyze.sh --demo"
    exit 1
fi

# ─── 2. Estadísticas ──────────────────────────────────────────────────────────
section "PASO 2: Estadísticas"

TOTAL=$(wc -l < "$LOG_SOURCE" | tr -d ' ')
UNIQUE_IPS=$(grep -o '"src_ip":"[^"]*"' "$LOG_SOURCE" | sort -u | wc -l | tr -d ' ')
CONNECTS=$(grep -c '"cowrie.session.connect"' "$LOG_SOURCE" 2>/dev/null || echo 0)
LOGINS_OK=$(grep -c '"cowrie.login.success"' "$LOG_SOURCE" 2>/dev/null || echo 0)
LOGINS_FAIL=$(grep -c '"cowrie.login.failed"' "$LOG_SOURCE" 2>/dev/null || echo 0)
COMMANDS=$(grep -c '"cowrie.command.input"' "$LOG_SOURCE" 2>/dev/null || echo 0)

echo ""
echo -e "${WHITE}  📊 Resumen del Periodo:${NC}"
echo -e "${GRAY}     Eventos totales      : ${WHITE}$TOTAL${NC}"
echo -e "${GRAY}     IPs únicas           : ${CYAN}$UNIQUE_IPS${NC}"
echo -e "${GRAY}     Conexiones SSH       : ${GRAY}$CONNECTS${NC}"
echo -e "${GRAY}     Logins EXITOSOS      : ${RED}$LOGINS_OK${NC}"
echo -e "${GRAY}     Logins fallidos      : ${YELLOW}$LOGINS_FAIL${NC}"
echo -e "${GRAY}     Comandos capturados  : ${GREEN}$COMMANDS${NC}"
echo ""

if [[ "$LOGINS_OK" -gt 0 ]]; then
    echo -e "${RED}  🔴 Credenciales que funcionaron:${NC}"
    grep '"cowrie.login.success"' "$LOG_SOURCE" | \
        python3 -c "import sys,json; [print(f'     {e[\"src_ip\"]} → {e[\"username\"]} / {e[\"password\"]}') for line in sys.stdin for e in [json.loads(line)]]" 2>/dev/null | head -10
fi

if [[ "$COMMANDS" -gt 0 ]]; then
    echo ""
    echo -e "${GREEN}  >_ Últimos comandos ejecutados:${NC}"
    grep '"cowrie.command.input"' "$LOG_SOURCE" | tail -10 | \
        python3 -c "import sys,json; [print(f'     {e[\"src_ip\"]} → {e[\"input\"]}') for line in sys.stdin for e in [json.loads(line)]]" 2>/dev/null
fi

# ─── 3. Análisis IA ───────────────────────────────────────────────────────────
if ! $NO_AI; then
    section "PASO 3: Análisis de Inteligencia de Amenazas (IA)"
    info "Modelo: $MODEL_NAME"

    REPORT_DATA=$(python3 - <<PYEOF 2>/dev/null
import json, sys

events = []
with open("$LOG_SOURCE") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            eid = e.get("eventid","")
            if eid in ("cowrie.login.success","cowrie.login.failed","cowrie.command.input"):
                ts = e.get("timestamp","")[:19].replace("T"," ")
                ip = e.get("src_ip","N/A")
                if eid == "cowrie.login.success":
                    print(f"[{ts}] LOGIN EXITOSO | IP: {ip} | {e.get('username')}/{e.get('password')}")
                elif eid == "cowrie.login.failed":
                    print(f"[{ts}] LOGIN FALLIDO | IP: {ip} | {e.get('username')}/{e.get('password')}")
                elif eid == "cowrie.command.input":
                    print(f"[{ts}] COMANDO       | IP: {ip} | {e.get('input')}")
        except:
            pass
PYEOF
    )

    if [[ -z "$REPORT_DATA" ]]; then
        warn "No hay eventos críticos para analizar."
    else
        PROMPT="Eres un analista experto en ciberseguridad. Analiza estos eventos de un honeypot SSH:\n\n$REPORT_DATA\n\nProvee:\n1. Resumen ejecutivo (IPs, riesgo)\n2. Credenciales (diccionario o dirigido)\n3. Comandos y objetivo del atacante\n4. Indicadores de Compromiso (IoC)\n5. Recomendaciones\n\nRespuesta SOLO en español, concisa y profesional."

        BODY=$(python3 -c "
import json, sys
print(json.dumps({
  'model': '$MODEL_NAME',
  'prompt': sys.argv[1],
  'stream': False,
  'options': {'temperature': 0.3, 'num_predict': 800}
}))" "$PROMPT" 2>/dev/null)

        info "Enviando a Ollama, espera (máx. 2 min)..."
        RESPONSE=$(curl -s --max-time 120 \
            -X POST "$OLLAMA_ENDPOINT" \
            -H "Content-Type: application/json" \
            -d "$BODY" 2>/dev/null) || {
            fail "No se pudo conectar con Ollama. ¿Está corriendo: ollama serve?"
            $NO_AI = true
        }

        if [[ -n "$RESPONSE" ]]; then
            ANALYSIS=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('response','(Sin respuesta)'))" 2>/dev/null)
            echo ""
            echo -e "${YELLOW}${"═"*0}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${YELLOW}  📋  REPORTE EJECUTIVO DE SEGURIDAD — $(date '+%Y-%m-%d %H:%M')${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${WHITE}$ANALYSIS${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        fi
    fi
fi

# Limpieza
[[ -f "$TEMP_LOG" ]] && rm -f "$TEMP_LOG"
ok "Proceso finalizado."
