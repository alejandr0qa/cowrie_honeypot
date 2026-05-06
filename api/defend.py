"""
MITRE D3FEND recommendation helpers for Cowrie ATT&CK detections.

The module is offline/static on purpose: it maps ATT&CK techniques already
found by api/prompt.py to defensive controls and SOC actions. It never blocks,
executes commands, or calls external services.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Risk level in the context of an SSH honeypot.
ATTACK_SEVERITY = {
    "T1105": "critical",      # Ingress Tool Transfer
    "T1003": "critical",      # OS Credential Dumping
    "T1098": "critical",      # Account Manipulation
    "T1098.004": "critical",  # SSH Authorized Keys
    "T1110.001": "high",      # Password Guessing
    "T1496": "high",          # Resource Hijacking
    "T1548": "high",          # Abuse Elevation Control
    "T1548.001": "high",
    "T1070": "high",          # Indicator Removal
    "T1053.003": "high",      # Cron persistence
    "T1136": "high",          # Create Account
    "T1562.004": "high",      # Firewall modification
    "T1027": "high",          # Obfuscation
    "T1489": "high",          # Service Stop
    "T1059.004": "high",      # Unix Shell
    "T1059.006": "high",      # Script execution
    "T1021.004": "medium",    # SSH Remote Services
    "T1046": "medium",
    "T1057": "medium",
    "T1082": "medium",
    "T1083": "medium",
    "T1049": "medium",
}

DEFAULT_DEFENSE = {
    "d3fend_controls": [
        "Command Monitoring",
        "Session Analysis",
        "Network Traffic Analysis",
    ],
    "recommended_actions": [
        "Registrar técnica, IP, usuario, comando, sesión y timestamp.",
        "Crear alerta si la técnica se repite desde la misma IP.",
        "Correlacionar la evidencia con el timeline de la sesión.",
    ],
}

# Control names are intentionally human-readable D3FEND-style capabilities.
D3FEND_MAP: dict[str, dict[str, list[str]]] = {
    "T1110.001": {
        "d3fend_controls": [
            "Authentication Event Thresholding",
            "Multi-factor Authentication",
            "Account Lockout",
            "Credential Hardening",
        ],
        "recommended_actions": [
            "Activar rate limiting o fail2ban para intentos SSH repetidos.",
            "Deshabilitar password SSH y exigir llaves públicas en servidores reales.",
            "Alertar múltiples credenciales probadas por una IP en una ventana corta.",
        ],
    },
    "T1021.004": {
        "d3fend_controls": [
            "Network Access Control",
            "Inbound Traffic Filtering",
            "Remote Access Policy Enforcement",
            "Session Monitoring",
        ],
        "recommended_actions": [
            "Restringir SSH por allowlist/VPN en sistemas reales.",
            "Registrar versión de cliente SSH, puerto origen y frecuencia de conexión.",
            "Mantener el honeypot aislado sin rutas hacia la red interna.",
        ],
    },
    "T1105": {
        "d3fend_controls": [
            "Network Traffic Filtering",
            "Outbound Connection Monitoring",
            "File Download Analysis",
            "Executable Allowlisting",
            "URL Reputation Analysis",
        ],
        "recommended_actions": [
            "Extraer URLs de wget/curl/fetch y convertirlas en IoC exportables.",
            "Alertar cuando una sesión SSH descargue binarios o scripts remotos.",
            "Aplicar control de salida y proxy filtrado en servidores productivos.",
        ],
    },
    "T1496": {
        "d3fend_controls": [
            "Process Analysis",
            "Resource Utilization Monitoring",
            "Executable Analysis",
            "Outbound Connection Monitoring",
        ],
        "recommended_actions": [
            "Detectar nombres de mineros como xmrig, minerd, cpuminer y variantes.",
            "Alertar por uso anómalo de CPU/procesos tras login SSH.",
            "Bloquear pools o dominios de minería observados en descargas.",
        ],
    },
    "T1003": {
        "d3fend_controls": [
            "File Access Monitoring",
            "Sensitive File Access Restriction",
            "Credential File Monitoring",
            "Privilege Management",
        ],
        "recommended_actions": [
            "Alertar acceso a /etc/passwd, /etc/shadow o unshadow.",
            "Asegurar permisos estrictos y monitoreo FIM en archivos sensibles.",
            "Enviar logs críticos a almacenamiento remoto no modificable.",
        ],
    },
    "T1070": {
        "d3fend_controls": [
            "Log Integrity Protection",
            "Remote Log Storage",
            "File Deletion Monitoring",
            "Tamper Detection",
        ],
        "recommended_actions": [
            "Enviar logs a SIEM o almacenamiento remoto append-only.",
            "Alertar history -c, shred y borrado de /var/log.",
            "Conservar evidencia de sesión antes de rotar o limpiar logs locales.",
        ],
    },
    "T1098.004": {
        "d3fend_controls": [
            "SSH Key File Monitoring",
            "File Integrity Monitoring",
            "Account Configuration Monitoring",
            "Persistence Detection",
        ],
        "recommended_actions": [
            "Alertar modificaciones a authorized_keys y generación de llaves SSH.",
            "Auditar llaves autorizadas contra un inventario conocido.",
            "Bloquear escritura no autorizada en directorios .ssh productivos.",
        ],
    },
    "T1059.004": {
        "d3fend_controls": [
            "Command Monitoring",
            "Interactive Session Monitoring",
            "Reverse Shell Detection",
            "Executable Allowlisting",
        ],
        "recommended_actions": [
            "Alertar bash -i, /bin/sh y nc -e como ejecución interactiva peligrosa.",
            "Registrar comandos completos y asociarlos a sesión/IP.",
            "Bloquear herramientas de reverse shell en servidores productivos.",
        ],
    },
    "T1059.006": {
        "d3fend_controls": [
            "Script Execution Monitoring",
            "Interpreter Restriction",
            "Command Content Analysis",
            "Executable Allowlisting",
        ],
        "recommended_actions": [
            "Alertar python/perl/ruby one-liners ejecutados desde SSH.",
            "Restringir intérpretes en cuentas de bajo privilegio.",
            "Extraer argumentos del intérprete para análisis y timeline.",
        ],
    },
}


def _priority(attack_id: str) -> str:
    return ATTACK_SEVERITY.get(attack_id, "medium")


def map_attack_to_defenses(attack_techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map ATT&CK techniques to D3FEND-style controls and actions."""
    recommendations: list[dict[str, Any]] = []

    for technique in attack_techniques:
        attack_id = str(technique.get("id", "")).strip()
        if not attack_id:
            continue
        defense = D3FEND_MAP.get(attack_id, DEFAULT_DEFENSE)
        recommendations.append({
            "attack_id": attack_id,
            "attack_name": technique.get("name", "Técnica ATT&CK"),
            "attack_desc": technique.get("desc", ""),
            "evidence": technique.get("evidence", ""),
            "priority": _priority(attack_id),
            "d3fend_controls": defense["d3fend_controls"],
            "recommended_actions": defense["recommended_actions"],
        })

    return sorted(
        recommendations,
        key=lambda item: SEVERITY_WEIGHT.get(item["priority"], 0),
        reverse=True,
    )


def build_defense_summary(pre_analysis: dict[str, Any]) -> dict[str, Any]:
    """Build aggregate API/dashboard response from pre_analyze output."""
    attack_techniques = pre_analysis.get("mitre", []) or []
    recommendations = map_attack_to_defenses(attack_techniques)

    controls: list[str] = []
    actions: list[str] = []
    for rec in recommendations:
        controls.extend(rec["d3fend_controls"])
        actions.extend(rec["recommended_actions"])

    seen_actions = set()
    top_actions = []
    for action in actions:
        if action not in seen_actions:
            seen_actions.add(action)
            top_actions.append(action)

    return {
        "framework": "MITRE D3FEND",
        "attack_framework": "MITRE ATT&CK",
        "total_attack_techniques": len(attack_techniques),
        "total_recommendations": len(recommendations),
        "priority_counts": dict(Counter(rec["priority"] for rec in recommendations)),
        "top_controls": [
            {"control": control, "count": count}
            for control, count in Counter(controls).most_common(8)
        ],
        "top_actions": top_actions[:6],
        "recommendations": recommendations,
    }
