# ==============================================================================
# Script: Generador-Web.ps1
# Descripción: Analiza logs de Cowrie con IA local (Ollama) y genera un
#              Dashboard HTML de inteligencia de amenazas estilo SOC.
# Uso: .\Generador-Web.ps1 [-Model "llama3"] [-MaxEvents 500] [-NoOpen]
# ==============================================================================
[CmdletBinding()]
param(
    [string]$ContainerName   = "cowrie_honeypot",
    [string]$LogPathInside   = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json",
    [string]$LogPathLocal    = "$env:TEMP\cowrie_temp.json",
    [string]$ReporteWeb      = ".\Dashboard_Inteligencia.html",
    [string]$OllamaEndpoint  = "http://localhost:11434/api/generate",
    [string]$Model           = "tinyllama",   # Cambia a llama3 si tienes RAM
    [int]   $MaxEvents       = 500,
    [switch]$NoOpen                           # No abrir el navegador al final
)

Set-StrictMode -Version 2   # Version Latest rompe .Count en GroupInfo con un solo elemento
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step { param([string]$Msg) Write-Host "`n[>] $Msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$Msg) Write-Host "    [OK] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "    [!]  $Msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$Msg) Write-Host "    [X]  $Msg" -ForegroundColor Red; exit 1 }

# ── 1. Extracción del contenedor ──────────────────────────────────────────────
Write-Step "Extrayendo logs desde el contenedor '$ContainerName'..."
try {
    docker cp "${ContainerName}:${LogPathInside}" $LogPathLocal 2>&1 | Out-Null
    Write-OK "Archivo copiado a $LogPathLocal"
} catch {
    Write-Fail "No se pudo copiar el log. ¿Está el contenedor activo? Error: $_"
}

# ── 2. Parseo y filtrado ──────────────────────────────────────────────────────
Write-Step "Parseando y filtrando eventos críticos..."
$EventosInteres = @(
    'cowrie.login.success',
    'cowrie.login.failed',
    'cowrie.command.input',
    'cowrie.session.connect',
    'cowrie.session.closed'
)

$RawLines = Get-Content $LogPathLocal -ErrorAction SilentlyContinue

if (-not $RawLines) { Write-Fail "El archivo de log está vacío o no existe." }

$AllLogs = $RawLines | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_ -ne $null }

Write-OK "Total de entradas parseadas: $($AllLogs.Count)"

$CriticalEvents = $AllLogs | Where-Object { $EventosInteres -contains $_.eventid } |
                  Select-Object -Last $MaxEvents

if (-not $CriticalEvents) { Write-Fail "No se encontraron eventos de interés en los logs." }
Write-OK "Eventos críticos encontrados: $($CriticalEvents.Count)"

# ── 3. Estadísticas pre-IA ────────────────────────────────────────────────────
Write-Step "Calculando estadísticas..."

# Top IPs atacantes
$TopIPs = @($AllLogs | Where-Object { $_.src_ip } |
    Group-Object src_ip | Sort-Object { $_.Count } -Descending | Select-Object -First 10)

# Credenciales más usadas (logins fallidos + exitosos)
$LoginEvents = @($AllLogs | Where-Object { $_.eventid -match 'cowrie.login' -and $_.username })
$TopCredentials = @($LoginEvents |
    ForEach-Object { "$($_.username):$($_.password)" } |
    Group-Object | Sort-Object { $_.Count } -Descending | Select-Object -First 8)

# Comandos más ejecutados
$TopCommands = @($AllLogs | Where-Object { $_.eventid -eq 'cowrie.command.input' -and $_.input } |
    Group-Object input | Sort-Object { $_.Count } -Descending | Select-Object -First 8)

# Logins exitosos (IPs comprometidas)
$SuccessfulLogins = $AllLogs | Where-Object { $_.eventid -eq 'cowrie.login.success' }

# Actividad por hora
$ActividadPorHora = @($AllLogs | Where-Object { $_.timestamp } |
    ForEach-Object {
        try { [datetime]::Parse($_.timestamp).Hour } catch { $null }
    } | Where-Object { $_ -ne $null } |
    Group-Object | Sort-Object Name | Select-Object Name, Count

# ── 4. Preparar datos compactos para la IA ────────────────────────────────────
Write-Step "Preparando contexto para el modelo '$Model'..."

$ResumenDatos = @"
=== RESUMEN DE ATAQUE AL HONEYPOT ===
Total eventos: $($AllLogs.Count)
Logins exitosos: $($SuccessfulLogins.Count)
Logins fallidos: $(($LoginEvents | Where-Object { $_.eventid -eq 'cowrie.login.failed' }).Count)
Comandos ejecutados: $(($AllLogs | Where-Object { $_.eventid -eq 'cowrie.command.input' }).Count)

TOP 5 IPs ATACANTES:
$(($TopIPs | Select-Object -First 5 | ForEach-Object { "- $($_.Name): $($_.Count) intentos" }) -join "`n")

CREDENCIALES MÁS PROBADAS:
$(($TopCredentials | Select-Object -First 5 | ForEach-Object { "- $($_.Name): $($_.Count) veces" }) -join "`n")

COMANDOS MÁS EJECUTADOS:
$(($TopCommands | Select-Object -First 5 | ForEach-Object { "- $($_.Name): $($_.Count) veces" }) -join "`n")
"@

$Prompt = @"
Eres un analista senior de ciberseguridad (SOC Tier 2). Analiza estos datos de un honeypot Cowrie y redacta en ESPAÑOL:

1. **Resumen Ejecutivo** (2-3 oraciones): naturaleza del ataque, escala, urgencia.
2. **Actores de Amenaza**: perfil de los atacantes basado en IPs y TTPs observadas.
3. **Tácticas Detectadas**: qué técnicas MITRE ATT&CK se evidencian (credential stuffing, etc.).
4. **Nivel de Riesgo**: CRÍTICO / ALTO / MEDIO / BAJO con justificación.
5. **Recomendaciones Inmediatas**: 3 acciones concretas.

Usa tono técnico-formal. Sin markdown excesivo.

$ResumenDatos
"@

# ── 5. Consulta al modelo Ollama ──────────────────────────────────────────────
Write-Step "Consultando modelo de IA (esto puede tardar 30-120s)..."
$ResumenIA = "[Análisis de IA no disponible]"
try {
    $Body = @{
        model  = $Model
        prompt = $Prompt
        stream = $false
        options = @{ num_predict = 600; temperature = 0.3 }
    } | ConvertTo-Json -Depth 3

    $Response = Invoke-RestMethod -Uri $OllamaEndpoint -Method Post `
                    -Body $Body -ContentType "application/json" `
                    -TimeoutSec 180
    $ResumenIA = $Response.response
    Write-OK "Análisis generado ($($ResumenIA.Length) caracteres)"
} catch {
    Write-Warn "No se pudo contactar Ollama: $_. El dashboard se generará sin análisis IA."
}

# ── 6. Construcción de datos JSON para las gráficas ──────────────────────────
$JsonTopIPs = ($TopIPs | Select-Object -First 8 | ForEach-Object {
    $n = [int]($_ | Select-Object -ExpandProperty Count)
    "{`"ip`":`"$($_.Name)`",`"count`":$n}"
}) -join ","

$JsonTopCreds = ($TopCredentials | Select-Object -First 6 | ForEach-Object {
    $n = [int]($_ | Select-Object -ExpandProperty Count)
    $escaped = $_.Name -replace '"', '\"'
    "{`"cred`":`"$escaped`",`"count`":$n}"
}) -join ","

$JsonTopCmds = ($TopCommands | Select-Object -First 6 | ForEach-Object {
    $n = [int]($_ | Select-Object -ExpandProperty Count)
    $escaped = ($_.Name -replace '"', '\"').Substring(0, [Math]::Min($_.Name.Length, 40))
    "{`"cmd`":`"$escaped`",`"count`":$n}"
}) -join ","

$JsonHorario = ($ActividadPorHora | ForEach-Object {
    $n = [int]($_ | Select-Object -ExpandProperty Count)
    "{`"hour`":$($_.Name),`"count`":$n}"
}) -join ","

# Tabla de últimos 15 eventos críticos
$TablaFilas = ($CriticalEvents | Select-Object -Last 15 | ForEach-Object {
    $ts   = if ($_.timestamp) { $_.timestamp.ToString().Substring(0, [Math]::Min($_.timestamp.ToString().Length, 19)) } else { "—" }
    $tipo = switch -Wildcard ($_.eventid) {
        "*success*" { '<span class="badge success">LOGIN OK</span>' }
        "*failed*"  { '<span class="badge failed">LOGIN FAIL</span>' }
        "*command*" { '<span class="badge command">CMD</span>' }
        "*connect*" { '<span class="badge connect">CONNECT</span>' }
        default     { "<span class='badge'>$($_.eventid)</span>" }
    }
    $ip      = if ($_.src_ip)   { $_.src_ip }   else { "—" }
    $detalle = if ($_.eventid -match "login") {
        "$($_.username)/$($_.password)"
    } elseif ($_.input) {
        ($_.input -replace "<", "&lt;" -replace ">", "&gt;").Substring(0, [Math]::Min($_.input.Length, 50))
    } else { "—" }

    "<tr><td>$ts</td><td>$tipo</td><td class='mono'>$ip</td><td class='mono'>$detalle</td></tr>"
}) -join "`n"

# Métricas de cabecera
$TotalSesiones = ($AllLogs | Where-Object { $_.eventid -eq 'cowrie.session.connect' }).Count
$TotalComandos = ($AllLogs | Where-Object { $_.eventid -eq 'cowrie.command.input' }).Count
$IPsUnicas     = ($AllLogs | Where-Object { $_.src_ip } | Select-Object -ExpandProperty src_ip -Unique).Count
$RiesgoTexto   = if ($SuccessfulLogins.Count -gt 0) { "CRÍTICO" } elseif ($IPsUnicas -gt 20) { "ALTO" } else { "MEDIO" }
$RiesgoClase   = $RiesgoTexto.ToLower() -replace "í", "i" -replace "Í", "i"

$FechaActual   = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
$ResumenIAHtml = ($ResumenIA -replace "&","&amp;" -replace "<","&lt;" -replace ">","&gt;" -replace "`n","<br>")

# ── 7. HTML del Dashboard ─────────────────────────────────────────────────────
Write-Step "Generando dashboard HTML..."

$HtmlContent = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Dashboard — Cowrie Threat Intelligence</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&family=Barlow+Condensed:wght@700;800&display=swap');

  :root {
    --bg0:     #060a0f;
    --bg1:     #0b1118;
    --bg2:     #111924;
    --bg3:     #192030;
    --border:  #1e2d42;
    --accent:  #00d4ff;
    --accent2: #ff4060;
    --accent3: #f0a500;
    --green:   #00e676;
    --text:    #c8d8e8;
    --muted:   #4a6070;
    --mono:    'Share Tech Mono', monospace;
    --sans:    'Barlow', sans-serif;
    --cond:    'Barlow Condensed', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg0);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,212,255,.015) 2px,
      rgba(0,212,255,.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* ── Header ── */
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 18px 32px;
    background: var(--bg1);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
  }
  .logo {
    display: flex; align-items: center; gap: 12px;
  }
  .logo-icon {
    width: 36px; height: 36px;
    border: 2px solid var(--accent);
    border-radius: 6px;
    display: grid; place-items: center;
    font-size: 18px;
    box-shadow: 0 0 12px rgba(0,212,255,.4);
    animation: pulse-border 3s ease-in-out infinite;
  }
  @keyframes pulse-border {
    0%,100% { box-shadow: 0 0 8px rgba(0,212,255,.3); }
    50%      { box-shadow: 0 0 20px rgba(0,212,255,.7); }
  }
  .logo-text {
    font-family: var(--cond);
    font-size: 20px;
    font-weight: 800;
    letter-spacing: .06em;
    color: #fff;
  }
  .logo-text span { color: var(--accent); }
  .header-right {
    display: flex; align-items: center; gap: 20px;
    font-family: var(--mono); font-size: 11px; color: var(--muted);
  }
  .live-dot {
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    animation: blink 1.4s step-end infinite;
  }
  @keyframes blink { 50% { opacity: 0; } }

  /* ── Layout ── */
  main { padding: 28px 32px; max-width: 1400px; margin: 0 auto; }
  .section-title {
    font-family: var(--cond);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .18em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 14px;
    display: flex; align-items: center; gap: 8px;
  }
  .section-title::after {
    content: ''; flex: 1;
    height: 1px; background: var(--border);
  }

  /* ── Metric cards ── */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .metric {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color .2s;
  }
  .metric:hover { border-color: var(--accent); }
  .metric::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0;
    height: 2px;
  }
  .metric.c1::before { background: var(--accent); }
  .metric.c2::before { background: var(--accent2); }
  .metric.c3::before { background: var(--accent3); }
  .metric.c4::before { background: var(--green); }
  .metric.c5::before { background: #b84fff; }
  .metric-label {
    font-size: 10px; letter-spacing: .12em; text-transform: uppercase;
    color: var(--muted); margin-bottom: 8px;
  }
  .metric-value {
    font-family: var(--cond);
    font-size: 38px;
    font-weight: 800;
    line-height: 1;
    color: #fff;
  }
  .metric.c1 .metric-value { color: var(--accent); }
  .metric.c2 .metric-value { color: var(--accent2); }
  .metric.c3 .metric-value { color: var(--accent3); }
  .metric.c4 .metric-value { color: var(--green); }
  .metric.c5 .metric-value { color: #b84fff; }
  .metric-sub { font-size: 11px; color: var(--muted); margin-top: 4px; }

  /* Riesgo especial */
  .risk-badge {
    display: inline-block;
    font-family: var(--cond);
    font-weight: 800;
    font-size: 24px;
    letter-spacing: .08em;
  }
  .risk-critico { color: var(--accent2); }
  .risk-alto    { color: var(--accent3); }
  .risk-medio   { color: #ffd740; }

  /* ── 2-col layout ── */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }
  .three-col { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 28px; }

  /* ── Card ── */
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
  }
  .card-title {
    font-family: var(--cond);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 16px;
  }

  /* ── Bar charts (CSS puro) ── */
  .bar-list { display: flex; flex-direction: column; gap: 10px; }
  .bar-item { }
  .bar-label {
    font-family: var(--mono); font-size: 11px; color: var(--text);
    margin-bottom: 4px;
    display: flex; justify-content: space-between;
  }
  .bar-label .cnt { color: var(--muted); }
  .bar-track {
    height: 6px; background: var(--bg3); border-radius: 3px; overflow: hidden;
  }
  .bar-fill {
    height: 100%; border-radius: 3px;
    animation: grow .8s ease-out forwards;
    transform-origin: left;
  }
  @keyframes grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
  .fill-ip   { background: linear-gradient(90deg, var(--accent), #0080aa); }
  .fill-cred { background: linear-gradient(90deg, var(--accent2), #990030); }
  .fill-cmd  { background: linear-gradient(90deg, var(--accent3), #8a5c00); }

  /* ── Horario sparkline ── */
  .sparkline-wrap { overflow: hidden; }
  .sparkline-bars {
    display: flex; align-items: flex-end;
    gap: 3px; height: 80px;
  }
  .spark-bar {
    flex: 1; background: var(--accent);
    opacity: .7; border-radius: 2px 2px 0 0;
    transition: opacity .2s;
    position: relative;
  }
  .spark-bar:hover { opacity: 1; }
  .spark-bar::after {
    content: attr(data-hour) 'h';
    position: absolute; bottom: -18px; left: 50%;
    transform: translateX(-50%);
    font-size: 9px; color: var(--muted);
    font-family: var(--mono);
  }
  .spark-labels { height: 20px; }

  /* ── AI Analysis ── */
  .ai-card {
    background: var(--bg1);
    border: 1px solid var(--accent);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
  }
  .ai-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
  }
  .ai-header {
    display: flex; align-items: center; gap: 10px; margin-bottom: 16px;
  }
  .ai-badge {
    background: rgba(0,212,255,.12);
    border: 1px solid rgba(0,212,255,.3);
    color: var(--accent);
    font-family: var(--mono);
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: .1em;
  }
  .ai-model {
    font-family: var(--mono); font-size: 11px; color: var(--muted);
  }
  .ai-body {
    font-size: 13.5px;
    line-height: 1.75;
    color: #b8ccd8;
    border-left: 3px solid rgba(0,212,255,.25);
    padding-left: 16px;
  }

  /* ── Tabla ── */
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  thead tr { border-bottom: 1px solid var(--accent); }
  th {
    padding: 8px 12px;
    text-align: left;
    font-family: var(--cond);
    font-size: 10px;
    letter-spacing: .14em;
    text-transform: uppercase;
    color: var(--muted);
    white-space: nowrap;
  }
  td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  tr:hover td { background: rgba(0,212,255,.04); }
  .mono { font-family: var(--mono); }

  .badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 10px;
    padding: 2px 7px;
    border-radius: 3px;
    font-weight: 600;
    white-space: nowrap;
  }
  .badge.success { background: rgba(0,230,118,.15); color: var(--green); border: 1px solid rgba(0,230,118,.3); }
  .badge.failed  { background: rgba(255,64,96,.12); color: var(--accent2); border: 1px solid rgba(255,64,96,.3); }
  .badge.command { background: rgba(240,165,0,.12); color: var(--accent3); border: 1px solid rgba(240,165,0,.3); }
  .badge.connect { background: rgba(0,212,255,.1); color: var(--accent); border: 1px solid rgba(0,212,255,.25); }

  footer {
    text-align: center;
    padding: 24px;
    color: var(--muted);
    font-size: 11px;
    font-family: var(--mono);
    border-top: 1px solid var(--border);
    margin-top: 20px;
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div>
      <div class="logo-text">SOC <span>DASHBOARD</span></div>
      <div style="font-size:10px;color:var(--muted);letter-spacing:.1em;">COWRIE HONEYPOT INTELLIGENCE</div>
    </div>
  </div>
  <div class="header-right">
    <div class="live-dot"></div>
    <span>ANÁLISIS: $FechaActual</span>
    <span style="color:var(--border)">|</span>
    <span>MODELO: $Model</span>
  </div>
</header>

<main>

  <!-- Métricas -->
  <div class="section-title">Métricas Globales</div>
  <div class="metrics-grid">
    <div class="metric c1">
      <div class="metric-label">Total Eventos</div>
      <div class="metric-value">$($AllLogs.Count)</div>
      <div class="metric-sub">en el log completo</div>
    </div>
    <div class="metric c2">
      <div class="metric-label">Logins Exitosos</div>
      <div class="metric-value">$($SuccessfulLogins.Count)</div>
      <div class="metric-sub">credenciales válidas</div>
    </div>
    <div class="metric c3">
      <div class="metric-label">IPs Únicas</div>
      <div class="metric-value">$IPsUnicas</div>
      <div class="metric-sub">fuentes atacantes</div>
    </div>
    <div class="metric c4">
      <div class="metric-label">Comandos</div>
      <div class="metric-value">$TotalComandos</div>
      <div class="metric-sub">post-autenticación</div>
    </div>
    <div class="metric c5">
      <div class="metric-label">Nivel de Riesgo</div>
      <div class="metric-value">
        <span class="risk-badge risk-$RiesgoClase">$RiesgoTexto</span>
      </div>
      <div class="metric-sub">evaluación automática</div>
    </div>
  </div>

  <!-- Análisis IA -->
  <div class="section-title">Análisis de Inteligencia Artificial</div>
  <div class="ai-card">
    <div class="ai-header">
      <span class="ai-badge">AI ANALYSIS</span>
      <span class="ai-model">$Model · local inference</span>
    </div>
    <div class="ai-body">$ResumenIAHtml</div>
  </div>

  <!-- Charts fila 1 -->
  <div class="section-title">Vectores de Ataque</div>
  <div class="three-col">

    <!-- Top IPs -->
    <div class="card">
      <div class="card-title">Top IPs Atacantes</div>
      <div class="bar-list" id="ip-bars"></div>
    </div>

    <!-- Top Credenciales -->
    <div class="card">
      <div class="card-title">Credenciales más usadas</div>
      <div class="bar-list" id="cred-bars"></div>
    </div>

    <!-- Top Comandos -->
    <div class="card">
      <div class="card-title">Comandos más ejecutados</div>
      <div class="bar-list" id="cmd-bars"></div>
    </div>
  </div>

  <!-- Actividad horaria -->
  <div class="section-title">Distribución Temporal</div>
  <div class="card" style="margin-bottom:28px;">
    <div class="card-title">Actividad por hora del día</div>
    <div class="sparkline-wrap">
      <div class="sparkline-bars" id="spark-bars"></div>
      <div class="spark-labels"></div>
    </div>
  </div>

  <!-- Tabla -->
  <div class="section-title">Últimos Eventos Detectados</div>
  <div class="card">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Tipo</th>
            <th>IP Origen</th>
            <th>Detalle</th>
          </tr>
        </thead>
        <tbody>
          $TablaFilas
        </tbody>
      </table>
    </div>
  </div>

</main>

<footer>
  SOC Dashboard · Cowrie Honeypot Intelligence · Generado el $FechaActual · Análisis local con $Model
</footer>

<script>
// ── Datos inyectados desde PowerShell ──────────────────────────────────────
const dataIPs   = [$JsonTopIPs];
const dataCreds = [$JsonTopCreds];
const dataCmds  = [$JsonTopCmds];
const dataHoras = [$JsonHorario];

// ── Barras genéricas ────────────────────────────────────────────────────────
function renderBars(containerId, data, labelKey, countKey, fillClass) {
  const el = document.getElementById(containerId);
  if (!el || !data.length) { el.innerHTML = '<span style="color:#4a6070;font-size:12px">Sin datos</span>'; return; }
  const max = data[0][countKey];
  el.innerHTML = data.map(d => {
    const pct = Math.round((d[countKey] / max) * 100);
    const lbl = String(d[labelKey]).substring(0, 28);
    return `<div class="bar-item">
      <div class="bar-label"><span>`+ lbl +`</span><span class="cnt">`+ d[countKey] +`</span></div>
      <div class="bar-track"><div class="bar-fill `+ fillClass +`" style="width:`+ pct +`%"></div></div>
    </div>`;
  }).join('');
}

renderBars('ip-bars',   dataIPs,   'ip',   'count', 'fill-ip');
renderBars('cred-bars', dataCreds, 'cred', 'count', 'fill-cred');
renderBars('cmd-bars',  dataCmds,  'cmd',  'count', 'fill-cmd');

// ── Sparkline horaria ───────────────────────────────────────────────────────
(function() {
  const el = document.getElementById('spark-bars');
  if (!el || !dataHoras.length) return;
  // Rellenar las 24 horas
  const byHour = {};
  dataHoras.forEach(d => { byHour[d.hour] = d.count; });
  const max = Math.max(...Object.values(byHour), 1);
  const bars = [];
  for (let h = 0; h < 24; h++) {
    const cnt = byHour[h] || 0;
    const pct = Math.round((cnt / max) * 100);
    bars.push(`<div class="spark-bar" data-hour="${h}" style="height:${Math.max(pct,2)}%;background:${cnt > 0 ? 'var(--accent)' : 'var(--bg3)'}" title="${h}:00 → ${cnt} eventos"></div>`);
  }
  el.innerHTML = bars.join('');
})();
</script>
</body>
</html>
"@

$HtmlContent | Out-File -FilePath $ReporteWeb -Encoding utf8 -NoNewline
Remove-Item $LogPathLocal -ErrorAction SilentlyContinue
Write-OK "Dashboard guardado en: $(Resolve-Path $ReporteWeb)"

# ── 8. Abrir en navegador ─────────────────────────────────────────────────────
if (-not $NoOpen) {
    Write-Step "Abriendo en el navegador..."
    Invoke-Item $ReporteWeb
}

Write-Host "`n✅ Listo. Dashboard generado con éxito.`n" -ForegroundColor Green