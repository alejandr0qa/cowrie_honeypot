# ==============================================================================
# Script: Analizador-Honeypot.ps1
# Descripción: Extracción de logs de Cowrie y análisis con IA via Ollama
# Versión: 2.0
#
# USO:
#   .\Analizador-Honeypot.ps1
#   .\Analizador-Honeypot.ps1 -ModelName "llama3" -MaxEvents 100
#   .\Analizador-Honeypot.ps1 -Demo          # Usa datos de muestra sin Docker
#   .\Analizador-Honeypot.ps1 -OutputFile    # Guarda reporte en archivo .txt
#   .\Analizador-Honeypot.ps1 -NoAI          # Solo muestra estadísticas, sin Ollama
# ==============================================================================

param(
    [string]$ContainerName  = "cowrie_honeypot",
    [string]$ModelName      = "tinyllama",
    [string]$OllamaEndpoint = "http://localhost:11434/api/generate",
    [int]$MaxEvents         = 50,
    [switch]$Demo,      # Usar datos de prueba locales
    [switch]$OutputFile, # Guardar reporte en archivo
    [switch]$NoAI        # Solo estadísticas, sin análisis LLM
)

$ErrorActionPreference = "Stop"
$LogPathInside  = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
$LogPathLocal   = Join-Path $env:TEMP "cowrie_temp_$(Get-Random).json"
$SampleDataPath = Join-Path $PSScriptRoot "..\sample-data\cowrie_sample.json"

# ─── Funciones ─────────────────────────────────────────────────────────────────
function Write-Section($msg) {
    Write-Host "`n$("─" * 60)" -ForegroundColor DarkGray
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "$("─" * 60)" -ForegroundColor DarkGray
}

function Write-Ok($msg)   { Write-Host "[✓] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor White }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[✗] $msg" -ForegroundColor Red }

function Test-DockerRunning {
    try {
        $null = docker version 2>&1
        return $true
    } catch {
        return $false
    }
}

function Test-ContainerRunning($Name) {
    $status = docker inspect --format "{{.State.Status}}" $Name 2>$null
    return $status -eq "running"
}

# ─── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║         🛡  COWRIE HONEYPOT — ANALIZADOR DE AMENAZAS         ║
║                      Versión 2.0                             ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ─── 1. Cargar logs ────────────────────────────────────────────────────────────
Write-Section "PASO 1: Obtención de Logs"

$JsonLines = @()

if ($Demo) {
    Write-Warn "Modo DEMO activo — usando datos de muestra."
    if (-not (Test-Path $SampleDataPath)) {
        Write-Fail "No se encontró el archivo de muestra en: $SampleDataPath"
        exit 1
    }
    $JsonLines = Get-Content $SampleDataPath
    Write-Ok "Datos de muestra cargados."
} else {
    # Verificar Docker
    if (-not (Test-DockerRunning)) {
        Write-Fail "Docker no está disponible en este sistema. Instala Docker Desktop o usa -Demo."
        exit 1
    }

    if (-not (Test-ContainerRunning $ContainerName)) {
        Write-Warn "El contenedor '$ContainerName' no está corriendo."
        Write-Info "Intentando con logs locales en ./cowrie-var/..."

        $LocalLogPath = Join-Path $PSScriptRoot "..\cowrie-var\log\cowrie\cowrie.json"
        if (Test-Path $LocalLogPath) {
            $JsonLines = Get-Content $LocalLogPath
            Write-Ok "Logs locales cargados desde: $LocalLogPath"
        } else {
            Write-Fail "No se encontraron logs. Sube el honeypot con: docker compose up -d"
            exit 1
        }
    } else {
        Write-Info "Extrayendo logs del contenedor '$ContainerName'..."
        docker cp "${ContainerName}:${LogPathInside}" $LogPathLocal 2>$null
        if (-not (Test-Path $LogPathLocal)) {
            Write-Fail "No se pudo copiar el log. ¿El honeypot ha captado eventos?"
            exit 1
        }
        $JsonLines = Get-Content $LogPathLocal
        Remove-Item $LogPathLocal -ErrorAction SilentlyContinue
        Write-Ok "Logs extraídos del contenedor."
    }
}

# ─── 2. Parsear y filtrar ──────────────────────────────────────────────────────
Write-Section "PASO 2: Análisis de Estadísticas"

$Logs = $JsonLines | Where-Object { $_.Trim() -ne "" } | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $_ -ne $null }

if ($Logs.Count -eq 0) {
    Write-Warn "No se encontraron eventos en el log."
    exit 0
}

# Estadísticas
$UniqueIPs    = ($Logs | Where-Object { $_.src_ip } | Select-Object -ExpandProperty src_ip | Sort-Object -Unique)
$TotalConnects = ($Logs | Where-Object { $_.eventid -eq 'cowrie.session.connect' }).Count
$LoginsOK     = ($Logs | Where-Object { $_.eventid -eq 'cowrie.login.success' })
$LoginsFail   = ($Logs | Where-Object { $_.eventid -eq 'cowrie.login.failed' }).Count
$Commands     = ($Logs | Where-Object { $_.eventid -eq 'cowrie.command.input' })

Write-Host ""
Write-Host "  📊 Resumen del Periodo:" -ForegroundColor White
Write-Host "     Eventos totales      : $($Logs.Count)" -ForegroundColor Gray
Write-Host "     IPs únicas           : $($UniqueIPs.Count)" -ForegroundColor Cyan
Write-Host "     Conexiones SSH       : $TotalConnects" -ForegroundColor Gray
Write-Host "     Logins EXITOSOS      : $($LoginsOK.Count)" -ForegroundColor Red
Write-Host "     Logins fallidos      : $LoginsFail" -ForegroundColor Yellow
Write-Host "     Comandos capturados  : $($Commands.Count)" -ForegroundColor Green
Write-Host ""

if ($LoginsOK.Count -gt 0) {
    Write-Host "  🔴 Credenciales que funcionaron:" -ForegroundColor Red
    $LoginsOK | Select-Object -First 10 | ForEach-Object {
        Write-Host "     $($_.src_ip) → $($_.username) / $($_.password)" -ForegroundColor DarkRed
    }
}

if ($Commands.Count -gt 0) {
    Write-Host ""
    Write-Host "  >_ Últimos comandos ejecutados:" -ForegroundColor Green
    $Commands | Select-Object -Last 10 | ForEach-Object {
        Write-Host "     $($_.src_ip) → $($_.input)" -ForegroundColor DarkGreen
    }
}

# ─── 3. Análisis con IA ────────────────────────────────────────────────────────
if (-not $NoAI) {
    Write-Section "PASO 3: Análisis de Inteligencia de Amenazas (IA)"
    Write-Info "Modelo: $ModelName | Endpoint: $OllamaEndpoint"

    $CriticalEvents = @($LoginsOK) + @(($Logs | Where-Object { $_.eventid -eq 'cowrie.login.failed' } | Select-Object -First 20)) + @($Commands)
    $CriticalEvents = $CriticalEvents | Select-Object -First $MaxEvents

    if ($CriticalEvents.Count -eq 0) {
        Write-Warn "No hay eventos críticos para analizar."
    } else {
        $ReportLines = $CriticalEvents | ForEach-Object {
            $ts = ($_.timestamp -replace "T"," " -replace "Z","").Substring(0, [Math]::Min(19, $_.timestamp.Length))
            switch ($_.eventid) {
                'cowrie.login.success' { "[$ts] LOGIN EXITOSO | IP: $($_.src_ip) | $($_.username)/$($_.password)" }
                'cowrie.login.failed'  { "[$ts] LOGIN FALLIDO | IP: $($_.src_ip) | $($_.username)/$($_.password)" }
                'cowrie.command.input' { "[$ts] COMANDO       | IP: $($_.src_ip) | $($_.input)" }
            }
        }
        $ReportData = $ReportLines -join "`n"

        $Prompt = @"
Eres un analista experto en ciberseguridad. Analiza estos eventos de un honeypot SSH y proporciona:
1. Resumen ejecutivo: IPs que atacaron y nivel de riesgo general.
2. Credenciales utilizadas: ¿ataque de diccionario o dirigido?
3. Comandos ejecutados: objetivo probable del atacante.
4. Indicadores de Compromiso (IoC).
5. Recomendaciones inmediatas.

REGLA ESTRICTA: Responde ÚNICAMENTE en español. Sé conciso y profesional.

REGISTROS:
$ReportData
"@

        $Body = @{
            model   = $ModelName
            prompt  = $Prompt
            stream  = $false
            options = @{ temperature = 0.3; num_predict = 800 }
        } | ConvertTo-Json -Depth 3

        try {
            Write-Info "Enviando a Ollama, espera (máx. 2 min)..."
            $Response = Invoke-RestMethod -Uri $OllamaEndpoint -Method Post -Body $Body -ContentType "application/json" -TimeoutSec 120

            $Report = $Response.response
            Write-Host "`n$("═" * 62)" -ForegroundColor Yellow
            Write-Host "  📋  REPORTE EJECUTIVO DE SEGURIDAD — $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Yellow
            Write-Host "$("═" * 62)" -ForegroundColor Yellow
            Write-Host $Report
            Write-Host "$("═" * 62)`n" -ForegroundColor Yellow

            if ($OutputFile) {
                $FileName = "reporte_honeypot_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $FilePath = Join-Path $PSScriptRoot $FileName
                $FullContent = @"
═══════════════════════════════════════════════
REPORTE EJECUTIVO DE SEGURIDAD — COWRIE HONEYPOT
Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Modelo IA: $ModelName
Contenedor: $ContainerName
═══════════════════════════════════════════════

$Report

═══════════════════════════════════════════════
ESTADÍSTICAS CRUDAS
═══════════════════════════════════════════════
IPs únicas: $($UniqueIPs.Count)
Conexiones: $TotalConnects
Logins exitosos: $($LoginsOK.Count)
Logins fallidos: $LoginsFail
Comandos: $($Commands.Count)
"@
                $FullContent | Out-File -FilePath $FilePath -Encoding UTF8
                Write-Ok "Reporte guardado en: $FilePath"
            }

        } catch [System.Net.WebException] {
            Write-Fail "No se pudo conectar con Ollama."
            Write-Info "Soluciones:"
            Write-Info "  1. Ejecutar: ollama serve"
            Write-Info "  2. O instalar Ollama desde: https://ollama.ai"
            Write-Info "  3. Verificar que el modelo esté descargado: ollama pull $ModelName"
            Write-Info "  4. Usar -NoAI para ver solo estadísticas"
        } catch {
            Write-Fail "Error inesperado: $_"
        }
    }
} else {
    Write-Info "Análisis IA omitido (-NoAI). Estadísticas mostradas arriba."
}

Write-Ok "Proceso finalizado.`n"
