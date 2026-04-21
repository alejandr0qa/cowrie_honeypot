# ==============================================================================
# Script: Analizador-Honeypot.ps1
# Descripción: Extracción de logs de Cowrie y análisis local con TinyLlama
# ==============================================================================

$ContainerName = "cowrie_honeypot"
$LogPathInside = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
$LogPathLocal = ".\temp_cowrie.json"
$OllamaEndpoint = "http://localhost:11434/api/generate"
$ModelName = "tinyllama"

Write-Host "[*] Iniciando proceso de inteligencia de amenazas..." -ForegroundColor Cyan

# 1. Extraer el archivo JSON
Write-Host "[*] Extrayendo logs del contenedor $ContainerName..."
docker cp ${ContainerName}:${LogPathInside} $LogPathLocal

# 2. Leer y filtrar
Write-Host "[*] Filtrando eventos críticos..."
$Logs = Get-Content $LogPathLocal | ConvertFrom-Json
$CriticalEvents = $Logs | Where-Object { 
    $_.eventid -eq 'cowrie.login.success' -or $_.eventid -eq 'cowrie.command.input' 
}

if ($null -eq $CriticalEvents -or $CriticalEvents.Count -eq 0) {
    Write-Host "[+] No se registraron intrusiones exitosas en este periodo." -ForegroundColor Green
    Remove-Item $LogPathLocal -ErrorAction SilentlyContinue
    exit
}

# 3. Formatear para el LLM
$ReportData = $CriticalEvents | ForEach-Object {
    $Detalle = if ($_.eventid -eq 'cowrie.login.success') { "Credenciales: $($_.username) / $($_.password)" } else { "Comando: $($_.input)" }
    "IP: $($_.src_ip) | Evento: $($_.eventid) | $Detalle"
} | Out-String

# 4. Construir petición a Ollama
Write-Host "[*] Enviando datos a Ollama ($ModelName) para análisis..."
$Prompt = @"
Eres un analista de ciberseguridad. Revisa el siguiente registro de eventos de un honeypot e identifica de forma breve y profesional:
1. Cuántas IPs distintas atacaron.
2. Qué credenciales usaron.
3. Qué comandos ejecutaron y cuál era su objetivo probable.

ESTA ES UNA REGLA ESTRICTA: DEBES ESCRIBIR TU RESPUESTA ÚNICAMENTE EN IDIOMA ESPAÑOL.

Registros:
$ReportData
"@

$Body = @{
    model = $ModelName
    prompt = $Prompt
    stream = $false
} | ConvertTo-Json

# 5. Enviar e imprimir
try {
    $Response = Invoke-RestMethod -Uri $OllamaEndpoint -Method Post -Body $Body -ContentType "application/json"
    
    Write-Host "`n================ REPORTE EJECUTIVO DE SEGURIDAD ================" -ForegroundColor Yellow
    Write-Host $Response.response
    Write-Host "================================================================`n" -ForegroundColor Yellow

} catch {
    Write-Host "[!] Error al conectar con Ollama. Asegúrate de que el servicio esté corriendo (ollama serve o en segundo plano)." -ForegroundColor Red
}

Remove-Item $LogPathLocal -ErrorAction SilentlyContinue
Write-Host "[*] Proceso finalizado." -ForegroundColor Cyan
