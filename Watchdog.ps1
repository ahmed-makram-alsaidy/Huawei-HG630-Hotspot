<#
.SYNOPSIS
    Huawei Hotspot Watchdog - runs every minute (scheduled task, elevated):
      1. Web server not listening on 8630? -> start it
      2. Enforcement engine heartbeat stale (>90s)? -> restart it
      3. First run of each day? -> automatic db.json backup (keeps last 30)
    Writes watchdog_state.json for the admin panel.
#>
$ErrorActionPreference = "SilentlyContinue"
$Root = $PSScriptRoot
$DataDir = "$Root\Huawei_Arabic_System\data"
$StateF = "$DataDir\watchdog_state.json"
$actions = @()

# --- 1) web server ---
$listener = Get-NetTCPConnection -State Listen -LocalPort 8630 -ErrorAction SilentlyContinue
if (-not $listener) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Root\Live_Router_Server.ps1`"" -WindowStyle Hidden
    $actions += "web server started"
}

# --- 2) engine heartbeat ---
$engFile = "$DataDir\engine.json"
$engOk = $false
if (Test-Path $engFile) {
    try {
        $e = Get-Content $engFile -Raw | ConvertFrom-Json
        if ($e.heartbeat) { $engOk = (((Get-Date) - [datetime]$e.heartbeat).TotalSeconds -lt 90) }
    } catch {}
}
if (-not $engOk) {
    $task = Get-ScheduledTask -TaskName "Huawei_Gateway_Engine" -ErrorAction SilentlyContinue
    if ($task) { Start-ScheduledTask -TaskName "Huawei_Gateway_Engine"; $actions += "engine restarted via task" }
    else {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& '$Root\engine\Gateway_Engine.ps1'`"" -WindowStyle Hidden
        $actions += "engine started directly"
    }
}

# --- 3) daily backup ---
$markerF = "$DataDir\.lastBackupDay"
$today = (Get-Date).ToString("yyyy-MM-dd")
$lastDay = if (Test-Path $markerF) { (Get-Content $markerF -Raw).Trim() } else { "" }
if ($lastDay -ne $today -and (Test-Path "$DataDir\db.json")) {
    $bdir = "$DataDir\backups"
    if (-not (Test-Path $bdir)) { New-Item -ItemType Directory -Path $bdir -Force | Out-Null }
    Copy-Item "$DataDir\db.json" "$bdir\db-$today-auto.json" -Force
    Set-Content -Path $markerF -Value $today
    # keep last 30
    Get-ChildItem $bdir -Filter "db-*.json" | Sort-Object Name -Descending | Select-Object -Skip 30 | Remove-Item -Force -ErrorAction SilentlyContinue
    $actions += "daily backup db-$today-auto.json"
}

@{ lastRun = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); engineOk = $engOk; actions = $actions } |
    ConvertTo-Json -Compress | Set-Content -Path $StateF -Encoding UTF8
