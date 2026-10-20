<#
.SYNOPSIS
    Installs/updates the Gateway Enforcement Engine as an elevated auto-start scheduled task.
    Part of the Huawei HG630 Hotspot System installer.
#>
$ErrorActionPreference = "Continue"
$log = "$PSScriptRoot\install_engine_log.txt"
"=== Engine install $(Get-Date) ===" | Out-File $log -Encoding utf8
function Log($m) { $m | Tee-Object -FilePath $log -Append }

# 1) Defender exclusion for the engine folder (WinDivert driver is heuristically flagged)
try {
    $pref = Get-MpPreference
    if (($pref.ExclusionPath) -notcontains "$PSScriptRoot\engine") {
        Add-MpPreference -ExclusionPath "$PSScriptRoot\engine"
        Log "Defender exclusion added for engine folder"
    } else { Log "Defender exclusion already present" }
} catch { Log "Defender exclusion skipped: $($_.Exception.Message)" }

# 2) Stop any running engine instance (elevated can kill elevated)
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -match 'Gateway_Engine' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Log "stopped engine PID $($_.ProcessId)" }

# 3) Register + start the elevated auto-start task
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& '$PSScriptRoot\engine\Gateway_Engine.ps1'`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
    Register-ScheduledTask -TaskName "Huawei_Gateway_Engine" -Action $action -Trigger $trigger -Principal $principal -Description "Hotspot enforcement engine (WinDivert) - elevated auto start" -Force | Out-Null
    Log "scheduled task registered"
    Start-ScheduledTask -TaskName "Huawei_Gateway_Engine"
    Log "task started"
} catch { Log "task registration failed: $($_.Exception.Message)" }

# 4) watchdog task (every minute: auto-restart server/engine + daily backup)
try {
    $wdAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSScriptRoot\Watchdog.ps1`""
    $wdTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    Register-ScheduledTask -TaskName "Huawei_Hotspot_Watchdog" -Action $wdAction -Trigger $wdTrigger -Principal $principal -Description "Hotspot watchdog: auto-restart + daily backup" -Force | Out-Null
    Start-ScheduledTask -TaskName "Huawei_Hotspot_Watchdog"
    Log "watchdog task registered"
} catch { Log "watchdog registration failed: $($_.Exception.Message)" }

Start-Sleep -Seconds 6
$e = Get-Content "$PSScriptRoot\Huawei_Arabic_System\data\engine.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($e -and $e.heartbeat) { Log "engine heartbeat: $($e.heartbeat)" } else { Log "engine NOT running (no heartbeat)" }
Log "=== DONE ==="
