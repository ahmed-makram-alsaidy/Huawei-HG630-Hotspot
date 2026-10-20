<#
.SYNOPSIS
    Self-update: downloads a release ZIP from the project's GitHub, preserves user data
    (Huawei_Arabic_System\data), replaces all other files, then restarts the web server
    and the enforcement engine. Launched by the admin panel (/api/update-apply).
#>
param([Parameter(Mandatory=$true)][string]$ZipUrl)
$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot
$log = "$Root\update_log.txt"
"=== update start $(Get-Date) ===" | Out-File $log -Encoding utf8
function Log($m) { $m | Tee-Object -FilePath $log -Append }

try {
    $tmp = Join-Path $env:TEMP ("hgupdate-" + [guid]::NewGuid().ToString("N").Substring(0,8))
    $zip = "$tmp\update.zip"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Log "downloading $ZipUrl"
    Invoke-WebRequest -Uri $ZipUrl -OutFile $zip -UseBasicParsing -TimeoutSec 120
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $staging = Get-ChildItem $tmp -Directory | Select-Object -First 1
    Log "staging: $($staging.FullName)"

    # stop engine + web server
    Get-ScheduledTask -TaskName "Huawei_Gateway_Engine" -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
        Where-Object { $_.CommandLine -match 'Gateway_Engine|Live_Router_Server' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Log "services stopped"

    # copy everything except user data
    $dataDirName = "Huawei_Arabic_System\data"
    Get-ChildItem $staging.FullName -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($staging.FullName.Length + 1)
        if ($rel -like "$dataDirName*") { return }
        if ($rel -like "*.log" -or $rel -like "*_log.txt") { return }
        $dest = Join-Path $Root $rel
        $destDir = Split-Path $dest -Parent
        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Copy-Item $_.FullName $dest -Force
    }
    Log "files replaced"

    # restart services
    Start-ScheduledTask -TaskName "Huawei_Gateway_Engine" -ErrorAction SilentlyContinue
    if (-not (Get-ScheduledTask -TaskName "Huawei_Gateway_Engine" -ErrorAction SilentlyContinue)) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& '$Root\engine\Gateway_Engine.ps1'`"" -WindowStyle Hidden
    }
    Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Root\Live_Router_Server.ps1`"" -WindowStyle Hidden
    Log "services restarted - update complete"
} catch {
    Log "UPDATE FAILED: $($_.Exception.Message)"
    # best effort: bring the web server back
    Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Root\Live_Router_Server.ps1`"" -WindowStyle Hidden
}
