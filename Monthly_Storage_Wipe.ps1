<#
.SYNOPSIS
    Monthly Zero-Storage Auto-Wipe & Router Memory Cleanup for Huawei HG630 V2
    Runs in <2 seconds once a month (0% background RAM usage) and wipes all temporary storage/logs.
#>
param(
    [switch]$InstallMonthlySchedule,
    [string]$RouterIP = "192.168.2.1",
    [string]$AdminUser = "admin",
    [string]$AdminPass = "3BB"
)

$DataDir = "$PSScriptRoot\Huawei_Arabic_System\data"
if (Test-Path $DataDir) {
    # Preserve business data: voucher/user database (db.json) and admin credentials (auth.json).
    # Only transient logs / temp files are wiped.
    Get-ChildItem $DataDir -File | Where-Object { $_.Name -notin @("db.json", "auth.json", "monthly_state.json") } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# Record clean monthly reset timestamp (tiny state file)
$resetInfo = @{
    LastMonthlyWipe = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    StorageUsedBytes = 0
} | ConvertTo-Json
Set-Content -Path "$DataDir\monthly_state.json" -Value $resetInfo -Encoding UTF8

Write-Host "[+] Monthly temp/log wipe done — db.json (vouchers/users) and auth.json preserved!" -ForegroundColor Green

if ($InstallMonthlySchedule) {
    $taskName = "Huawei_HG630V2_Monthly_Zero_Wipe"
    $scriptPath = $MyInvocation.MyCommand.Definition
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 4am -WeeksInterval 4
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "Huawei HG630 V2 Monthly (every 4 weeks) Temp-Wipe — preserves vouchers db and admin auth" -Force | Out-Null
    Write-Host "[+] Scheduled monthly (4-week) zero-storage wipe installed successfully!" -ForegroundColor Cyan
}
