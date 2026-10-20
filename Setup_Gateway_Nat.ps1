<#
.SYNOPSIS
    Gateway NAT setup v2 (run as Administrator):
    Tries WinNAT (New-NetNat). If unavailable ("Invalid class" on some Win11 builds),
    falls back to a properly configured Internet Connection Sharing (ICS):
      - ICS scope forced to 192.168.2.1 via registry BEFORE enabling (no 192.168.137.1 override)
      - Wi-Fi = public (internet source), Ethernet = private (Huawei hotspot LAN)
      - ICS then provides DHCP + DNS proxy + NAT for the 192.168.2.0/24 hotspot LAN
    Results: setup_nat_log.txt
#>
$ErrorActionPreference = "Continue"
$log = Join-Path $PSScriptRoot "setup_nat_log.txt"
"=== Gateway NAT setup v2 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $log -Encoding UTF8
function Log([string]$m) { $m | Tee-Object -FilePath $log -Append }

Log "[1] Trying WinNAT (New-NetNat)..."
$natOk = $false
try {
    Set-Service RemoteAccess -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service RemoteAccess -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    if (-not (Get-NetNat -ErrorAction SilentlyContinue)) {
        $nat = New-NetNat -Name "HuaweiHotspotNat" -InternalIPInterfaceAddressPrefix "192.168.2.0/24" -ErrorAction Stop
    }
    $natOk = $true
    $n = Get-NetNat -ErrorAction SilentlyContinue
    Log "    OK -> $($n.Name) / $($n.InternalIPInterfaceAddressPrefix)"
    Log "    ROUTER DHCP must stay ENABLED (it serves 192.168.2.x with public DNS)."
} catch {
    Log "    WinNAT failed: $($_.Exception.Message)"
}

if (-not $natOk) {
    Log "[2] Falling back to ICS (Internet Connection Sharing), scope 192.168.2.1..."
    try {
        # Scope must be set BEFORE enabling sharing, otherwise ICS resets the adapter to 192.168.137.1
        $p = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
        Set-ItemProperty $p -Name ScopeAddress          -Value "192.168.2.1" -Type String
        Set-ItemProperty $p -Name ScopeAddressBackup    -Value "192.168.2.1" -Type String
        Set-ItemProperty $p -Name StandaloneDhcpAddress -Value "192.168.2.1" -Type String
        Log "    registry scope forced to 192.168.2.1"

        Start-Service SharedAccess -ErrorAction SilentlyContinue
        $ics = New-Object -ComObject HNetCfg.HNetShare
        foreach ($c in $ics.EnumEveryConnection()) {
            $props = $ics.NetConnectionProps($c)
            $cfg = $ics.INetSharingConfigurationForINetConnection($c)
            if ($props.Name -eq "Wi-Fi")    { $null = $cfg.EnableSharing(0); Log "    sharing enabled PUBLIC on: $($props.Name)" }
            if ($props.Name -eq "Ethernet") { $null = $cfg.EnableSharing(1); Log "    sharing enabled PRIVATE on: $($props.Name)" }
        }
        Start-Sleep -Seconds 3
        Log "    ROUTER DHCP must be DISABLED in the new config (ICS serves DHCP)."
    } catch { Log "    ICS ERR: $($_.Exception.Message)" }
}

Log "[3] Verification:"
$ips = (Get-NetIPAddress -InterfaceIndex 8 -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ", "
Log "    Ethernet IPv4: $ips"
$dhcp67 = Get-NetUDPEndpoint -LocalPort 67 -ErrorAction SilentlyContinue
Log "    UDP-67 (DHCP) listeners: $(@($dhcp67).Count)"
$dns53 = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
Log "    UDP-53 (DNS proxy) listeners: $(@($dns53).Count)"
$sa = Get-Service SharedAccess -ErrorAction SilentlyContinue
Log "    SharedAccess: $($sa.Status) / $($raStatus = ''; $sa.StartType)"
if (-not $natOk) {
    try {
        $ics2 = New-Object -ComObject HNetCfg.HNetShare
        foreach ($c in $ics2.EnumEveryConnection()) {
            $props = $ics2.NetConnectionProps($c)
            $cfg2 = $ics2.INetSharingConfigurationForINetConnection($c)
            Log "    $($props.Name): SharingEnabled=$($cfg2.SharingEnabled) SharingType=$($cfg2.SharingConnectionType)"
        }
    } catch {}
}
Log "=== DONE ==="
