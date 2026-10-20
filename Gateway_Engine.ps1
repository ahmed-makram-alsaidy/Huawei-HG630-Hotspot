<#
.SYNOPSIS
    Huawei HG630 Hotspot — Gateway Enforcement Engine (WinDivert-based)
    Runs ELEVATED. Captures all guest traffic (192.168.2.2-253) at the network layer and provides:
      - Per-device byte accounting (upload/download)        -> quota tracking in db.json + history
      - Hard cutoff for expired/blacklisted/cut devices     -> packets are dropped, not re-injected
      - Captive DNS for unauthenticated guests              -> all A queries answered with 192.168.2.1
                                                               so phones auto-open the portal
      - Per-device speed limits                             -> token-bucket throttle (down/up)
      - Night/study schedule + daily quota                  -> time-based gating, midnight reset
      - Device protection                                   -> drops guest traffic to router (.254)
                                                               and to the home LAN (192.168.1.0/24)
    State files (shared with Live_Router_Server.ps1):
      data\engine.json     - live sessions/blacklist/schedule/heartbeat (engine writes)
      data\engine_cmd.json - command queue from the web server/portal (web writes, engine consumes)
      data\db.json         - vouchers/users/packages (usage written back periodically)
      data\history\YYYY-MM-DD.json - per-day usage for reports
#>
param(
    [switch]$TestMode
)
$ErrorActionPreference = "Continue"
$Root      = Split-Path $PSScriptRoot -Parent
$DataDir   = Join-Path $Root "Huawei_Arabic_System\data"
$EngineF   = Join-Path $DataDir "engine.json"
$CmdF      = Join-Path $DataDir "engine_cmd.json"
$DbF       = Join-Path $DataDir "db.json"
$HistoryDir= Join-Path $DataDir "history"
$LogFile   = Join-Path $DataDir "engine_log.txt"
$WD        = Join-Path $PSScriptRoot "wd"
$GUEST_LO  = "192.168.2.2";  $GUEST_HI = "192.168.2.253"
$ROUTER_IP = "192.168.2.254"
$ETH_IFIDX = 8   # Ethernet ifIndex (guest side)

function Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
}

# ---------------- WinDivert P/Invoke ----------------
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WD {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetDllDirectory(string path);

    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern bool WinDivertRecv(IntPtr handle, byte[] pPacket, uint packetLen, out uint pRecvLen, byte[] pAddr);

    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern bool WinDivertSend(IntPtr handle, byte[] pPacket, uint packetLen, out uint pSendLen, byte[] pAddr);

    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern bool WinDivertClose(IntPtr handle);
}
'@
$null = [WD]::SetDllDirectory($WD)
$null = [WD]::LoadLibrary((Join-Path $WD "WinDivert.dll"))

# WINDIVERT_ADDRESS (NETWORK layer) = 24 bytes: Timestamp(8) + Bitfields(4) + Reserved(4) + IfIdx(4) + SubIfIdx(4)
$ADDR_LEN = 24
$FLAG_OUTBOUND = 0x00020000  # bit 17
$FLAG_SNIFFED  = 0x00010000  # bit 16
$FLAG_IPCSUM   = 0x00200000  # bit 21
$FLAG_TCPCSUM  = 0x00400000  # bit 22
$FLAG_UDPCSUM  = 0x00800000  # bit 23
$LAYER_NETWORK = 0   # WINDIVERT_LAYER_NETWORK (1 = NETWORK_FORWARD - not used by host traffic)

# ---------------- Shared state ----------------
$S = [hashtable]::Synchronized(@{})
$S.Sessions  = @{}      # mac -> session hashtable (also ip -> mac in $S.IpMap)
$S.IpMap     = @{}      # ip  -> mac
$S.Blacklist = @()      # macs
$S.CutIps    = @()      # ips manually cut by admin
$S.Schedule  = @{ enabled=$false; start="00:00"; end="08:00"; bypassMacs=@(); activeNow=$false }
$S.CmdId     = 0
$S.Stats     = @{ startedAt=(Get-Date).ToString("s"); packets=0; dropped=0; dnsAnswered=0 }
$S.Pending   = [hashtable]::Synchronized(@{})  # mac -> ArrayList of @{pkt;addr;ts;bytes;dir}
$S.Day       = (Get-Date).ToString("yyyy-MM-dd")
$S.History   = @{}

function IPToUInt([string]$ip) {
    $o = [int[]]($ip.Split('.')); return [uint32]($o[0]*16777216 + $o[1]*65536 + $o[2]*256 + $o[3])
}
$LO_U = IPToUInt $GUEST_LO; $HI_U = IPToUInt $GUEST_HI; $ROUTER_U = IPToUInt $ROUTER_IP
$HOME_U = IPToUInt "192.168.1.0"; $HOME_MASK = [uint32]4294967040  # /24

function IsGuestIp([string]$ip) { try { $u = IPToUInt $ip; return ($u -ge $LO_U -and $u -le $HI_U) } catch { return $false } }

function Get-SessionByIp([string]$ip) {
    $mac = $S.IpMap[$ip]
    if ($mac -and $S.Sessions.ContainsKey($mac)) { return $S.Sessions[$mac] }
    return $null
}
function Get-OrphanSession([string]$ip) {
    # session created before MAC known: keyed as "ip:<ip>"
    $k = "ip:$ip"
    if ($S.Sessions.ContainsKey($k)) { return $S.Sessions[$k] }
    return $null
}
function Get-EffectiveSession([string]$ip) {
    $s = Get-SessionByIp $ip
    if ($s) { return $s }
    return Get-OrphanSession $ip
}

function Schedule-ActiveNow {
    if (-not $S.Schedule.enabled) { return $false }
    $now = Get-Date; $t = $now.ToString("HH:mm")
    $a = $S.Schedule.start; $b = $S.Schedule.end
    if ($a -eq $b) { return $false }
    if ([datetime]::ParseExact($a,"HH:mm",$null) -le [datetime]::ParseExact($b,"HH:mm",$null)) {
        return ($t -ge $a -and $t -lt $b)
    } else { return ($t -ge $a -or $t -lt $b) }   # overnight window
}

# ---------------- Control thread (runspace): cmd processing, HostInfo polling, state persistence ----------------
$ctrl = [powershell]::Create().AddScript({
    param($Root, $DataDir, $EngineF, $CmdF, $DbF, $HistoryDir, $S, $ROUTER_IP)
    function LogC([string]$m) { try { Add-Content -Path (Join-Path $DataDir "engine_log.txt") -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  [ctrl] $m" -Encoding UTF8 } catch {} }
    $lastHistory = 0; $lastHostPoll = 0; $lastDbWrite = 0; $lastEngineWrite = 0
    while ($true) {
        try {
            Start-Sleep -Milliseconds 1000
            $now = Get-Date

            # ---- consume command queue ----
            if (Test-Path $CmdF) {
                $cmd = Get-Content $CmdF -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($cmd.lastId -gt $S.CmdId) {
                    foreach ($c in $cmd.cmds) {
                        if ($c.id -le $S.CmdId) { continue }
                        switch ($c.type) {
                            "authorize" {
                                $mac = $c.mac
                                if (-not $mac -or $mac -eq "") { $mac = "ip:$($c.ip)" }
                                $sess = $null
                                foreach ($k in @($S.Sessions.Keys)) { if ($S.Sessions[$k].mac -eq $mac) { $sess = $S.Sessions[$k]; break } }
                                if (-not $sess) {
                                    $sess = @{ mac=$mac; ip=$c.ip; host=""; auth=$false; usedBytes=0; dailyBytes=0; pending=0 }
                                    $S.Sessions[$mac] = $sess
                                }
                                $sess.ip = $c.ip; $S.IpMap[$c.ip] = $mac
                                $sess.auth = $true; $sess.reason = ""
                                $sess.name = $c.name; $sess.code = $c.code; $sess.userKey = $c.userKey
                                $sess.package = $c.pkg.name; $sess.quotaGB = $c.pkg.quotaGB; $sess.dailyGB = $c.pkg.dailyGB
                                $sess.speedDownKbps = $c.pkg.speedDownKbps; $sess.speedUpKbps = $c.pkg.speedUpKbps
                                $sess.expiresAt = $c.expiresAt; $sess.activatedAt = (Get-Date).ToString("s")
                                $sess.cut = $false
                                LogC "authorized $($c.ip) ($mac) code=$($c.code) pkg=$($c.pkg.name)"
                            }
                            "cut"   { $S.CutIps = @($S.CutIps + $c.ip | Select-Object -Unique); LogC "cut $($c.ip)" }
                            "release" { $S.CutIps = @($S.CutIps | Where-Object { $_ -ne $c.ip }); LogC "release $($c.ip)" }
                            "blacklist" { if ($c.mac -and $S.Blacklist -notcontains $c.mac) { $S.Blacklist += $c.mac; LogC "blacklist $($c.mac)" } }
                            "unblacklist" { $S.Blacklist = @($S.Blacklist | Where-Object { $_ -ne $c.mac }); LogC "unblacklist $($c.mac)" }
                            "schedule" {
                                $S.Schedule.enabled = [bool]$c.payload.enabled
                                $S.Schedule.start = $c.payload.start
                                $S.Schedule.end = $c.payload.end
                                $S.Schedule.bypassMacs = @($c.payload.bypassMacs)
                                LogC "schedule: enabled=$($c.payload.enabled) $($c.payload.start)-$($c.payload.end)"
                            }
                            "reload" { LogC "reload requested" }
                        }
                        $S.CmdId = $c.id
                    }
                }
            }

            # ---- schedule state ----
            $a = $S.Schedule.start; $b = $S.Schedule.end; $active = $false
            if ($S.Schedule.enabled -and $a -ne $b) {
                $t = (Get-Date).ToString("HH:mm")
                $p = { param($x) [datetime]::ParseExact($x,"HH:mm",$null) }
                if (& $p $a -le (& $p $b)) { $active = ($t -ge $a -and $t -lt $b) } else { $active = ($t -ge $a -or $t -lt $b) }
            }
            $S.Schedule.activeNow = $active

            # ---- daily rollover ----
            $today = (Get-Date).ToString("yyyy-MM-dd")
            if ($today -ne $S.Day) {
                $S.Day = $today; $S.History = @{}
                foreach ($k in @($S.Sessions.Keys)) { $S.Sessions[$k].dailyBytes = 0 }
                LogC "daily rollover -> $today"
            }

            # ---- poll router HostInfo for IP<->MAC map ----
            if (($now.Ticks - $lastHostPoll) -gt 20000000) {   # 2s
                $lastHostPoll = $now.Ticks
                try {
                    $raw = (Invoke-WebRequest -Uri "http://$ROUTER_IP/api/system/HostInfo" -UseBasicParsing -TimeoutSec 3).Content
                    $clean = $raw.Trim() -replace '^while\(1\);\s*/\*','' -replace '\*/\s*$',''
                    $hosts = $clean | ConvertFrom-Json
                    foreach ($h in $hosts) {
                        $ip = $h.IPAddress; $mac = ($h.MACAddress + "").ToUpper()
                        if ($ip -and $mac -and $mac -ne "00:00:00:00:00:00") {
                            if ($S.IpMap.ContainsKey($ip) -and $S.IpMap[$ip] -ne $mac) {
                                $old = $S.IpMap[$ip]
                                if ($S.Sessions.ContainsKey($old)) { $S.Sessions.Remove($old) }
                            }
                            $S.IpMap[$ip] = $mac
                            # merge orphan session (authorized before MAC known) into the mac-keyed session
                            $ok = "ip:$ip"
                            if ($S.Sessions.ContainsKey($ok)) {
                                $orphan = $S.Sessions[$ok]; $S.Sessions.Remove($ok)
                                $existing = $null
                                foreach ($k in @($S.Sessions.Keys)) { if ($S.Sessions[$k].mac -eq $mac) { $existing = $S.Sessions[$k]; break } }
                                if ($existing) {
                                    $existing.usedBytes += $orphan.usedBytes; $existing.dailyBytes += $orphan.dailyBytes
                                    if ($orphan.auth) { $existing.auth = $true; $existing.reason=""; $existing.name=$orphan.name; $existing.code=$orphan.code; $existing.package=$orphan.package; $existing.quotaGB=$orphan.quotaGB; $existing.dailyGB=$orphan.dailyGB; $existing.speedDownKbps=$orphan.speedDownKbps; $existing.speedUpKbps=$orphan.speedUpKbps; $existing.expiresAt=$orphan.expiresAt; $existing.userKey=$orphan.userKey }
                                } else { $orphan.mac = $mac; $S.Sessions[$mac] = $orphan }
                            }
                            if ($S.Sessions.ContainsKey($mac)) { $S.Sessions[$mac].ip = $ip; $S.Sessions[$mac].host = $h.HostName }
                        }
                    }
                } catch {}
            }

            # ---- activity events (new devices, quota/expiry cutoffs) ----
            try {
                $actF = Join-Path $DataDir "activity_engine.json"
                $alist = @()
                if (Test-Path $actF) { try { $alist = @(([System.IO.File]::ReadAllText($actF) | ConvertFrom-Json)) } catch {} }
                $changed = $false
                foreach ($k in @($S.Sessions.Keys)) {
                    $s2 = $S.Sessions[$k]
                    if (-not $s2.notified) {
                        $s2.notified = $true; $changed = $true
                        $alist += @{ ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); kind = "device"; text = "جهاز جديد ظهر على الشبكة: $($s2.ip)" }
                    }
                    if (($s2.reason -eq "quota" -or $s2.reason -eq "expired" -or $s2.reason -eq "daily") -and -not $s2.warned) {
                        $s2.warned = $true; $changed = $true
                        $alist += @{ ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); kind = "cutoff"; text = "قُطع الاتصال ($($s2.reason)): $($s2.name) [$($s2.ip)]" }
                    }
                }
                if ($changed) {
                    if ($alist.Count -gt 50) { $alist = $alist[($alist.Count - 50)..($alist.Count - 1)] }
                    [System.IO.File]::WriteAllText($actF, ($alist | ConvertTo-Json -Depth 5 -Compress))
                }
            } catch {}

            # ---- persist engine.json (heartbeat) ----
            if (($now.Ticks - $lastEngineWrite) -gt 30000000) {  # 3s
                $lastEngineWrite = $now.Ticks
                $sessArr = @()
                foreach ($k in @($S.Sessions.Keys)) {
                    $s2 = $S.Sessions[$k]
                    $sessArr += [ordered]@{
                        mac=$s2.mac; ip=$s2.ip; host=$s2.host; name=$s2.name; code=$s2.code
                        auth=[bool]$s2.auth; reason=$s2.reason; package=$s2.package
                        usedMB=[math]::Round($s2.usedBytes/1MB,2); dailyMB=[math]::Round($s2.dailyBytes/1MB,2)
                        quotaGB=$s2.quotaGB; dailyGB=$s2.dailyGB; speedDownKbps=$s2.speedDownKbps; speedUpKbps=$s2.speedUpKbps
                        expiresAt=$s2.expiresAt; cut=($S.CutIps -contains $s2.ip)
                    }
                }
                $obj = [ordered]@{
                    heartbeat = (Get-Date).ToString("s")
                    stats = $S.Stats
                    schedule = $S.Schedule
                    blacklist = $S.Blacklist
                    cutIps = $S.CutIps
                    sessions = $sessArr
                }
                [System.IO.File]::WriteAllText($EngineF, ($obj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
            }

            # ---- write usage back to db.json (vouchers/users) + history ----
            if (($now.Ticks - $lastDbWrite) -gt 60000000) {   # 60s
                $lastDbWrite = $now.Ticks
                try {
                    if (Test-Path $DbF) {
                        $db = [System.IO.File]::ReadAllText($DbF) | ConvertFrom-Json
                        $dirty = $false
                        foreach ($v in $db.vouchers) {
                            foreach ($k in @($S.Sessions.Keys)) {
                                $s2 = $S.Sessions[$k]
                                if ($s2.userKey -eq "voucher:$($v.code)") {
                                    $mb = [math]::Round($s2.usedBytes/1MB,1)
                                    if ($v.usedMB -ne $mb) { $v.usedMB = $mb; $dirty = $true }
                                }
                            }
                        }
                        foreach ($u in $db.users) {
                            foreach ($k in @($S.Sessions.Keys)) {
                                $s2 = $S.Sessions[$k]
                                if ($s2.userKey -eq "user:$($u.username)") {
                                    $mb = [math]::Round($s2.usedBytes/1MB,1)
                                    if ($u.usedMB -ne $mb) { $u.usedMB = $mb; $dirty = $true }
                                }
                            }
                        }
                        if ($dirty) { [System.IO.File]::WriteAllText($DbF, ($db | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false))) }
                    }
                } catch { LogC "db write err: $($_.Exception.Message)" }

                # history
                try {
                    if (-not (Test-Path $HistoryDir)) { New-Item -ItemType Directory -Path $HistoryDir -Force | Out-Null }
                    $hf = Join-Path $HistoryDir "$($S.Day).json"
                    $dayHist = @{}
                    if (Test-Path $hf) { try { $dayHist = (Get-Content $hf -Raw | ConvertFrom-Json) } catch {} }
                    $hs = @()
                    foreach ($k in @($S.Sessions.Keys)) {
                        $s2 = $S.Sessions[$k]
                        if ($s2.usedBytes -gt 0) {
                            $hs += [ordered]@{ mac=$s2.mac; ip=$s2.ip; name=$s2.name; code=$s2.code; package=$s2.package; usedMB=[math]::Round($s2.usedBytes/1MB,2); active=$s2.auth }
                        }
                    }
                    $out = [ordered]@{ date=$S.Day; updatedAt=(Get-Date).ToString("s"); sessions=$hs }
                    [System.IO.File]::WriteAllText($hf, ($out | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
                } catch {}
            }
        } catch { LogC "loop err: $($_.Exception.Message)" }
    }
})
$null = $ctrl.AddArgument($Root); $null = $ctrl.AddArgument($DataDir); $null = $ctrl.AddArgument($EngineF)
$null = $ctrl.AddArgument($CmdF); $null = $ctrl.AddArgument($DbF); $null = $ctrl.AddArgument($HistoryDir)
$null = $ctrl.AddArgument($S); $null = $ctrl.AddArgument($ROUTER_IP)
$ctrl.BeginInvoke() | Out-Null

# ---------------- Throttle flush thread ----------------
$flush = [powershell]::Create().AddScript({
    param($S, $WD)
    function LogF([string]$m) {}
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WDF {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetDllDirectory(string path);
    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern bool WinDivertSend(IntPtr handle, byte[] pPacket, uint packetLen, out uint pSendLen, byte[] pAddr);
    [DllImport("WinDivert.dll", CallingConvention=CallingConvention.Cdecl, SetLastError=true)]
    public static extern bool WinDivertClose(IntPtr handle);
}
'@
    $null = [WDF]::SetDllDirectory($WD)
    $null = [WDF]::LoadLibrary((Join-Path $WD "WinDivert.dll"))
    # send-only handle: filter matches nothing (prevents re-capture loops)
    $h = [WDF]::WinDivertOpen("ip.SrcAddr == 0.0.0.0 and ip.DstAddr == 255.255.255.255 and ip.Protocol == 250", 0, -100, 0)
    if ($h -eq [IntPtr]::Zero) { return }
    while ($true) {
        Start-Sleep -Milliseconds 40
        $nowMs = [DateTime]::UtcNow.Ticks / 10000
        foreach ($mac in @($S.Pending.Keys)) {
            $q = $S.Pending[$mac]
            if ($q.Count -eq 0) { continue }
            $sess = $null
            foreach ($k in @($S.Sessions.Keys)) { if ($S.Sessions[$k].mac -eq $mac) { $sess = $S.Sessions[$k]; break } }
            if (-not $sess) { $q.Clear(); continue }
            $sentAny = $true
            while ($q.Count -gt 0 -and $sentAny) {
                $sentAny = $false
                $item = $q[0]
                $budget = $item.dir + "Budget"
                if ($sess[$budget] -ge $item.bytes) {
                    $sess[$budget] -= $item.bytes
                    $null = [WDF]::WinDivertSend($h, $item.pkt, $item.pkt.Length, [ref]([uint32]0), $item.addr)
                    $q.RemoveAt(0)
                    $sentAny = $true
                } else { break }
            }
        }
    }
})
$null = $flush.AddArgument($S); $null = $flush.AddArgument($WD)
$flush.BeginInvoke() | Out-Null

# ---------------- Open capture handle ----------------
$guestRange = "(ip.SrcAddr >= $GUEST_LO and ip.SrcAddr <= $GUEST_HI)"
$guestDst   = "(ip.DstAddr >= $GUEST_LO and ip.DstAddr <= $GUEST_HI)"
$flt = "(inbound and $guestRange) or (outbound and $guestDst)"
if ($TestMode) {
    $flt = "($flt) or (ip.SrcAddr == $ROUTER_IP) or (ip.DstAddr == $ROUTER_IP)"
    Log "TEST MODE: router $ROUTER_IP included in capture"
}
$hMain = [WD]::WinDivertOpen($flt, $LAYER_NETWORK, 0, 0)
if ($hMain -eq [IntPtr]::Zero) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Log "FATAL: WinDivertOpen failed, error $err"
    Write-Host "FATAL: WinDivertOpen failed (error $err). Run as Administrator." -ForegroundColor Red
    exit 1
}
Log "engine started (TestMode=$TestMode) filter=$flt"

# ---------------- DNS reply builder ----------------
function New-CaptiveDnsReply([byte[]]$query, [int]$ihl, [byte[]]$clientIpBytes, [byte[]]$serverIpBytes) {
    if ($query.Length -lt ($ihl + 20 + 12)) { return $null }
    $udpStart = $ihl
    $cliPort = ($query[$udpStart] -shl 8) -bor $query[$udpStart+1]
    $dnsStart = $ihl + 8
    $dnsLen = $query.Length - $dnsStart
    if ($dnsLen -lt 12) { return $null }
    $flags = ($query[$dnsStart+2] -shl 8) -bor $query[$dnsStart+3]
    if (($flags -band 0x8000) -ne 0) { return $null }   # not a query
    # response header: same id, QR+RD+RA, rcode 0, qd=1, an=1
    $id0 = $query[$dnsStart]; $id1 = $query[$dnsStart+1]
    $qd0 = $query[$dnsStart+4]; $qd1 = $query[$dnsStart+5]
    $resp = New-Object System.Collections.Generic.List[byte]
    $resp.Add($id0); $resp.Add($id1)
    $resp.Add(0x81); $resp.Add(0x80)   # QR=1 RD=1 RA=1
    $resp.Add($qd0); $resp.Add($qd1)
    $resp.Add(0); $resp.Add(1)         # ANCOUNT
    $resp.Add(0); $resp.Add(0)         # NSCOUNT
    $resp.Add(0); $resp.Add(0)         # ARCOUNT
    for ($i = $dnsStart+12; $i -lt ($dnsStart + $dnsLen); $i++) { $resp.Add($query[$i]) }   # question section
    # answer: pointer to qname (0xC00C), TYPE A, CLASS IN, TTL 10, RDLENGTH 4, RDATA 192.168.2.1
    $resp.Add(0xC0); $resp.Add(0x0C)
    $resp.Add(0); $resp.Add(1)
    $resp.Add(0); $resp.Add(1)
    $resp.Add(0); $resp.Add(0); $resp.Add(0); $resp.Add(10)
    $resp.Add(0); $resp.Add(4)
    $resp.Add(192); $resp.Add(168); $resp.Add(2); $resp.Add(1)
    $dns = $resp.ToArray()
    # UDP header
    $udpLen = 8 + $dns.Length
    $udp = New-Object byte[] 8
    $udp[0] = 0; $udp[1] = 53
    $udp[2] = ($cliPort -shr 8) -band 0xFF; $udp[3] = $cliPort -band 0xFF
    $udp[4] = ($udpLen -shr 8) -band 0xFF;  $udp[5] = $udpLen -band 0xFF
    # IP header
    $totalLen = 20 + $udpLen
    $ip = New-Object byte[] 20
    $ip[0] = 0x45; $ip[1] = 0
    $ip[2] = ($totalLen -shr 8) -band 0xFF; $ip[3] = $totalLen -band 0xFF
    $ip[4] = 0; $ip[5] = 0; $ip[6] = 0x40; $ip[7] = 0
    $ip[8] = 64; $ip[9] = 17
    $ip[12] = $serverIpBytes[0]; $ip[13] = $serverIpBytes[1]; $ip[14] = $serverIpBytes[2]; $ip[15] = $serverIpBytes[3]
    $ip[16] = $clientIpBytes[0]; $ip[17] = $clientIpBytes[1]; $ip[18] = $clientIpBytes[2]; $ip[19] = $clientIpBytes[3]
    $pkt = New-Object byte[] $totalLen
    [Array]::Copy($ip, 0, $pkt, 0, 20)
    [Array]::Copy($udp, 0, $pkt, 20, 8)
    [Array]::Copy($dns, 0, $pkt, 28, $dns.Length)
    return $pkt
}

# ---------------- Main capture loop ----------------
$buf = New-Object byte[] 65536
$addr = New-Object byte[] $ADDR_LEN
$null = 0
while ($true) {
  try {
    $n = [uint32]0
    $ok = [WD]::WinDivertRecv($hMain, $buf, $buf.Length, [ref]$n, $addr)
    if (-not $ok -or $n -lt 20) { continue }
    $S.Stats.packets++
    $ihl = ($buf[0] -band 0x0F) * 4
    if ($ihl -lt 20 -or $n -lt $ihl) { [WD]::WinDivertSend($hMain, $buf, $n, [ref]([uint32]0), $addr); continue }
    $proto = $buf[9]
    $src = "$($buf[12]).$($buf[13]).$($buf[14]).$($buf[15])"
    $dst = "$($buf[16]).$($buf[17]).$($buf[18]).$($buf[19])"
    $bitf = [BitConverter]::ToUInt32($addr, 8)
    $isOutbound = (($bitf -band $FLAG_OUTBOUND) -ne 0)

    # guest-bound protection zones (always drop, even for authenticated devices)
    $dstU = 0; $isRouterDst = $false; $isHomeDst = $false
    try { $dstU = IPToUInt $dst } catch {}
    if ($dstU -eq $ROUTER_U) { $isRouterDst = $true }
    if (($dstU -band $HOME_MASK) -eq $HOME_U) { $isHomeDst = $true }

    # direction: inbound from guest = UPLOAD; outbound to guest = DOWNLOAD
    $guestIp = $null; $dir = "down"
    if (-not $isOutbound -and (IsGuestIp $src)) { $guestIp = $src; $dir = "up" }
    elseif ($isOutbound -and (IsGuestIp $dst)) { $guestIp = $dst; $dir = "down" }
    elseif ($TestMode -and ($src -eq $ROUTER_IP -or $dst -eq $ROUTER_IP)) { $guestIp = $ROUTER_IP; $dir = "down" }

    if (-not $guestIp) { [WD]::WinDivertSend($hMain, $buf, $n, [ref]([uint32]0), $addr); continue }

    $sess = Get-EffectiveSession $guestIp
    if (-not $sess) {
        $sess = @{ mac="ip:$guestIp"; ip=$guestIp; host=""; auth=$false; usedBytes=0; dailyBytes=0; reason="new"; pending=0 }
        $S.Sessions["ip:$guestIp"] = $sess
    }

    # DNS captive check for unauthenticated guests
    $isDnsQuery = $false
    if ($proto -eq 17 -and -not $isOutbound -and $n -ge ($ihl + 8)) {
        $dport = ($buf[$ihl+2] -shl 8) -bor $buf[$ihl+3]
        if ($dport -eq 53) { $isDnsQuery = $true }
    }

    $blacklisted = $sess.mac -and ($S.Blacklist -contains $sess.mac)
    $cut = ($S.CutIps -contains $guestIp)
    $nightGated = ($S.Schedule.activeNow -and -not ($S.Schedule.bypassMacs -contains $sess.mac))
    $expired = $false
    if ($sess.auth -and $sess.expiresAt) {
        try { if ((Get-Date) -gt [datetime]::Parse($sess.expiresAt)) { $expired = $true; $sess.reason = "expired" } } catch {}
    }
    $quotaHit = $false
    if ($sess.auth -and $sess.quotaGB -gt 0 -and ($sess.usedBytes / 1GB) -ge $sess.quotaGB) { $quotaHit = $true; $sess.reason = "quota" }
    $dailyHit = $false
    if ($sess.auth -and $sess.dailyGB -gt 0 -and ($sess.dailyBytes / 1GB) -ge $sess.dailyGB) { $dailyHit = $true; $sess.reason = "daily" }

    $allowed = $sess.auth -and -not $blacklisted -and -not $cut -and -not $nightGated -and -not $expired -and -not $quotaHit -and -not $dailyHit

    if ($isRouterDst -or $isHomeDst) {
        if (-not $isOutbound) { $S.Stats.dropped++; continue }   # drop silently (guest -> router/home)
    }

    if (-not $allowed) {
        if ($isDnsQuery -and -not $blacklisted -and -not $cut) {
            $cli = [byte[]]@($buf[12],$buf[13],$buf[14],$buf[15])
            $srv = [byte[]]@($buf[16],$buf[17],$buf[18],$buf[19])
            $reply = New-CaptiveDnsReply $buf $ihl $cli $srv
            if ($reply) {
                $outAddr = [byte[]]$addr.Clone()
                $bf = [BitConverter]::ToUInt32($outAddr, 8)
                $bf = $bf -bor $FLAG_OUTBOUND
                $bf = $bf -band (-bnot $FLAG_SNIFFED)
                $bf = $bf -band (-bnot ($FLAG_IPCSUM -bor $FLAG_TCPCSUM -bor $FLAG_UDPCSUM))
                [BitConverter]::GetBytes([uint32]$ETH_IFIDX).CopyTo($outAddr, 16)
                [BitConverter]::GetBytes([uint32]0).CopyTo($outAddr, 20)
                [BitConverter]::GetBytes([uint32]$bf).CopyTo($outAddr, 8)
                $null = [WD]::WinDivertSend($hMain, $reply, $reply.Length, [ref]([uint32]0), $outAddr)
                $S.Stats.dnsAnswered++
            }
        }
        $S.Stats.dropped++
        continue   # drop everything else
    }

    # accounting
    $sess.usedBytes += $n
    $sess.dailyBytes += $n
    if ($dir -eq "down") { $sess.bytesDown = ($sess.bytesDown + $n) } else { $sess.bytesUp = ($sess.bytesUp + $n) }

    # throttling (token bucket): refill happens in flush thread by rate per second
    $sdK = [int]$sess.speedDownKbps; $suK = [int]$sess.speedUpKbps
    if (($dir -eq "down" -and $sdK -gt 0) -or ($dir -eq "up" -and $suK -gt 0)) {
        if (-not $sess["downBudget"]) { $sess.downBudget = $sdK * 128; $sess.upBudget = $suK * 128 }  # ~1s burst (KBps*1024/8*... simplified)
        # refill: budgets are refilled by flush thread each 40ms; approximate here by adding rate*40ms
        if ($dir -eq "down") { $sess.downBudget = [Math]::Min($sdK * 256, $sess.downBudget + $sdK * 5) }
        else { $sess.upBudget = [Math]::Min($suK * 256, $sess.upBudget + $suK * 5) }
        $budgetKey = $dir + "Budget"
        if ($sess[$budgetKey] -lt $n) {
            $mac = $sess.mac
            if (-not $S.Pending.ContainsKey($mac)) { $S.Pending[$mac] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)) }
            if ($S.Pending[$mac].Count -lt 300) {
                $pktCopy = New-Object byte[] $n
                [Array]::Copy($buf, $pktCopy, $n)
                $addrCopy = [byte[]]$addr.Clone()
                $null = $S.Pending[$mac].Add(@{ pkt=$pktCopy; addr=$addrCopy; bytes=$n; dir=$dir })
                continue
            }
        }
        $sess[$budgetKey] -= $n
    }

    $null = [WD]::WinDivertSend($hMain, $buf, $n, [ref]([uint32]0), $addr)
  } catch {
    Log ("mainloop ERR: " + $_.Exception.Message + " @ " + $_.InvocationInfo.ScriptLineNumber)
    Start-Sleep -Milliseconds 100
  }
}
