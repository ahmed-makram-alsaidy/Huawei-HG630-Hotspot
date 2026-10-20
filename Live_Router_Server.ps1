<#
.SYNOPSIS
    Huawei HG630 V2 Direct Port-80 Server for 192.168.2.1
    Serves the Clean Arabic Router & Hotspot Management System on http://192.168.2.1 (Port 80) and Port 8630,
    bridging directly to the Huawei router hardware at 192.168.2.254.
#>
param(
    [int]$PrimaryPort = 80,
    [int]$SecondaryPort = 8630,
    [string]$RouterIP = "192.168.2.254",
    [string]$AdminUser = "admin",
    [string]$AdminPass = "3BB"
)

$ErrorActionPreference = "Continue"
$AuthFile = "$PSScriptRoot\Huawei_Arabic_System\data\auth.json"
$DbFile   = "$PSScriptRoot\Huawei_Arabic_System\data\db.json"

# --- Admin session tokens (in-memory; invalidated by server restart) ---
$script:Sessions = @{}
function New-SessionToken {
    $t = [guid]::NewGuid().ToString("N")
    $script:Sessions[$t] = (Get-Date).AddHours(12)
    return $t
}
function Test-SessionToken([string]$tok) {
    if ([string]::IsNullOrWhiteSpace($tok)) { return $false }
    if (-not $script:Sessions.ContainsKey($tok)) { return $false }
    if ((Get-Date) -gt $script:Sessions[$tok]) { $script:Sessions.Remove($tok) | Out-Null; return $false }
    return $true
}
function Revoke-SessionToken([string]$tok) {
    if ($tok -and $script:Sessions.ContainsKey($tok)) { $script:Sessions.Remove($tok) | Out-Null }
}

function Get-LocalAuth {
    if (Test-Path $AuthFile) {
        try { return ([System.IO.File]::ReadAllText($AuthFile, [System.Text.Encoding]::UTF8) | ConvertFrom-Json) } catch {}
    }
    return @{ username = $AdminUser; password = $AdminPass }
}

function Save-LocalAuth([string]$u, [string]$p) {
    $dir = Split-Path $AuthFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = @{ username = $u; password = $p } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($AuthFile, $json, [System.Text.Encoding]::UTF8)
}

function Get-DbJsonString {
    if (Test-Path $DbFile) {
        return [System.IO.File]::ReadAllText($DbFile, [System.Text.Encoding]::UTF8)
    }
    return "{}"
}

function Save-DbJsonString([string]$rawJson) {
    $dir = Split-Path $DbFile -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($DbFile, $rawJson, [System.Text.Encoding]::UTF8)
}

$CmdFile = "$PSScriptRoot\Huawei_Arabic_System\data\engine_cmd.json"
$script:CmdId = 0
function Send-EngineCmd([hashtable]$cmd) {
    $lockDir = "$PSScriptRoot\Huawei_Arabic_System\data"
    if (-not (Test-Path $CmdFile)) {
        [System.IO.File]::WriteAllText($CmdFile, '{"lastId":0,"cmds":[]}', [System.Text.Encoding]::UTF8)
    }
    if ($script:CmdId -eq 0) {
        try { $script:CmdId = ((Get-Content $CmdFile -Raw -Encoding UTF8 | ConvertFrom-Json).lastId) } catch { $script:CmdId = 0 }
    }
    $script:CmdId++
    $cmd.id = $script:CmdId
    $queue = @()
    try { $queue = @((Get-Content $CmdFile -Raw -Encoding UTF8 | ConvertFrom-Json).cmds) } catch {}
    $queue = @($queue | Where-Object { $_.id -gt ($script:CmdId - 50) })   # keep queue small
    $queue += $cmd
    $json = @{ lastId = $script:CmdId; cmds = $queue } | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::WriteAllText($CmdFile, $json, [System.Text.Encoding]::UTF8)
}

function Get-EngineState {
    $f = "$PSScriptRoot\Huawei_Arabic_System\data\engine.json"
    if (Test-Path $f) {
        try { return ([System.IO.File]::ReadAllText($f, [System.Text.Encoding]::UTF8) | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Parse-HuaweiJson([string]$raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $clean = $raw.Trim() -replace '^while\(1\);\s*/\*', '' -replace '\*/$', ''
    return ($clean | ConvertFrom-Json)
}

function Get-Sha256([string]$text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Get-AuthenticatedRouterSession([string]$targetIP) {
    $r0 = Invoke-WebRequest -Uri "http://$targetIP/" -SessionVariable sess -UseBasicParsing -TimeoutSec 5
    $csrf_param = [regex]::Match($r0.Content, 'name="csrf_param"\s+content="([^"]+)"').Groups[1].Value
    $csrf_token = [regex]::Match($r0.Content, 'name="csrf_token"\s+content="([^"]+)"').Groups[1].Value

    $vcRaw = (Invoke-WebRequest -Uri "http://$targetIP/api/system/getverifycode" -WebSession $sess -UseBasicParsing -TimeoutSec 5).Content
    $vcObj = Parse-HuaweiJson $vcRaw
    $code = ($vcObj.VerifyCodeImg.Split(",") | ForEach-Object { $_.Replace(".gif","")[-1] }) -join ""
    $chkBody = @{ csrf = @{ csrf_param = $csrf_param; csrf_token = $csrf_token }; data = @{ VerifyCode = $code } } | ConvertTo-Json -Compress
    $chkRaw = (Invoke-WebRequest -Uri "http://$targetIP/api/system/checkverifycode" -Method Post -WebSession $sess -Body $chkBody -ContentType "application/json" -UseBasicParsing -TimeoutSec 5).Content
    $chkObj = Parse-HuaweiJson $chkRaw
    $csrf_param = $chkObj.csrf_param
    $csrf_token = $chkObj.csrf_token

    $pwdHash = Get-Sha256 $AdminPass
    $pwdB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pwdHash))
    $finalPwd = Get-Sha256 ($AdminUser + $pwdB64 + $csrf_param + $csrf_token)
    $loginBody = @{ csrf = @{ csrf_param = $csrf_param; csrf_token = $csrf_token }; data = @{ UserName = $AdminUser; Password = $finalPwd } } | ConvertTo-Json -Compress
    $loginRaw = (Invoke-WebRequest -Uri "http://$targetIP/api/system/user_login" -Method Post -WebSession $sess -Body $loginBody -ContentType "application/json" -UseBasicParsing -TimeoutSec 5).Content
    $loginObj = Parse-HuaweiJson $loginRaw
    if ($loginObj.csrf_param) {
        $csrf_param = $loginObj.csrf_param
        $csrf_token = $loginObj.csrf_token
    } else {
        $r1 = Invoke-WebRequest -Uri "http://$targetIP/" -WebSession $sess -UseBasicParsing -TimeoutSec 5
        $csrf_param = [regex]::Match($r1.Content, 'name="csrf_param"\s+content="([^"]+)"').Groups[1].Value
        $csrf_token = [regex]::Match($r1.Content, 'name="csrf_token"\s+content="([^"]+)"').Groups[1].Value
    }
    return @{ session = $sess; csrf_param = $csrf_param; csrf_token = $csrf_token }
}

function Get-LiveRouterStatus {
    $targetIP = $RouterIP
    try {
        $devRaw = (Invoke-WebRequest -Uri "http://$targetIP/api/system/deviceinfo" -UseBasicParsing -TimeoutSec 2).Content
        $hostRaw = (Invoke-WebRequest -Uri "http://$targetIP/api/system/HostInfo" -UseBasicParsing -TimeoutSec 2).Content
        $aclRaw = (Invoke-WebRequest -Uri "http://$targetIP/api/ntwk/acl" -UseBasicParsing -TimeoutSec 2).Content
        $dev = Parse-HuaweiJson $devRaw
        $hostsParsed = Parse-HuaweiJson $hostRaw
        $acls = Parse-HuaweiJson $aclRaw

        $hostList = @()
        if ($null -ne $hostsParsed) {
            if ($hostsParsed -is [System.Array]) { $hostList = $hostsParsed }
            else { $hostList = @($hostsParsed) }
        }

        $monthlyFile = "$PSScriptRoot\Huawei_Arabic_System\data\monthly_state.json"
        $lastWipe = "2026-10-20"
        if (Test-Path $monthlyFile) {
            $mObj = Get-Content $monthlyFile -Raw | ConvertFrom-Json
            $lastWipe = $mObj.LastMonthlyWipe
        }

        return @{
            ok = $true
            connected = $true
            routerIP = "192.168.2.1"
            engineIP = $targetIP
            deviceInfo = $dev
            hosts = $hostList
            aclCount = @($acls).Count
            lastMonthlyWipe = $lastWipe
        }
    } catch {
        return @{
            ok = $false
            connected = $false
            routerIP = "192.168.2.1"
            engineIP = $targetIP
            error = $_.Exception.Message
        }
    }
}

function Push-SignedConfigToRouter([byte[]]$fileBytes) {
    $targetIP = $RouterIP
    $auth = Get-AuthenticatedRouterSession $targetIP
    $sess = $auth.session
    $csrf_param = $auth.csrf_param
    $csrf_token = $auth.csrf_token

    $vcRaw2 = (Invoke-WebRequest -Uri "http://$targetIP/api/system/getverifycode" -WebSession $sess -UseBasicParsing -TimeoutSec 5).Content
    $vcObj2 = Parse-HuaweiJson $vcRaw2
    $code2 = ($vcObj2.VerifyCodeImg.Split(",") | ForEach-Object { $_.Replace(".gif","")[-1] }) -join ""
    $chkBody2 = @{ csrf = @{ csrf_param = $csrf_param; csrf_token = $csrf_token }; data = @{ VerifyCode = $code2 } } | ConvertTo-Json -Compress
    $chkRaw2 = (Invoke-WebRequest -Uri "http://$targetIP/api/system/checkverifycode" -Method Post -WebSession $sess -Body $chkBody2 -ContentType "application/json" -UseBasicParsing -TimeoutSec 5).Content
    $chkObj2 = Parse-HuaweiJson $chkRaw2
    $csrf_param = $chkObj2.csrf_param
    $csrf_token = $chkObj2.csrf_token

    $boundary = "---------------------------" + [DateTime]::Now.Ticks.ToString("x")
    $crlf = "`r`n"
    $csrfCombined = "csrf:" + $csrf_param + $csrf_token
    $part1 = "--$boundary$crlf" + "Content-Disposition: form-data; name=`"csrf_token`"$crlf$crlf" + "$csrfCombined$crlf"
    $part2Header = "--$boundary$crlf" + "Content-Disposition: form-data; name=`"configurefilename`"; filename=`"curcfg_upgraded_signed.conf`"$crlf" + "Content-Type: application/octet-stream$crlf$crlf"
    $partFooter = "$crlf--$boundary--$crlf"

    $p1Bytes = [System.Text.Encoding]::ASCII.GetBytes($part1)
    $p2Bytes = [System.Text.Encoding]::ASCII.GetBytes($part2Header)
    $pfBytes = [System.Text.Encoding]::ASCII.GetBytes($partFooter)

    $bodyStream = New-Object System.IO.MemoryStream
    $bodyStream.Write($p1Bytes, 0, $p1Bytes.Length)
    $bodyStream.Write($p2Bytes, 0, $p2Bytes.Length)
    $bodyStream.Write($fileBytes, 0, $fileBytes.Length)
    $bodyStream.Write($pfBytes, 0, $pfBytes.Length)
    $fullBody = $bodyStream.ToArray()

    [System.IO.File]::WriteAllBytes("$PSScriptRoot\backups\curcfg_upgraded_signed.conf", $fileBytes)

    $uploadResp = Invoke-WebRequest -Uri "http://$targetIP/uploadconfigfile.cgi" -Method Post -WebSession $sess -Body $fullBody -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing -TimeoutSec 30
    $upObj = Parse-HuaweiJson $uploadResp.Content
    return @{
        ok = ($upObj.errcode -eq 0)
        errcode = $upObj.errcode
        raw = $uploadResp.Content
    }
}

function Invoke-RouterReboot {
    try {
        $targetIP = $RouterIP
        $auth = Get-AuthenticatedRouterSession $targetIP
        $rebBody = @{ csrf = @{ csrf_param = $auth.csrf_param; csrf_token = $auth.csrf_token } } | ConvertTo-Json -Compress
        $resp = Invoke-WebRequest -Uri "http://$targetIP/api/service/reboot.cgi" -Method Post -WebSession $auth.session -Body $rebBody -ContentType "application/json" -UseBasicParsing -TimeoutSec 5
        return @{ ok = $true }
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

function Handle-Client($client) {
    try {
        $stream = $client.GetStream()
        $stream.ReadTimeout = 400
        $buf = New-Object byte[] 65536
        $ms = New-Object System.IO.MemoryStream
        $headerEnd = -1
        $contentLen = 0

        while ($true) {
            $r = $stream.Read($buf, 0, $buf.Length)
            if ($r -le 0) { break }
            $ms.Write($buf, 0, $r)
            $arr = $ms.ToArray()
            if ($headerEnd -lt 0) {
                $str = [System.Text.Encoding]::ASCII.GetString($arr)
                $idx = $str.IndexOf("`r`n`r`n")
                if ($idx -ge 0) {
                    $headerEnd = $idx + 4
                    $mLen = [regex]::Match($str.Substring(0, $idx), 'Content-Length:\s*(\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if ($mLen.Success) { $contentLen = [int]$mLen.Groups[1].Value }
                }
            }
            if ($headerEnd -ge 0 -and ($arr.Length -ge ($headerEnd + $contentLen))) { break }
        }

        $allBytes = $ms.ToArray()
        if ($allBytes.Length -eq 0) { $client.Close(); return }
        $reqHeader = [System.Text.Encoding]::ASCII.GetString($allBytes, 0, [Math]::Min($allBytes.Length, 4096))
        $firstLine = ($reqHeader -split "`r`n")[0]
        $parts = $firstLine -split " "
        $method = $parts[0]
        $path = ($parts[1] -split "\?")[0]
        $authToken = [regex]::Match($reqHeader, 'X-Auth-Token:\s*([^\r\n]+)').Groups[1].Value.Trim()

        $statusLine = "HTTP/1.1 200 OK"
        $contentType = "application/json; charset=utf-8"
        $respBytes = [byte[]]@()

        # Endpoints that expose router state, config blobs, voucher codes or destructive actions
        $protectedPaths = @("/api/db", "/api/current-conf", "/api/live-status", "/api/apply-config", "/api/reboot", "/api/wipe-storage", "/api/change-password", "/api/engine-status", "/api/engine-cmd", "/api/reports", "/api/vouchers-export")
        if ($protectedPaths -contains $path -and -not (Test-SessionToken $authToken)) {
            $statusLine = "HTTP/1.1 401 Unauthorized"
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes('{ "ok": false, "error": "Unauthorized" }')
        }
        elseif ($method -eq "OPTIONS") {
            $respBytes = [byte[]]@()
        }
        elseif ($path -eq "/" -or $path -eq "/index.html" -or $path -eq "/admin") {
            $contentType = "text/html; charset=utf-8"
            $respBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\Huawei_Arabic_System\index.html")
        }
        elseif ($path -eq "/portal" -or $path -eq "/portal.html") {
            $contentType = "text/html; charset=utf-8"
            $respBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\Huawei_Arabic_System\portal.html")
        }
        elseif ($path -eq "/api/login" -and $method -eq "POST") {
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($allBytes, $headerEnd, $contentLen)
            $reqObj = $bodyStr | ConvertFrom-Json
            $curAuth = Get-LocalAuth
            if ($reqObj.username -eq $curAuth.username -and $reqObj.password -eq $curAuth.password) {
                $tok = New-SessionToken
                $json = @{ ok = $true; username = $curAuth.username; token = $tok } | ConvertTo-Json -Compress
            } else {
                $json = @{ ok = $false; error = "Invalid credentials" } | ConvertTo-Json -Compress
            }
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/change-password" -and $method -eq "POST") {
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($allBytes, $headerEnd, $contentLen)
            $reqObj = $bodyStr | ConvertFrom-Json
            $curAuth = Get-LocalAuth
            if ($reqObj.currentPassword -ne $curAuth.password) {
                $json = @{ ok = $false; error = "Invalid current password" } | ConvertTo-Json -Compress
            } else {
                Save-LocalAuth $reqObj.username $reqObj.newPassword
                $json = @{ ok = $true } | ConvertTo-Json -Compress
            }
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/portal-info" -and $method -eq "GET") {
            # Public endpoint for the guest portal: network name, welcome text and packages ONLY.
            # Never exposes vouchers, users or credentials (those stay behind the token on /api/db).
            $dbObj = Get-DbJsonString | ConvertFrom-Json
            $pkgs = @(); if ($dbObj.packages) { $pkgs = @($dbObj.packages) }
            $json = @{ portalConfig = $dbObj.portalConfig; packages = $pkgs } | ConvertTo-Json -Depth 6 -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/db" -and $method -eq "GET") {
            $rawDb = Get-DbJsonString
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($rawDb)
        }
        elseif ($path -eq "/api/db" -and $method -eq "POST") {
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($allBytes, $headerEnd, $contentLen)
            Save-DbJsonString $bodyStr
            $json = @{ ok = $true } | ConvertTo-Json -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/portal-login" -and $method -eq "POST") {
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($allBytes, $headerEnd, $contentLen)
            $reqObj = $bodyStr | ConvertFrom-Json
            $dbObj = Get-DbJsonString | ConvertFrom-Json
            $clientIp = $client.Client.RemoteEndPoint.Address.ToString()
            $result = @{ ok = $false; error = "Invalid login" }

            if ($reqObj.mode -eq "voucher") {
                $code = ($reqObj.code + "").Trim()
                foreach ($v in $dbObj.vouchers) {
                    if ($v.code -eq $code) {
                        if ($v.status -eq "disabled" -or $v.status -eq "expired") {
                            $result = @{ ok = $false; error = "Voucher disabled or expired" }
                        } else {
                            $v.status = "active"
                            if (-not $v.activatedAt) { $v.activatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm") }
                            $v.deviceIp = $clientIp
                            $v.deviceMac = ""
                            Save-DbJsonString ($dbObj | ConvertTo-Json -Depth 8)
                            $expAt = (Get-Date).AddDays([double]($v.days | ForEach-Object { if ($_ -as [double]) { $_ } else { 30 } })).ToString("s")
                            Send-EngineCmd @{
                                type = "authorize"; ip = $clientIp; mac = ""
                                name = $v.code; code = $v.code; userKey = "voucher:$($v.code)"
                                pkg = @{ name = $v.packageName; quotaGB = $v.quotaGB; dailyGB = 0
                                         speedDownKbps = [int]($v.speedDown * 1024); speedUpKbps = [int]($v.speedUp * 1024) }
                                expiresAt = $expAt
                            }
                            $result = @{
                                ok = $true
                                type = "voucher"
                                name = $v.code
                                packageName = $v.packageName
                                speedDown = $v.speedDown
                                speedUp = $v.speedUp
                                quotaGB = $v.quotaGB
                                usedMB = $v.usedMB
                                expiresInfo = "$($v.days) Days"
                            }
                        }
                        break
                    }
                }
            } else {
                $uName = ($reqObj.username + "").Trim()
                $uPass = ($reqObj.password + "")
                foreach ($u in $dbObj.users) {
                    if ($u.username -eq $uName -and $u.password -eq $uPass) {
                        if ($u.status -ne "active") {
                            $result = @{ ok = $false; error = "Account suspended" }
                        } else {
                            $u.deviceIp = $clientIp
                            Send-EngineCmd @{
                                type = "authorize"; ip = $clientIp; mac = $u.macLock
                                name = $u.fullName; code = $u.username; userKey = "user:$($u.username)"
                                pkg = @{ name = $u.packageName; quotaGB = $u.quotaGB; dailyGB = 0
                                         speedDownKbps = [int]($u.speedDown * 1024); speedUpKbps = [int]($u.speedUp * 1024) }
                                expiresAt = $u.expiresAt
                            }
                            $result = @{
                                ok = $true
                                type = "user"
                                name = $u.fullName
                                packageName = $u.packageName
                                speedDown = $u.speedDown
                                speedUp = $u.speedUp
                                quotaGB = $u.quotaGB
                                usedMB = $u.usedMB
                                expiresInfo = $u.expiresAt
                            }
                        }
                        break
                    }
                }
            }
            $json = $result | ConvertTo-Json -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/current-conf") {
            $confPath = "$PSScriptRoot\backups\curcfg_upgraded_signed.conf"
            if (-not (Test-Path $confPath)) { $confPath = "$PSScriptRoot\backups\curcfg_backup_original.conf" }
            $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($confPath))
            $json = @{ ok = $true; confBase64 = $b64 } | ConvertTo-Json -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/live-status") {
            $st = Get-LiveRouterStatus
            $json = $st | ConvertTo-Json -Depth 6 -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/wipe-storage" -and $method -eq "POST") {
            & "$PSScriptRoot\Monthly_Storage_Wipe.ps1" | Out-Null
            $json = @{ ok = $true; wipedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") } | ConvertTo-Json -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/reboot" -and $method -eq "POST") {
            $rebRes = Invoke-RouterReboot
            $json = $rebRes | ConvertTo-Json -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/apply-config" -and $method -eq "POST") {
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($allBytes, $headerEnd, $contentLen)
            $reqObj = $bodyStr | ConvertFrom-Json
            $confBytes = [Convert]::FromBase64String($reqObj.confBase64)
            $upRes = Push-SignedConfigToRouter $confBytes
            $json = $upRes | ConvertTo-Json -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/engine-status" -and $method -eq "GET") {
            $eng = Get-EngineState
            $json = @{ ok = $true; engine = $eng } | ConvertTo-Json -Depth 8 -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/engine-cmd" -and $method -eq "POST") {
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($allBytes, $headerEnd, $contentLen)
            $reqObj = $bodyStr | ConvertFrom-Json
            switch ($reqObj.cmd) {
                "cut"        { Send-EngineCmd @{ type = "cut"; ip = $reqObj.ip } }
                "release"    { Send-EngineCmd @{ type = "release"; ip = $reqObj.ip } }
                "blacklist"  { Send-EngineCmd @{ type = "blacklist"; mac = ($reqObj.mac + "").ToUpper() } }
                "unblacklist"{ Send-EngineCmd @{ type = "unblacklist"; mac = ($reqObj.mac + "").ToUpper() } }
                "schedule"   { Send-EngineCmd @{ type = "schedule"; payload = @{ enabled = [bool]$reqObj.enabled; start = $reqObj.start; end = $reqObj.end; bypassMacs = @($reqObj.bypassMacs) } } }
                default      { $json = @{ ok = $false; error = "unknown cmd" } | ConvertTo-Json -Compress; $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json) }
            }
            if (-not $respBytes) {
                $json = @{ ok = $true } | ConvertTo-Json -Compress
                $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            }
        }
        elseif ($path -eq "/api/reports" -and $method -eq "GET") {
            $hdir = "$PSScriptRoot\Huawei_Arabic_System\data\history"
            $days = @()
            if (Test-Path $hdir) {
                $days = Get-ChildItem $hdir -Filter "*.json" | Sort-Object Name -Descending | Select-Object -First 30 | ForEach-Object {
                    $day = $_.BaseName
                    try {
                        $d = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
                        [ordered]@{ date = $day; updatedAt = $d.updatedAt; sessions = $d.sessions }
                    } catch { $null }
                }
            }
            $json = @{ ok = $true; days = $days } | ConvertTo-Json -Depth 8 -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/vouchers-export" -and $method -eq "GET") {
            $dbObj = Get-DbJsonString | ConvertFrom-Json
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("code,package,speed_down_mbps,speed_up_mbps,quota_gb,days,status,used_mb,activated_at,device_ip")
            foreach ($v in $dbObj.vouchers) {
                [void]$sb.AppendLine("$($v.code),`"$($v.packageName)`",$($v.speedDown),$($v.speedUp),$($v.quotaGB),$($v.days),$($v.status),$($v.usedMB),$($v.activatedAt),$($v.deviceIp)")
            }
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
            $contentType = "text/csv; charset=utf-8"
        }
        elseif ($path -eq "/api/portal-status" -and $method -eq "GET") {
            $clientIp = $client.Client.RemoteEndPoint.Address.ToString()
            $eng = Get-EngineState
            $sess = $null
            if ($eng -and $eng.sessions) {
                foreach ($s in @($eng.sessions)) { if ($s.ip -eq $clientIp) { $sess = $s; break } }
            }
            $json = [ordered]@{
                ok = $true
                clientIp = $clientIp
                engineOnline = [bool]($eng -and $eng.heartbeat -and ((Get-Date) - [datetime]::Parse($eng.heartbeat)).TotalSeconds -lt 10)
                scheduleActive = [bool]($eng -and $eng.schedule.activeNow)
                session = $sess
            } | ConvertTo-Json -Depth 6 -Compress
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        }
        elseif ($path -eq "/api/speedtest" -and $method -eq "GET") {
            $kb = 2048
            try { if ($parts -join " " -match "kb=(\d+)") { $kb = [Math]::Min(16384, [int]$matches[1]) } } catch {}
            $ms = New-Object System.IO.MemoryStream
            $chunk = New-Object byte[] 65536
            (New-Object Random 42).NextBytes($chunk)
            $left = $kb * 1024
            while ($left -gt 0) {
                $take = [Math]::Min($left, $chunk.Length)
                $ms.Write($chunk, 0, $take)
                $left -= $take
            }
            $respBytes = $ms.ToArray()
            $contentType = "application/octet-stream"
        }
        else {
            $contentType = "text/html; charset=utf-8"
            $respBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\Huawei_Arabic_System\index.html")
        }

        $headers = "$statusLine`r`n" +
                   "Content-Type: $contentType`r`n" +
                   "Content-Length: $($respBytes.Length)`r`n" +
                   "Access-Control-Allow-Origin: *`r`n" +
                   "Access-Control-Allow-Methods: GET, POST, OPTIONS`r`n" +
                   "Access-Control-Allow-Headers: Content-Type, X-Auth-Token`r`n" +
                   "Connection: close`r`n`r`n"
        $hBytes = [System.Text.Encoding]::ASCII.GetBytes($headers)
        $stream.Write($hBytes, 0, $hBytes.Length)
        if ($respBytes.Length -gt 0) {
            $stream.Write($respBytes, 0, $respBytes.Length)
        }
        $stream.Flush()
        $client.Close()
    } catch {
        try { $client.Close() } catch {}
    }
}

$listener80 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $PrimaryPort)
$listener8630 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $SecondaryPort)
$listener80.Start()
$listener8630.Start()
Write-Host "[+] Arabic System Server active on Port $PrimaryPort (http://192.168.2.1/) and Port $SecondaryPort!" -ForegroundColor Green

while ($true) {
    if ($listener80.Pending()) {
        $c = $listener80.AcceptTcpClient()
        Handle-Client $c
    }
    if ($listener8630.Pending()) {
        $c = $listener8630.AcceptTcpClient()
        Handle-Client $c
    }
    Start-Sleep -Milliseconds 25
}
