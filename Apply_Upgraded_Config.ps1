# Upload curcfg_upgraded_signed.conf to Huawei HG630 V2 (192.168.2.254)
$ErrorActionPreference = "Stop"

function Parse-HuaweiJson([string]$raw) {
    $clean = $raw.Trim() -replace '^while\(1\);\s*/\*', '' -replace '\*/$', ''
    return ($clean | ConvertFrom-Json)
}

function Get-Sha256([string]$text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($bytes)
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
}

$confFile = "$PSScriptRoot\backups\curcfg_upgraded_signed.conf"
if (-not (Test-Path $confFile)) {
    throw "Upgraded config file not found: $confFile"
}
$fileBytes = [System.IO.File]::ReadAllBytes($confFile)
Write-Host "[1/4] Connecting to http://192.168.2.254/ ..."
$r0 = Invoke-WebRequest -Uri "http://192.168.2.254/" -SessionVariable sess -UseBasicParsing
$csrf_param = [regex]::Match($r0.Content, 'name="csrf_param"\s+content="([^"]+)"').Groups[1].Value
$csrf_token = [regex]::Match($r0.Content, 'name="csrf_token"\s+content="([^"]+)"').Groups[1].Value

# Solve VerifyCode before login just in case
$vcRaw = (Invoke-WebRequest -Uri "http://192.168.2.254/api/system/getverifycode" -WebSession $sess -UseBasicParsing).Content
$vcObj = Parse-HuaweiJson $vcRaw
$code = ($vcObj.VerifyCodeImg.Split(",") | ForEach-Object { $_.Replace(".gif","")[-1] }) -join ""
$chkBody = @{ csrf = @{ csrf_param = $csrf_param; csrf_token = $csrf_token }; data = @{ VerifyCode = $code } } | ConvertTo-Json -Compress
$chkRaw = (Invoke-WebRequest -Uri "http://192.168.2.254/api/system/checkverifycode" -Method Post -WebSession $sess -Body $chkBody -ContentType "application/json" -UseBasicParsing).Content
$chkObj = Parse-HuaweiJson $chkRaw
$csrf_param = $chkObj.csrf_param
$csrf_token = $chkObj.csrf_token

Write-Host "[2/4] Authenticating as admin ..."
$pwdHash = Get-Sha256 "3BB"
$pwdB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pwdHash))
$finalPwd = Get-Sha256 ("admin" + $pwdB64 + $csrf_param + $csrf_token)
$loginBody = @{ csrf = @{ csrf_param = $csrf_param; csrf_token = $csrf_token }; data = @{ UserName = "admin"; Password = $finalPwd } } | ConvertTo-Json -Compress
$loginRaw = (Invoke-WebRequest -Uri "http://192.168.2.254/api/system/user_login" -Method Post -WebSession $sess -Body $loginBody -ContentType "application/json" -UseBasicParsing).Content
$loginObj = Parse-HuaweiJson $loginRaw
Write-Host "      Login errcode: $($loginObj.errcode) | errCategory: $($loginObj.errCategory)"
if ($loginObj.csrf_param) {
    $csrf_param = $loginObj.csrf_param
    $csrf_token = $loginObj.csrf_token
} else {
    # Refresh index to get post-login CSRF tokens
    $r1 = Invoke-WebRequest -Uri "http://192.168.2.254/" -WebSession $sess -UseBasicParsing
    $csrf_param = [regex]::Match($r1.Content, 'name="csrf_param"\s+content="([^"]+)"').Groups[1].Value
    $csrf_token = [regex]::Match($r1.Content, 'name="csrf_token"\s+content="([^"]+)"').Groups[1].Value
}

Write-Host "[3/4] Passing ValidateCodeController check for uploadconfigfile.cgi ..."
$vcRaw2 = (Invoke-WebRequest -Uri "http://192.168.2.254/api/system/getverifycode" -WebSession $sess -UseBasicParsing).Content
$vcObj2 = Parse-HuaweiJson $vcRaw2
$code2 = ($vcObj2.VerifyCodeImg.Split(",") | ForEach-Object { $_.Replace(".gif","")[-1] }) -join ""
$chkBody2 = @{ csrf = @{ csrf_param = $csrf_param; csrf_token = $csrf_token }; data = @{ VerifyCode = $code2 } } | ConvertTo-Json -Compress
$chkRaw2 = (Invoke-WebRequest -Uri "http://192.168.2.254/api/system/checkverifycode" -Method Post -WebSession $sess -Body $chkBody2 -ContentType "application/json" -UseBasicParsing).Content
$chkObj2 = Parse-HuaweiJson $chkRaw2
$csrf_param = $chkObj2.csrf_param
$csrf_token = $chkObj2.csrf_token
Write-Host "      VerifyCode ($code2) CheckResult: $($chkObj2.CheckResult)"

Write-Host "[4/4] Uploading signed configuration ($($fileBytes.Length) bytes) to http://192.168.2.254/uploadconfigfile.cgi ..."
$boundary = "---------------------------" + [DateTime]::Now.Ticks.ToString("x")
$crlf = "`r`n"
$csrfCombined = "csrf:" + $csrf_param + $csrf_token

$part1 = "--$boundary$crlf" +
         "Content-Disposition: form-data; name=`"csrf_token`"$crlf$crlf" +
         "$csrfCombined$crlf"
$part2Header = "--$boundary$crlf" +
               "Content-Disposition: form-data; name=`"configurefilename`"; filename=`"curcfg_upgraded_signed.conf`"$crlf" +
               "Content-Type: application/octet-stream$crlf$crlf"
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

$uploadResp = Invoke-WebRequest -Uri "http://192.168.2.254/uploadconfigfile.cgi" -Method Post -WebSession $sess -Body $fullBody -ContentType "multipart/form-data; boundary=$boundary" -UseBasicParsing -TimeoutSec 30
Write-Host "=== Upload Response ==="
Write-Host $uploadResp.Content
