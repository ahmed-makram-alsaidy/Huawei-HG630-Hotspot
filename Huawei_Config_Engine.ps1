<#
.SYNOPSIS
    Huawei HG630 V2 / HG633 Configuration Decryption, Password Encoder, RSA-1024 Signer & AES-256-CBC Packer
    100% Native PowerShell (.NET Cryptography & BigInteger) — Zero External Dependencies
#>

param(
    [ValidateSet("Inspect", "BuildUpgradedConfig", "DecryptFile", "EncryptFile", "ApplyToRouter")]
    [string]$Action = "Inspect",
    [string]$InputFile = "$PSScriptRoot\backups\curcfg_backup_original.conf",
    [string]$OutputFile = "$PSScriptRoot\backups\curcfg_upgraded_signed.conf",
    [string]$RouterIP = "192.168.2.1",
    [string]$AdminUser = "admin",
    [string]$AdminPass = "3BB",
    # Customization parameters for BuildUpgradedConfig
    [string]$PrimarySSID = "3bb-wlan",
    [string]$PrimaryPass = "HG630!Admin-2026",
    [switch]$EnableSSID2 = $true,
    [string]$SSID2Name = "Huawei-Guest-Basic",
    [string]$SSID2Pass = "12345678",
    [int]$SSID2MaxClients = 10,
    # Firmware only supports 2 concurrent SSIDs (TR-064 exposes WLANConfiguration_1 & _2 only)
    [switch]$EnableSSID3 = $false,
    [string]$SSID3Name = "Huawei-VIP-Net",
    [string]$SSID3Pass = "12345678",
    [int]$SSID3MaxClients = 15,
    [switch]$EnableSSID4 = $false,
    [string]$SSID4Name = "Huawei-Net-4",
    [string]$SSID4Pass = "12345678",
    [int]$SSID4MaxClients = 15,
    [int]$UploadLimitKbps = 4096,
    [int]$DownloadLimitKbps = 0,
    [int]$MaxConntrack = 2048
)

$ErrorActionPreference = "Stop"

# --- Cryptographic Constants (Confirmed for HG630 V2 V100R001C36B023) ---
$AES256_KEY_HEX = "65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C"
$AES256_IV_HEX  = "85AE4578D5A1BD0758E8349AE0335F0A"
$PWD_KEY_HEX    = "0386DDC2789180D4B9A0CDB52126DEBB"
$PWD_IV_HEX     = "1A5F11D8D619537E23EB9B8FF4A238AF"
$RSA_N_HEX      = "9CFDDA6E973A127866386467435998E77B92E28C345043372260EB60F90D9DA6EC7446A9A475E24E22E3D933DEB157A817E0298EF579B91B7F894BA18C4117EF129458E4FDF5EBF959FD9A6B5D3F337A6EA7F06C03B2CD5F8F7F8BAA6B3605CC21108A97206BE965BC654389C54A71F48C2100D19587F7852E300F8BE0FE09CD"
$RSA_D_HEX      = "3571FA75E1C7E457D6BCE5F97DA537F7BE4B001329101601E41348AE87BB09EBB4DDD4DC95DF87FE7FC43FC277D2B9FBC0BD1088D9AAE9C8A1BF74DEF76785A4D5658602722376B64907DFCB23399F4E7823E839D3559230FC1939630DC6C48B7D36642C2BA3F6B2E0777829590065366B9933E26065A1FF97338095851ED8E5"
$RSA_E_HEX      = "010001"

function Convert-HexToBytes([string]$hex) {
    $b = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) {
        $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $b
}

function Convert-HexToBigInt([string]$hex) {
    if ($hex.Length % 2 -ne 0) { $hex = "0" + $hex }
    $bytes = Convert-HexToBytes $hex
    [Array]::Reverse($bytes)
    $u = New-Object byte[] ($bytes.Length + 1)
    [Array]::Copy($bytes, 0, $u, 0, $bytes.Length)
    return [System.Numerics.BigInteger]::new($u)
}

function Convert-BytesToBigInt([byte[]]$b) {
    $copy = [byte[]]$b.Clone()
    [Array]::Reverse($copy)
    $u = New-Object byte[] ($copy.Length + 1)
    [Array]::Copy($copy, 0, $u, 0, $copy.Length)
    return [System.Numerics.BigInteger]::new($u)
}

function Convert-BigIntToBytes128([System.Numerics.BigInteger]$bi) {
    $arr = $bi.ToByteArray()
    [Array]::Reverse($arr)
    if ($arr.Length -gt 128 -and $arr[0] -eq 0) {
        $arr = $arr[1..($arr.Length - 1)]
    }
    if ($arr.Length -lt 128) {
        $arr = (New-Object byte[] (128 - $arr.Length)) + $arr
    }
    return [byte[]]$arr
}

function Unprotect-HuaweiPwd([string]$b64) {
    if ([string]::IsNullOrWhiteSpace($b64)) { return "" }
    $cipher = [Convert]::FromBase64String($b64)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = Convert-HexToBytes $PWD_KEY_HEX
    $aes.IV  = Convert-HexToBytes $PWD_IV_HEX
    $dec = $aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length)
    return [System.Text.Encoding]::UTF8.GetString($dec).TrimEnd([char]0)
}

function Protect-HuaweiPwd([string]$plain) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
    $blockLen = [Math]::Ceiling(([Math]::Max(1, $bytes.Length)) / 16.0) * 16
    $padded = New-Object byte[] $blockLen
    [Array]::Copy($bytes, 0, $padded, 0, $bytes.Length)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = Convert-HexToBytes $PWD_KEY_HEX
    $aes.IV  = Convert-HexToBytes $PWD_IV_HEX
    $enc = $aes.CreateEncryptor().TransformFinalBlock($padded, 0, $padded.Length)
    $b64 = [Convert]::ToBase64String($enc)
    if ($b64.EndsWith("==")) {
        $ch = $b64[$b64.Length - 3]
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $idx = $alphabet.IndexOf($ch)
        if (($idx % 2) -eq 0) {
            $newCh = $alphabet[$idx + 1]
            $b64 = $b64.Substring(0, $b64.Length - 3) + $newCh + "=="
        }
    }
    return $b64
}

function Get-WpaPskHex([string]$passphrase, [string]$ssid) {
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        [System.Text.Encoding]::UTF8.GetBytes($passphrase),
        [System.Text.Encoding]::UTF8.GetBytes($ssid),
        4096
    )
    $pskBytes = $pbkdf2.GetBytes(32)
    return (($pskBytes | ForEach-Object { $_.ToString("X2") }) -join "")
}

function Expand-Zlib([byte[]]$compressed) {
    # Skip 2-byte zlib header (0x78 0xDA / 0x78 0x9C)
    $ms = New-Object System.IO.MemoryStream($compressed, 2, ($compressed.Length - 2))
    $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    $ds.CopyTo($out)
    $ds.Close()
    return $out.ToArray()
}

function Compress-Zlib([byte[]]$rawBytes) {
    $out = New-Object System.IO.MemoryStream
    # Write standard zlib level-9 header (0x78 0xDA)
    $out.WriteByte(0x78)
    $out.WriteByte(0xDA)
    $ds = New-Object System.IO.Compression.DeflateStream($out, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $ds.Write($rawBytes, 0, $rawBytes.Length)
    $ds.Close()
    # Compute Adler-32 checksum (big-endian)
    [uint32]$a = 1
    [uint32]$b = 0
    foreach ($byte in $rawBytes) {
        $a = ($a + $byte) % 65521
        $b = ($b + $a) % 65521
    }
    [uint32]$adler = ($b -shl 16) -bor $a
    $adlerBytes = [BitConverter]::GetBytes($adler)
    [Array]::Reverse($adlerBytes)
    $out.Write($adlerBytes, 0, 4)
    return $out.ToArray()
}

function Unprotect-HuaweiConfig([string]$confPath) {
    $encBytes = [System.IO.File]::ReadAllBytes($confPath)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = Convert-HexToBytes $AES256_KEY_HEX
    $aes.IV  = Convert-HexToBytes $AES256_IV_HEX
    $decPadded = $aes.CreateDecryptor().TransformFinalBlock($encBytes, 0, $encBytes.Length)
    $decompressed = Expand-Zlib $decPadded

    $xmlAndNullLen = $decompressed.Length - 128
    $xmlAndNull = New-Object byte[] $xmlAndNullLen
    $sigBytes   = New-Object byte[] 128
    [Array]::Copy($decompressed, 0, $xmlAndNull, 0, $xmlAndNullLen)
    [Array]::Copy($decompressed, $xmlAndNullLen, $sigBytes, 0, 128)

    # Verify RSA-1024 signature
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $actualMd5Hex = ($md5.ComputeHash($xmlAndNull) | ForEach-Object { $_.ToString("x2") }) -join ""
    $RSA_N = Convert-HexToBigInt $RSA_N_HEX
    $RSA_E = Convert-HexToBigInt $RSA_E_HEX
    $decSigBytes = Convert-BigIntToBytes128 ([System.Numerics.BigInteger]::ModPow((Convert-BytesToBigInt $sigBytes), $RSA_E, $RSA_N))
    $decSigHex = ($decSigBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    $expectedHex = "0001" + ("ff" * 91) + "003020300c06082a864886f70d020505000410" + $actualMd5Hex

    $sigValid = ($decSigHex -eq $expectedHex)
    $xmlText = [System.Text.Encoding]::UTF8.GetString($xmlAndNull).TrimEnd([char]0)
    return [PSCustomObject]@{
        SignatureValid = $sigValid
        MD5            = $actualMd5Hex
        XmlText        = $xmlText
    }
}

function Protect-HuaweiConfig([string]$xmlText, [string]$outConfPath) {
    # Ensure XML starts with <?xml version="1.0" ?> and ends with trailing null byte
    $xmlBytes = [System.Text.Encoding]::UTF8.GetBytes($xmlText)
    $xmlWithNull = New-Object byte[] ($xmlBytes.Length + 1)
    [Array]::Copy($xmlBytes, 0, $xmlWithNull, 0, $xmlBytes.Length)
    $xmlWithNull[$xmlBytes.Length] = 0

    # Calculate MD5 & Sign with RSA-1024 Private Key (RSA_D)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $md5Hex = ($md5.ComputeHash($xmlWithNull) | ForEach-Object { $_.ToString("x2") }) -join ""
    $sigPlainHex = "0001" + ("ff" * 91) + "003020300c06082a864886f70d020505000410" + $md5Hex
    $RSA_N = Convert-HexToBigInt $RSA_N_HEX
    $RSA_D = Convert-HexToBigInt $RSA_D_HEX
    $sigBytes = Convert-BigIntToBytes128 ([System.Numerics.BigInteger]::ModPow((Convert-HexToBigInt $sigPlainHex), $RSA_D, $RSA_N))

    # Concatenate XML + Null + 128-byte RSA Signature
    $payload = New-Object byte[] ($xmlWithNull.Length + 128)
    [Array]::Copy($xmlWithNull, 0, $payload, 0, $xmlWithNull.Length)
    [Array]::Copy($sigBytes, 0, $payload, $xmlWithNull.Length, 128)

    # Compress with Zlib (0x78 0xDA + Deflate + Adler32)
    $compressed = Compress-Zlib $payload

    # Pad to 16-byte boundary with zero bytes (exact Huawei ATP behavior)
    $rem = $compressed.Length % 16
    $padLen = 16 - $rem
    $padded = New-Object byte[] ($compressed.Length + $padLen)
    [Array]::Copy($compressed, 0, $padded, 0, $compressed.Length)

    # Encrypt with AES-256-CBC
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = Convert-HexToBytes $AES256_KEY_HEX
    $aes.IV  = Convert-HexToBytes $AES256_IV_HEX
    $encConf = $aes.CreateEncryptor().TransformFinalBlock($padded, 0, $padded.Length)

    [System.IO.File]::WriteAllBytes($outConfPath, $encConf)
    return $outConfPath
}

if ($Action -eq "Inspect") {
    $res = Unprotect-HuaweiConfig $InputFile
    Write-Host "[+] Config Decrypted Successfully!" -ForegroundColor Green
    Write-Host "    RSA-1024 Signature Valid : $($res.SignatureValid)"
    Write-Host "    XML Payload MD5          : $($res.MD5)"
    Write-Host "    XML Length               : $($res.XmlText.Length) chars"
}
elseif ($Action -eq "BuildUpgradedConfig") {
    $res = Unprotect-HuaweiConfig $InputFile
    $xml = $res.XmlText

    # 1. Disable IPv6 SLAAC & DHCPv6 Server on LAN to permanently prevent dual-NIC DNS hang
    $xml = $xml -replace '<X_SLAAC\s+RouterAdvertisementEnable="1"', '<X_SLAAC RouterAdvertisementEnable="0"'
    $xml = $xml -replace '<X_DHCPv6\s+DHCPServerEnable="1"', '<X_DHCPv6 DHCPServerEnable="0"'
    $xml = $xml -replace 'IPInterfaceIPAddress="192\.168\.2\.1"', 'IPInterfaceIPAddress="192.168.2.254"'
    $xml = $xml -replace 'X_DtimPeriod="1"', 'X_DtimPeriod="2"'

    # 1b. DHCP hygiene: the Windows gateway (ICS on 192.168.2.1) is the ONLY DHCP/DNS server for the
    #     hotspot LAN — the router's own DHCP must be off to avoid a two-server race. Pool/DNS/lease
    #     values are still normalized in case DHCP is ever re-enabled from the web UI.
    $xml = [regex]::Replace($xml, '(<LANHostConfigManagement[^>]*DHCPServerEnable=")1(")', '${1}0${2}')
    $xml = $xml -replace '(<LANHostConfigManagement[^>]*MaxAddress=")[^"]+(")', '${1}192.168.2.200${2}'
    $xml = $xml -replace '(<LANHostConfigManagement[^>]*DNSServers=")[^"]+(")', '${1}1.1.1.1,8.8.8.8${2}'
    $xml = $xml -replace '(<LANHostConfigManagement[^>]*DHCPLeaseTime=")[^"]+(")', '${1}3600${2}'
    $xml = $xml -replace '(<LANHostConfigManagement[^>]*SubnetMask=")[^"]*(")', '${1}255.255.255.0${2}'

    # 2. Disable TR-069 CWMP ISP Spying / Auto-Reset (acs.3bb.co.th)
    $xml = $xml -replace '<ManagementServer\s+EnableCWMP="1"', '<ManagementServer EnableCWMP="0"'

    # 3. Enable DoS Protection (SYN Flood, ICMP Flood, ARP Attack)
    $xml = $xml -replace '<DosAttack\s+SynFlooding="0"\s+IcmpFlooding="0"\s+ArpAttack="0"\s*/>', '<DosAttack SynFlooding="1" IcmpFlooding="1" ArpAttack="1"/>'

    # 4. Remove WAN Management Exposure (HTTP, SNMP, TELNET on WAN)
    $xml = $xml -replace '<ACLInstance InstanceID="5" X_Service="HTTP" X_Direction="WAN"[^/]*/>', ''
    $xml = $xml -replace '<ACLInstance InstanceID="9" X_Service="SNMP" X_Direction="WAN"[^/]*/>', ''
    $xml = $xml -replace '<ACLInstance InstanceID="10" X_Service="TELNET" X_Direction="WAN"[^/]*/>', ''
    $xml = $xml -replace '<ACL NumberOfInstances="10">', '<ACL NumberOfInstances="7">'

    # 4b. Lock every LAN-side management service (HTTP/FTP/ICMP/TELNET/SNMP/SSH) to the admin PC only.
    #     Empty IP range on an ACL instance = "allow all LAN clients".
    $xml = $xml -replace 'X_Direction="LAN" X_StartIpAddr="" X_EndIpAddr=""', 'X_Direction="LAN" X_StartIpAddr="192.168.2.1" X_EndIpAddr="192.168.2.1"'

    # 5. Enable Auto Scheduled Weekly/Monthly Maintenance Reboot (X_TimeReboot) to clear RAM/logs
    $xml = $xml -replace '<X_TimeReboot\s+Enable="0"\s+Hour="1"\s+Minute="0"\s+Weekday="w1"\s*/>', '<X_TimeReboot Enable="1" Hour="4" Minute="0" Weekday="w1"/>'

    # 6. Unlock GuestNetwork & PowerSave capacity flags in Header
    $xml = $xml -replace '<X_Capacity WIFI="0" GuestNetwork="1" USB="1" PowerSave="1"/>', '<X_Capacity WIFI="1" GuestNetwork="1" USB="1" PowerSave="1"/>'

    # 7. Configure Primary Wi-Fi (SSID 1)
    if ($PrimarySSID -and $PrimaryPass.Length -ge 8) {
        $psk1 = Get-WpaPskHex $PrimaryPass $PrimarySSID
        $encPass1 = Protect-HuaweiPwd $PrimaryPass
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="1"[^>]*SSID=")[^"]+(")', "`${1}$PrimarySSID`${2}")
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="1"[\s\S]*?<PreSharedKeyInstance InstanceID="1" PreSharedKey=")[^"]+(" KeyPassphrase=")[^"]+("/>)', "`${1}$psk1`${2}$encPass1`${3}")
    }

    # 8. Unlock & Configure Second Wi-Fi Network (SSID 2 - Isolated Guest / Hotspot Network!)
    if ($EnableSSID2 -and $SSID2Name -and $SSID2Pass.Length -ge 8) {
        $psk2 = Get-WpaPskHex $SSID2Pass $SSID2Name
        $encPass2 = Protect-HuaweiPwd $SSID2Pass
        $xml = [regex]::Replace($xml, '<WLANConfigurationInstance InstanceID="2" Enable="0" Name="wl0\.1"([^>]*?)SSID="SSID-2" BeaconType="Basic"([^>]*?)X_AssociateDeviceNum="32"([^>]*?)X_WlanIsolateControl="0"', "<WLANConfigurationInstance InstanceID=`"2`" Enable=`"1`" Name=`"wl0.1`"`$1SSID=`"$SSID2Name`" BeaconType=`"WPAand11i`"`$2X_AssociateDeviceNum=`"$SSID2MaxClients`"`$3X_WlanIsolateControl=`"1`"")
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="2"[\s\S]*?<PreSharedKeyInstance InstanceID="1" PreSharedKey=")[^"]+(" KeyPassphrase=")[^"]+("/>)', "`${1}$psk2`${2}$encPass2`${3}")
        # TKIP caps 802.11n at legacy rates and is cryptographically broken — force AES/CCMP only
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="2"[\s\S]*?)X_MixedEncryptionModes="[^"]*"', "`${1}X_MixedEncryptionModes=`"AESEncryption`"")
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="2"[\s\S]*?)WPAEncryptionModes="[^"]*"', "`${1}WPAEncryptionModes=`"AESEncryption`"")
    }

    # 9. Unlock & Configure Third Wi-Fi Network (SSID 3) if requested
    if ($EnableSSID3 -and $SSID3Name -and $SSID3Pass.Length -ge 8) {
        $psk3 = Get-WpaPskHex $SSID3Pass $SSID3Name
        $encPass3 = Protect-HuaweiPwd $SSID3Pass
        $xml = [regex]::Replace($xml, '<WLANConfigurationInstance InstanceID="3" Enable="0" Name="wl0\.2"([^>]*?)SSID="SSID-3" BeaconType="Basic"([^>]*?)X_AssociateDeviceNum="32"([^>]*?)X_WlanIsolateControl="0"', "<WLANConfigurationInstance InstanceID=`"3`" Enable=`"1`" Name=`"wl0.2`"`$1SSID=`"$SSID3Name`" BeaconType=`"WPAand11i`"`$2X_AssociateDeviceNum=`"$SSID3MaxClients`"`$3X_WlanIsolateControl=`"1`"")
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="3"[\s\S]*?<PreSharedKeyInstance InstanceID="1" PreSharedKey=")[^"]+(" KeyPassphrase=")[^"]+("/>)', "`${1}$psk3`${2}$encPass3`${3}")
    }

    # 9b. Unlock & Configure Fourth Wi-Fi Network (SSID 4 - wl0.3)
    if ($EnableSSID4 -and $SSID4Name -and $SSID4Pass.Length -ge 8) {
        $psk4 = Get-WpaPskHex $SSID4Pass $SSID4Name
        $encPass4 = Protect-HuaweiPwd $SSID4Pass
        $xml = [regex]::Replace($xml, '<WLANConfigurationInstance InstanceID="4" Enable="0" Name="wl0\.3"([^>]*?)SSID="SSID-4" BeaconType="Basic"([^>]*?)X_AssociateDeviceNum="32"([^>]*?)X_WlanIsolateControl="0"', "<WLANConfigurationInstance InstanceID=`"4`" Enable=`"1`" Name=`"wl0.3`"`$1SSID=`"$SSID4Name`" BeaconType=`"WPAand11i`"`$2X_AssociateDeviceNum=`"$SSID4MaxClients`"`$3X_WlanIsolateControl=`"1`"")
        $xml = [regex]::Replace($xml, '(<WLANConfigurationInstance InstanceID="4"[\s\S]*?<PreSharedKeyInstance InstanceID="1" PreSharedKey=")[^"]+(" KeyPassphrase=")[^"]+("/>)', "`${1}$psk4`${2}$encPass4`${3}")
    }

    # 9c. Hardware RAM & CPU Booster: Disable 7 heavy background daemons & enable Short GI
    $xml = $xml -replace '<X_SyslogConfig Enable="1" Level="Debug"', '<X_SyslogConfig Enable="0" Level="Error"'
    $xml = $xml -replace '<X_Printer Enable="1"/>', '<X_Printer Enable="0"/>'
    $xml = $xml -replace '<StorageServiceInstance InstanceID="1" Enable="1">', '<StorageServiceInstance InstanceID="1" Enable="0">'
    $xml = $xml -replace '<NetworkServer SMBEnable="1"', '<NetworkServer SMBEnable="0"'
    $xml = $xml -replace '<FTPServer Enable="1">', '<FTPServer Enable="0">'
    $xml = $xml -replace '<X_DmsService Enable="1"', '<X_DmsService Enable="0"'
    $xml = $xml -replace '<X_SNMP Status="1"', '<X_SNMP Status="0"'
    $xml = $xml -replace '<X_UPnP Enable="0" X_TR064Enable="1"/>', '<X_UPnP Enable="0" X_TR064Enable="0"/>'
    $xml = $xml -replace '<X_WANUMTSInterfaceConfig Enable="1">', '<X_WANUMTSInterfaceConfig Enable="0">'
    $xml = $xml -replace 'X_Wlan11NGIControl="long"', 'X_Wlan11NGIControl="short"'
    $xml = $xml -replace '<X_FireWall CurrentLevel="Low">', '<X_FireWall CurrentLevel="High">'

    # 10. Configure QoS QueueManagement & Conntrack Limits
    $qosEnable = if ($UploadLimitKbps -gt 0 -or $DownloadLimitKbps -gt 0) { "1" } else { "0" }
    $xml = [regex]::Replace($xml, '<QueueManagement Enable="0" X_BandWidth="0"([^>]*?)X_ConntrackMax="0"', "<QueueManagement Enable=`"$qosEnable`" X_BandWidth=`"$UploadLimitKbps`"`$1X_ConntrackMax=`"$MaxConntrack`"")

    # Save modified XML for inspection and encrypt/sign into .conf
    $xmlOutPath = $OutputFile -replace '\.conf$', '.xml'
    [System.IO.File]::WriteAllText($xmlOutPath, $xml, (New-Object System.Text.UTF8Encoding($false)))
    $null = Protect-HuaweiConfig $xml $OutputFile

    # Verify the newly generated .conf file!
    $verify = Unprotect-HuaweiConfig $OutputFile
    Write-Host "[+] Upgraded Config Built & Signed Successfully!" -ForegroundColor Green
    Write-Host "    Output .conf File        : $OutputFile ($((Get-Item $OutputFile).Length) bytes)"
    Write-Host "    Output .xml File         : $xmlOutPath"
    Write-Host "    RSA-1024 Signature Valid : $($verify.SignatureValid)"
    Write-Host "    New XML MD5              : $($verify.MD5)"
}
