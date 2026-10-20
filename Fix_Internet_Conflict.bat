@echo off
title Fix Dual Network (Wi-Fi + Huawei Ethernet) Conflict
echo ============================================================================
echo Fixing IPv6 & DNS Timeout Conflict between Wi-Fi (ZTE) and Ethernet (Huawei)
echo ============================================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID ms_tcpip6 -Confirm:$false; Set-NetIPInterface -InterfaceIndex 8 -AddressFamily IPv4 -InterfaceMetric 500; Set-DnsClientServerAddress -InterfaceIndex 8 -ResetServerAddresses; Set-DnsClientServerAddress -InterfaceIndex 18 -ServerAddresses ('1.1.1.1','8.8.8.8','192.168.1.1'); Disable-NetAdapterBinding -Name 'Wi-Fi' -ComponentID ms_tcpip6 -Confirm:$false; ipconfig /flushdns"
echo.
echo [DONE] All websites will now open instantly over Wi-Fi while Huawei Ethernet stays connected!
pause
