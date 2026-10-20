@echo off
chcp 65001 >nul
title Huawei HG630 Hotspot System — Installer
echo ============================================================
echo   نظام الهوت سبوت لراوتر Huawei HG630 V2 — التثبيت
echo ============================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [i] طلب صلاحيات الأدمن...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set ROOT=%~dp0

echo [1/6] إضافة استثناء Windows Defender لمحرك الحماية...
powershell -NoProfile -Command "try { $p = Get-MpPreference; if (($p.ExclusionPath) -notcontains '%ROOT%engine') { Add-MpPreference -ExclusionPath '%ROOT%engine'; Write-Host '    تم' } else { Write-Host '    موجود مسبقا' } } catch { Write-Host '    تخطي' }"

echo [2/6] تسجيل محرك الحماية كتاسك تشغيل تلقائي مرتفع الصلاحيات...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"& ''%ROOT%engine\Gateway_Engine.ps1''\"'; $trigger = New-ScheduledTaskTrigger -AtLogOn; $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest; Register-ScheduledTask -TaskName 'Huawei_Gateway_Engine' -Action $action -Trigger $trigger -Principal $principal -Description 'Hotspot enforcement engine (WinDivert)' -Force | Out-Null; Write-Host '    تم'"

echo [3/6] تسجيل سيرفر الويب (تشغيل تلقائي عند الدخول)...
powershell -NoProfile -Command "$s = (New-Object -ComObject WScript.Shell).CreateShortcut(([Environment]::GetFolderPath('Startup')) + '\Huawei_Hotspot_Web.lnk'); $s.TargetPath = '%ROOT%Start_Hotspot.bat'; $s.Arguments = 'silent'; $s.WindowStyle = 7; $s.Save(); Write-Host '    تم'"

echo [4/6] ضبط مشاركة الإنترنت (ICS) على 192.168.2.1...
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%ROOT%Setup_Gateway_Nat.ps1'" 2>nul

echo [5/6] تشغيل السيرفر والمحرك...
if not exist "%ROOT%Huawei_Arabic_System\data\db.json" (
    copy /y "%ROOT%Huawei_Arabic_System\data\db.sample.json" "%ROOT%Huawei_Arabic_System\data\db.json" >nul
)
powershell -NoProfile -Command "if (-not (Get-NetTCPConnection -LocalPort 8630 -State Listen -ErrorAction SilentlyContinue)) { Start-Process powershell.exe -ArgumentList '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%ROOT%Live_Router_Server.ps1\"' }"
powershell -NoProfile -Command "Start-ScheduledTask -TaskName 'Huawei_Gateway_Engine'" 2>nul

echo [6/6] فتح لوحة الإدارة...
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8630/"

echo.
echo ============================================================
echo   تم التثبيت!
echo   لوحة الأدمن:  http://192.168.2.1  (admin / 3BB)
echo   بوابة العملاء: http://192.168.2.1/portal
echo   باسورد واي فاي الأدمن الافتراضي: HG630!Admin-2026
echo   باسورد واي فاي العملاء الافتراضي: 12345678
echo ============================================================
pause
