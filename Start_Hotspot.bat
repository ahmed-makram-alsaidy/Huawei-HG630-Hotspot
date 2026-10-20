@echo off
chcp 65001 >nul
title Huawei HG630 Hotspot — Web Server
powershell -NoProfile -WindowStyle Hidden -Command "if (-not (Get-NetTCPConnection -LocalPort 8630 -State Listen -ErrorAction SilentlyContinue)) { Start-Process powershell.exe -ArgumentList '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%~dp0Live_Router_Server.ps1\"' }"
if /i "%~1"=="silent" exit /b
timeout /t 1 /nobreak >nul
start "" "http://127.0.0.1:8630/"
