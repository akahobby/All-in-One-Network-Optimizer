@echo off
setlocal EnableExtensions

rem === self-elevate if not admin (prevents a separate PowerShell window) ===
>nul 2>&1 net session
if %errorlevel% neq 0 (
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

title Network Optimizer (All-in-One) [Admin]
rem default console colors: white on black
color 07

set "CORE=%~dp0network-optimizer-core.ps1"
set "PS=powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CORE%""

:menu
cls
echo ============================================================
echo [36m   Network Optimizer [Admin]   ^|  Ethernet + WiFi[0m
echo ============================================================
echo.
echo [33m 1.[0m [37m TCP Autotuning and Datagram Threshold[0m
echo [33m 2.[0m [37m Apply Advanced + NIC registry tweaks   (incl. extras)[0m
echo [33m 3.[0m [37m Adapter Bindings   [status / stubs][0m
echo [33m 4.[0m [37m APPLY ALL   (congestion + TCP mode + advanced + extras)[0m
echo ------------------------------------------------------------
echo [33m 5.[0m [37m Show current Advanced / Power / TCP status[0m
echo [33m 6.[0m [37m Full Restore   (TCP Normal + remove AFD tweak)[0m
echo [33m 7.[0m [37m View change log[0m
echo ------------------------------------------------------------
echo [31m 8. Exit[0m
echo ============================================================
echo.
set /p choice="[37mChoose 1-8: [0m"

if "%choice%"=="1" %PS% -Action Set-TcpMode
if "%choice%"=="2" %PS% -Action Adv-Apply
if "%choice%"=="3" %PS% -Action Bindings-Status
if "%choice%"=="4" %PS% -Action Apply-All
if "%choice%"=="5" %PS% -Action Show-TcpStatus
if "%choice%"=="6" %PS% -Action Full-Restore
if "%choice%"=="7" (
  if exist "%ProgramData%\NetworkOptimizer.log" ( start "" notepad "%ProgramData%\NetworkOptimizer.log" ) else ( echo No log yet. )
  echo.
  pause
  goto :menu
)
if "%choice%"=="8" exit /b

echo.
pause
goto :menu
