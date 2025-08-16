@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: -----------------------------------------------------------------
:: Self-elevate to Administrator when double-clicked
:: Uses FLTMC (admin-only). If not admin, relaunch this same .BAT
:: elevated and exit. No marker args, so %~dp0 stays correct.
:: -----------------------------------------------------------------
fltmc >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)

:: ---- Paths ----
title Network Optimizer [Admin]  ^|  Ethernet + WiFi
set "ROOT=%~dp0"
set "CORE=%ROOT%network-optimizer-core.ps1"
set "PS=powershell -NoProfile -ExecutionPolicy Bypass -File"
set "LOGFILE=%ProgramData%\NetworkOptimizer.log"

if not exist "%CORE%" (
  echo [ERROR] Missing core: "%CORE%"
  echo Make sure network-optimizer-core.ps1 is in the same folder.
  echo.
  pause
  exit /b 1
)

:: ---- ANSI accents for menu ----
for /F "delims=" %%A in ('echo prompt $E^| cmd') do set "ESC=%%A"
set "RST=%ESC%[0m"
set "B=%ESC%[1m"
set "CYAN=%ESC%[96m"
set "YELL=%ESC%[93m"
set "GRAY=%ESC%[90m"
set "RED=%ESC%[91m"

:menu
cls
echo %CYAN%%B%============================================================%RST%
echo %CYAN%%B%   Network Optimizer [Admin]   ^|   Ethernet + WiFi%RST%
echo %CYAN%%B%============================================================%RST%
echo %GRAY%(Apply All will ask for Auto-Tuning + Congestion. NIC tweaks are optional.)%RST%
echo.
echo   %YELL%1.%RST% Advanced (SAFE) - core TCP/registry only
echo   %YELL%2.%RST% Apply NIC Tweaks (AGGRESSIVE / OPT-IN)
echo       %GRAY%TIP: If your adapter drops or misbehaves, run option 3 to restore.%RST%
echo   %YELL%3.%RST% Restore NIC Tweaks (from last backup)
echo   %YELL%4.%RST% APPLY ALL (full + optional NIC tweaks)
echo   %GRAY%------------------------------------------------------------%RST%
echo   %YELL%5.%RST% Show current Advanced / Power / TCP status
echo   %YELL%6.%RST% Full Restore (TCP Normal + remove AFD)
echo   %YELL%7.%RST% View change log
echo   %YELL%8.%RST% Adapter Bindings [status / stub]
echo   %GRAY%------------------------------------------------------------%RST%
echo   %RED%9.%RST% Exit
echo %CYAN%%B%============================================================%RST%
echo.

choice /C 123456789 /N /M "Choose 1-9: "
set "ch=%errorlevel%"

if "%ch%"=="1" goto do_adv
if "%ch%"=="2" goto do_nic_apply
if "%ch%"=="3" goto do_nic_restore
if "%ch%"=="4" goto do_all
if "%ch%"=="5" goto do_tcp_status
if "%ch%"=="6" goto do_full_restore
if "%ch%"=="7" goto do_view_log
if "%ch%"=="8" goto do_bindings_status
if "%ch%"=="9" goto bye
goto menu

:do_adv
%PS% "%CORE%" -Action Adv-Apply
goto hold

:do_nic_apply
%PS% "%CORE%" -Action Apply-NicTweaks
goto hold

:do_nic_restore
%PS% "%CORE%" -Action Restore-NicTweaks
goto hold

:do_all
%PS% "%CORE%" -Action Apply-All
echo.
choice /C YN /N /M "Also apply NIC tweaks (Y/N)? "
if errorlevel 2 goto do_all_skip
if errorlevel 1 goto do_all_yes

:do_all_yes
echo.
%PS% "%CORE%" -Action Apply-NicTweaks
goto hold

:do_all_skip
echo.
echo %GRAY%[Skipped NIC tweaks]%RST%
goto hold

:do_tcp_status
%PS% "%CORE%" -Action Show-TcpStatus
goto hold

:do_full_restore
%PS% "%CORE%" -Action Full-Restore
goto hold

:do_view_log
if exist "%LOGFILE%" (
  start "" notepad "%LOGFILE%"
) else (
  echo %GRAY%No log yet. Expected at: %LOGFILE%%RST%
  echo.
  pause
)
goto menu

:do_bindings_status
%PS% "%CORE%" -Action Bindings-Status
goto hold

:hold
echo.
echo %GRAY%Press any key to return to the menu...%RST%
pause >nul
goto menu

:bye
echo.
echo %GRAY%Exiting Network Optimizer...%RST%
pause
endlocal & exit /b 0
