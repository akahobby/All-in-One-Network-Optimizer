@echo off
setlocal EnableExtensions
title Network Optimizer (All-in-One) + Wi-Fi + Change-Only Logging
color 0A

:: -------- paths --------
set "SCRIPT_DIR=%~dp0"
set "CORE=%SCRIPT_DIR%network-optimizer-core.ps1"
set "LOGPATH=%ProgramData%\NetworkOptimizer.log"

if not exist "%CORE%" (
  echo [!] Can't find "%CORE%".
  echo     Save network-optimizer-core.ps1 in the same folder as this BAT.
  echo.
  pause
  exit /b 1
)

:: -------- elevation --------
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting administrator rights...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath 'cmd.exe' -Verb RunAs -ArgumentList '/c','\"\"%~f0\"\"' -Wait"
  exit /b
)

if not exist "%LOGPATH%" ( type nul > "%LOGPATH%" )

:menu
cls
echo ============================================================
echo         Network Optimizer - Ethernet + Wi-Fi [Admin]
echo ============================================================
echo  1. TCP Autotuning and Datagram Threshold
echo  2. Apply Advanced and Power now  + NIC registry tweaks
echo  3. Adapter Bindings  disable, restore, status
echo  4. APPLY ALL  choose congestion + TCP mode, then bindings and advanced
echo ------------------------------------------------------------
echo  5. Show current Advanced and Power per adapter
echo  6. Full Restore  TCP Normal + restore both backups
echo  7. View change log
echo  8. Exit
echo.
set /p sel="Choose 1-8: "
if "%sel%"=="1" goto tcp
if "%sel%"=="2" goto apply_now
if "%sel%"=="3" goto bindings
if "%sel%"=="4" goto applyall
if "%sel%"=="5" goto showadv
if "%sel%"=="6" goto fullrestore
if "%sel%"=="7" goto viewlog
if "%sel%"=="8" goto end
goto menu

:apply_now
cls
echo Applying NIC registry tweaks...
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" PerfRegs-Apply
echo.
echo Applying Advanced and Power profile...
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Adv-Apply
echo.
echo [+] Done.
echo.
pause
goto menu

:tcp
cls
echo ================= TCP Menu =================
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Show-TcpStatus
echo.
echo  1. Disable autotuning  + FastSendDatagramThreshold = 409600
echo  2. NORMAL autotuning   + remove FastSendDatagramThreshold
echo  3. HIGHLYRESTRICTED    + FastSendDatagramThreshold = 409600
echo     keeps bandwidth closer to normal but may not stabilize as well as Disabled
echo ------------------------------------------------------------
echo  4. Set TCP Congestion Provider...
echo  5. Back
echo.
set /p tsel="Choose 1-5: "
if "%tsel%"=="5" goto menu
if "%tsel%"=="4" goto cong
if "%tsel%"=="3" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-TcpMode HighlyRestricted & echo.& pause & goto tcp
if "%tsel%"=="2" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-TcpMode Normal            & echo.& pause & goto tcp
if "%tsel%"=="1" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-TcpMode Disabled          & echo.& pause & goto tcp
goto tcp

:cong
cls
echo ============ TCP Congestion Provider ============
echo  1. BBR2   ^(best performing - Windows 11 24H2+^)
echo  2. CUBIC  ^(default^)
echo  3. NewReno ^(test^)
echo  4. Back
echo.
set /p csel="Choose 1-4: "
if "%csel%"=="4" goto tcp
if "%csel%"=="1" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-Congestion BBR2   & echo.& pause & goto cong
if "%csel%"=="2" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-Congestion CUBIC  & echo.& pause & goto cong
if "%csel%"=="3" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-Congestion NewReno & echo.& pause & goto cong
goto cong

:bindings
cls
echo =============== Adapter Bindings Menu ===============
echo Targets physical Ethernet and Wi-Fi adapters  skips virtual or Bluetooth.
echo.
echo  1. Disable selected bindings  backup saved
echo  2. Restore from latest backup
echo  3. Show current binding status
echo  4. List detected adapters
echo  5. Back
echo.
set /p bsel="Choose 1-5: "
if "%bsel%"=="5" goto menu
if "%bsel%"=="4" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Adapters-List   & echo.& pause & goto bindings
if "%bsel%"=="3" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Bindings-Status  & echo.& pause & goto bindings
if "%bsel%"=="2" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Bindings-Restore & echo.& pause & goto bindings
if "%bsel%"=="1" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Bindings-Disable & echo.& pause & goto bindings
goto bindings

:applyall
cls
echo ========= APPLY ALL =========
echo First choose a TCP congestion provider:
echo  1. BBR2   ^(best performing - Windows 11 24H2+^)
echo  2. CUBIC  ^(default^)
echo  3. NewReno ^(test^)
echo  4. Skip  ^(leave current provider^)
echo  5. Back
echo.
set /p cpsel="Choose 1-5: "
if "%cpsel%"=="5" goto menu
if "%cpsel%"=="1" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-Congestion BBR2   & set "CPSET=1"
if "%cpsel%"=="2" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-Congestion CUBIC  & set "CPSET=1"
if "%cpsel%"=="3" powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-Congestion NewReno & set "CPSET=1"
if "%cpsel%"=="4" set "CPSET=1"
if not defined CPSET (
  echo Invalid choice.
  timeout /t 1 >nul
  goto applyall
)

echo.
echo Now choose autotuning mode to use with the full profile:
echo  1. DISABLED          ^(max stability, may reduce bandwidth^)
echo  2. HIGHLYRESTRICTED  ^(closer to normal bandwidth^)
echo  3. NORMAL            ^(no TCP tuning; still applies NIC changes^)
echo  4. Back
echo.
set /p amode="Choose 1-4: "
if "%amode%"=="4" goto menu

set "MODE="
if "%amode%"=="1" set "MODE=Disabled"
if "%amode%"=="2" set "MODE=HighlyRestricted"
if "%amode%"=="3" set "MODE=Normal"

if not defined MODE (
  echo Invalid choice.
  timeout /t 1 >nul
  goto applyall
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Set-TcpMode %MODE%
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Bindings-Disable
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" PerfRegs-Apply
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Adv-Apply
echo.
echo [+] APPLY ALL complete.
echo.
pause
goto menu

:showadv
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Adv-Show
echo.
pause
goto menu

:fullrestore
powershell -NoProfile -ExecutionPolicy Bypass -File "%CORE%" Full-Restore
echo.
pause
goto menu

:viewlog
start "" notepad "%LOGPATH%"
goto menu

:end
echo.
echo Press any key to close...
pause >nul
endlocal
exit /b
