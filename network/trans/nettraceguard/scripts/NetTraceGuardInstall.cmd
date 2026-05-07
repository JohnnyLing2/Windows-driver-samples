@echo off
setlocal

set ROOT=%~dp0..
set BUILD=%ROOT%\sys\x64\Debug
if not "%1"=="" set BUILD=%1

echo [1/4] Installing driver INF
pnputil /add-driver "%ROOT%\sys\nettraceguard.inf" /install
if errorlevel 1 goto :error

echo [2/4] Starting nettraceguard service
sc start inspect >nul 2>&1

echo [3/4] Registering default adapter-scope and detection registry settings
reg add "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterIfIndex /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterLuidLowPart /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterLuidHighPart /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v BlockTraffic /t REG_DWORD /d 0 /f

echo [4/4] NetTraceGuard install completed
exit /b 0

:error
echo Install failed
exit /b 1
