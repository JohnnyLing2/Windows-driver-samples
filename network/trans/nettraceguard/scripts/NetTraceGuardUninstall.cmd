@echo off
setlocal

echo Stopping service
sc stop inspect >nul 2>&1
sc stop nettraceguard >nul 2>&1

echo Removing driver package by INF
pnputil /delete-driver nettraceguard.inf /uninstall /force >nul 2>&1

reg delete "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterIfIndex /f >nul 2>&1
reg delete "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterLuidLowPart /f >nul 2>&1
reg delete "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterLuidHighPart /f >nul 2>&1

echo NetTraceGuard uninstall completed
exit /b 0
