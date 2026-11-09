@echo off
rem Double-click / cmd.exe entry point: runs the PowerShell installer without
rem changing the machine execution policy. Arguments pass through, e.g.
rem   install-windows.cmd -DryRun
rem   install-windows.cmd -Uninstall
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1" %*
set "rc=%ERRORLEVEL%"
if not "%rc%"=="0" echo Install failed with exit code %rc%.
if "%~1"=="" pause
exit /b %rc%
