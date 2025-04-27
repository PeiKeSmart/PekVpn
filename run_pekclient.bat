@echo off
:: Get the directory where the batch file is located
set "SCRIPT_DIR=%~dp0"

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Starting PekVpn client with administrator rights...
echo Using client from: %SCRIPT_DIR%

:: Run PekVpn client from the same directory as the batch file
"%SCRIPT_DIR%pekclient.exe" -server 113.57.110.92:23456

pause
