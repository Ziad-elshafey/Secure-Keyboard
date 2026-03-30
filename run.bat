@echo off
REM Quick build and run with default settings
REM Double-click this file to build and run the app

cd /d "%~dp0"

REM Check if emulator is already running
echo [INFO] Checking for running emulator...
adb devices | findstr "emulator" >nul
if errorlevel 1 (
    echo [INFO] No emulator detected. Starting emulator...
    start /B emulator -avd Medium_Phone_API_35 -no-snapshot-load
    echo [INFO] Waiting for emulator to boot...
    adb wait-for-device
    timeout /t 15 /nobreak >nul
    echo [INFO] Emulator ready!
) else (
    echo [INFO] Emulator already running
)

python build_and_run.py -e Medium_Phone_API_35 --clean
pause
