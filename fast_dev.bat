@echo off
REM Fast Development Loop - Build and Install (skips emulator startup)
REM Usage: fast_dev.bat
REM For use when emulator is already running. Just rebuilds and reinstalls.

echo [INFO] Fast Dev Loop - Building and Installing...
cd /d "%~dp0"

echo [INFO] Building app (incremental)...
call gradlew.bat assembleDebug -x lint -x test --daemon --build-cache
if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)

echo [INFO] Installing on emulator...
call gradlew.bat installDebug --daemon
if errorlevel 1 (
    echo [ERROR] Installation failed
    exit /b 1
) else (
    echo [OK] App installed!
)
