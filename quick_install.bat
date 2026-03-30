@echo off
REM Quick install without full build (for changes already compiled)
REM Usage: quick_install.bat
REM This skips the full build process and just installs the APK on running emulator

echo [INFO] Quick Install - APK only (no rebuild)
cd /d "%~dp0"
call gradlew.bat installDebug
if errorlevel 1 (
    echo [ERROR] Installation failed
    exit /b 1
) else (
    echo [OK] App installed successfully!
    echo Waiting for app to appear on emulator...
    timeout /t 3 /nobreak
)
