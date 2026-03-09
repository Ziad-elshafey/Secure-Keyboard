@echo off
REM Ultra-fast build - Only Kotlin compilation, no lint/test/full build
REM Usage: super_fast.bat
REM Use when you only changed Kotlin code (no resources/manifest)

echo [SUPER FAST] Code-only build...
cd /d "%~dp0"

REM ── Ensure emulator is running ──
set "EMULATOR=%LOCALAPPDATA%\Android\sdk\emulator\emulator.exe"
set "ADB=%LOCALAPPDATA%\Android\sdk\platform-tools\adb.exe"
set "AVD_NAME=Medium_Phone_API_35"

"%ADB%" devices 2>nul | findstr /R "emulator-.*device" >nul 2>&1
if errorlevel 1 (
    echo [INFO] No emulator detected — launching %AVD_NAME%...
    start "" "%EMULATOR%" -avd %AVD_NAME% -no-snapshot-load -dns-server 8.8.8.8
    echo [INFO] Waiting for emulator to boot...
    "%ADB%" wait-for-device
    :WAIT_BOOT
    for /f "tokens=*" %%A in ('"%ADB%" shell getprop sys.boot_completed 2^>nul') do set BOOT=%%A
    if not "%BOOT%"=="1" (
        timeout /t 2 /nobreak >nul
        goto WAIT_BOOT
    )
    echo [OK] Emulator is ready
) else (
    echo [OK] Emulator already running
)

call gradlew.bat :app:compileDebugKotlin --daemon --build-cache
if errorlevel 1 (
    echo [ERROR] Kotlin compilation failed
    exit /b 1
)

echo [INFO] Installing...
call gradlew.bat installDebug --daemon
if errorlevel 1 (
    echo [ERROR] Install failed
    exit /b 1
)

echo [OK] Done!
