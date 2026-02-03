@echo off
REM Ultra-fast build - Only Kotlin compilation, no lint/test/full build
REM Usage: super_fast.bat
REM Use when you only changed Kotlin code (no resources/manifest)

echo [SUPER FAST] Code-only build...
cd /d "%~dp0"

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
