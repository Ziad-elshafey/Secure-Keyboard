@echo off
REM Automated Android App Build and Emulator Runner for Windows
REM This batch script provides a quick way to build and run the keyboard app

setlocal enabledelayedexpansion

REM Configuration
set PYTHON_CMD=python
set SCRIPT_NAME=build_and_run.py

REM Colors (using findstr workaround)
set FAIL=[91m
set SUCCESS=[92m
set INFO=[96m
set RESET=[0m

echo.
echo ========================================
echo  Android App Builder
echo ========================================
echo.

REM Check if Python is available
%PYTHON_CMD% --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.6+ or add it to your PATH
    pause
    exit /b 1
)

REM Check if script exists
if not exist "%SCRIPT_NAME%" (
    echo Error: %SCRIPT_NAME% not found in current directory
    pause
    exit /b 1
)

REM Run the Python script with all arguments
%PYTHON_CMD% "%SCRIPT_NAME%" %*

if %errorlevel% neq 0 (
    echo.
    echo Build or installation failed
    pause
    exit /b 1
)

echo.
pause
