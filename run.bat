@echo off
title Dhanyah Crypto Utility
echo ===================================================
echo Starting Dhanyah Crypto Utility...
echo FIPS 140-2/3 Level 3 Crypto Token Management & PKI Signer
echo ===================================================

set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

if not exist "%PYTHON_EXE%" (
    where python >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PYTHON_EXE=python"
    ) else (
        echo ERROR: Python 3.11 was not found!
        echo Please ensure Python is installed and added to PATH.
        pause
        exit /b 1
    )
)

start "" "%PYTHON_EXE%" "%~dp0main.py" %*
