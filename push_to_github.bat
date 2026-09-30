@echo off
title Push Dhanyah Crypto Utility to GitHub
echo =========================================================
echo Pushing to GitHub Repository:
echo https://github.com/cacssma/DHANYAH-CRYPTO-TOKEN-UTILITY-PRECISION-HYP-PROXKEY-MTOKEN-INDIA-
echo Author: CA Akash (mail@ca-akash.in)
echo =========================================================
echo.

set "GIT_EXE=C:\Program Files\Git\cmd\git.exe"
if not exist "%GIT_EXE%" (
    where git >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "GIT_EXE=git"
    ) else (
        echo ERROR: Git was not found!
        pause
        exit /b 1
    )
)

echo Attempting push via Git Credential Manager...
"%GIT_EXE%" push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo =========================================================
    echo SUCCESS: Repository successfully pushed to GitHub!
    echo =========================================================
    echo.
    pause
    exit /b 0
)

echo.
echo =========================================================
echo If the push did not complete or prompted for credentials:
echo You can use a GitHub Personal Access Token (PAT).
echo 1. Generate one at: https://github.com/settings/tokens (classic token with 'repo' scope checked)
echo 2. Paste it below:
echo =========================================================
echo.
set /p "GITHUB_TOKEN=Enter your GitHub Token (or press Enter to exit): "

if not "%GITHUB_TOKEN%"=="" (
    echo Pushing using Personal Access Token...
    "%GIT_EXE%" push https://%GITHUB_TOKEN%@github.com/cacssma/DHANYAH-CRYPTO-TOKEN-UTILITY-PRECISION-HYP-PROXKEY-MTOKEN-INDIA-.git main
    if %ERRORLEVEL% equ 0 (
        echo.
        echo =========================================================
        echo SUCCESS: Pushed to GitHub!
        echo =========================================================
    ) else (
        echo.
        echo Push failed. Please verify your token permissions.
    )
)

echo.
pause
