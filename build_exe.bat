@echo off
title Build Dhanyah Crypto Utility Standalone Executable
echo =========================================================
echo Compiling Dhanyah Crypto Utility into Standalone Windows EXE
echo =========================================================

set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"

if not exist "%PYTHON_EXE%" (
    where python >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PYTHON_EXE=python"
    ) else (
        echo ERROR: Python was not found!
        pause
        exit /b 1
    )
)

echo Cleaning previous build artifacts...
if exist "dist\DhanyahCryptoUtility" rmdir /s /q "dist\DhanyahCryptoUtility"
if exist "build" rmdir /s /q "build"

echo Compiling via PyInstaller...
"%PYTHON_EXE%" -m PyInstaller DhanyahCryptoUtility.spec --noconfirm

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED! Check output above.
    pause
    exit /b %ERRORLEVEL%
)

echo Copying standalone drivers into output directory...
xcopy /E /I /Y "drivers" "dist\DhanyahCryptoUtility\drivers" >nul

echo.
echo =========================================================
echo BUILD SUCCESSFUL!
echo Portable application output location:
echo %~dp0dist\DhanyahCryptoUtility\DhanyahCryptoUtility.exe
echo =========================================================
echo.
pause
