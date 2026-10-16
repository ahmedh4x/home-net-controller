@echo off
setlocal
title Home Net Controller v0.0.1 - Gateway Network Controller

echo ========================================================
echo   Home Net Controller v0.0.1 - Starting Desktop GUI Controller...
echo ========================================================
echo.

cd /d "%~dp0"

:: Check for python executable in PATH
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in your system PATH.
    echo Please install Python 3.10+ or add it to PATH.
    echo.
    pause
    exit /b 1
)

:: Launch the main Home Net Controller GUI entry point
python "%~dp0main.py" --gui

:: Preserve terminal output if startup or execution encounters an error
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Home Net Controller GUI terminated with exit code %errorlevel%.
    echo.
    pause
)

endlocal
