@echo off
setlocal
cd /d "%~dp0\.."

echo [Home Net Controller Build Pipeline] Starting PyInstaller Windows Build...

python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PyInstaller is not installed. Installing...
    pip install pyinstaller
)

echo [Home Net Controller Build Pipeline] Cleaning previous build outputs...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [Home Net Controller Build Pipeline] Compiling standalone package...
python -m PyInstaller hnc.spec --clean --noconfirm

if exist "dist\HomeNetController\HomeNetController.exe" (
    echo [SUCCESS] Windows executable built successfully at dist\HomeNetController\HomeNetController.exe
) else (
    echo [ERROR] Build failed. Check compiler output above.
    exit /b 1
)

endlocal
