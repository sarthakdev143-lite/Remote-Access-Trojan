@echo off
set "PYTHON=python"

if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON=%~dp0.venv\Scripts\python.exe"
)

echo Installing dependencies for the local TLS demo...
"%PYTHON%" -m pip install --upgrade pip
"%PYTHON%" -m pip install cryptography
echo Done. You can now run gen_certs.py, server.py, and client.py.
pause
