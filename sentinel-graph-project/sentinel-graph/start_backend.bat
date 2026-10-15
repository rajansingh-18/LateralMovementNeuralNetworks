@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
if errorlevel 1 (echo Run setup.bat first. & pause & exit /b 1)
echo Open http://127.0.0.1:8000 in your browser. Press Ctrl+C to stop.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
pause
