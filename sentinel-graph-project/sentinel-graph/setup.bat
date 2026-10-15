@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (echo Install Python 3.11 or 3.12 with the Python Launcher first. & pause & exit /b 1)
py -3 -m venv .venv
if errorlevel 1 (pause & exit /b 1)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (pause & exit /b 1)
echo Setup complete. Run start_backend.bat, then open http://127.0.0.1:8000
echo For neural training, run setup_ml.bat then train_models.bat.
pause
