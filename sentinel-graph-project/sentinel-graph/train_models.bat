@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
if errorlevel 1 (echo Run setup.bat first. & pause & exit /b 1)
python -m backend.detection.train_model
echo Restart the backend after successful training to load new weights.
pause
