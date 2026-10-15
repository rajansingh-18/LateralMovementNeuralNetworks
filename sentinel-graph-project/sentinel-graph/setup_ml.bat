@echo off
cd /d "%~dp0"
call .venv\Scripts\activate.bat
if errorlevel 1 (echo Run setup.bat first. & pause & exit /b 1)
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
pause
