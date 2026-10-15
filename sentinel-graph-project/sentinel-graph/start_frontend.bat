@echo off
cd /d "%~dp0"
where npm >nul 2>nul
if errorlevel 1 (echo Install Node.js 22.13 or newer for frontend development. & pause & exit /b 1)
if not exist node_modules call npm install
call npm run dev
pause
