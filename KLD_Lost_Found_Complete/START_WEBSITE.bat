@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed or not on PATH.
  echo Install Node.js LTS from https://nodejs.org/ then double-click this file again.
  pause
  exit /b 1
)
node server.js
if errorlevel 1 (
  echo.
  echo The server stopped because of an error. Please take a screenshot of this window.
  pause
)
