@echo off
echo ========================================
echo Starting Secure-Click Backend Server
echo ========================================
echo.

cd /d "%~dp0secure-click\backend"

echo Setting Google Safe Browsing API Key...
set SAFE_BROWSING_API_KEY=AIzaSyDOoR_W2klXfNFlJnkwJEvKbKaeT4o8Qxg

echo.
echo Starting server on http://localhost:8000
echo Press Ctrl+C to stop the server
echo.

uvicorn app:app --reload --port 8000

pause

