@echo off
echo Testing Secure-Click Backend...
echo.

echo Testing health endpoint...
curl http://localhost:8000/health
echo.
echo.

echo Testing predict endpoint...
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" -d "{\"url\": \"https://example.com\", \"run_safe_browsing\": true}"
echo.
echo.

pause

