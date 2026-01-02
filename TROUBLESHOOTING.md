# Troubleshooting Guide

## "Failed to fetch" Error in Service Worker

This error means the extension cannot connect to the backend server. Follow these steps:

### Step 1: Verify Backend is Running

1. Open a terminal/PowerShell
2. Navigate to the backend directory:
   ```bash
   cd secure-click/backend
   ```

3. Check if the backend is running by testing the health endpoint:
   ```bash
   curl http://localhost:8000/health
   ```
   
   **Expected response:**
   ```json
   {"status":"ok","time":1234567890}
   ```

4. If you get a connection error, start the backend:
   ```bash
   # Windows PowerShell
   $env:SAFE_BROWSING_API_KEY="AIzaSyDOoR_W2klXfNFlJnkwJEvKbKaeT4o8Qxg"
   uvicorn app:app --reload --port 8000
   
   # macOS/Linux
   export SAFE_BROWSING_API_KEY="AIzaSyDOoR_W2klXfNFlJnkwJEvKbKaeT4o8Qxg"
   uvicorn app:app --reload --port 8000
   ```

### Step 2: Check Backend Console Output

When you start the backend, you should see:
```
[Secure-Click] Google Safe Browsing API enabled (key: AIzaSyDOoR_...)
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

If you see:
```
[Secure-Click] Google Safe Browsing API disabled (set SAFE_BROWSING_API_KEY env var to enable)
```
Then the API key is not set correctly.

### Step 3: Verify Extension Can Reach Backend

1. Open Chrome and go to `chrome://extensions/`
2. Find "Secure-Click" extension
3. Click "Service worker" (or "Inspect views: service worker")
4. This opens the DevTools console for the service worker
5. You should see logs like:
   ```
   Secure-Click service worker loaded
   [Secure-Click] Fetching prediction for https://example.com
   ```

### Step 4: Test Backend Manually

Test the backend API directly:

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "run_safe_browsing": true}'
```

**Expected response:**
```json
{
  "url": "https://example.com",
  "score": 0.1234,
  "label": 0,
  "reason": "...",
  "google_safe": false,
  "ts": 1234567890
}
```

### Step 5: Check Extension Console

1. Open Chrome DevTools (F12)
2. Go to Console tab
3. Visit a website
4. You should see logs like:
   ```
   [Secure-Click] Fetching prediction for https://example.com
   [Secure-Click] Cached result for https://example.com: score=0.123, label=0
   [Secure-Click] updateBadge for tab 123, URL: https://example.com, domain: example.com, score: 0.123, label: 0
   ```

### Common Issues

#### Issue 1: Backend Not Running
**Solution:** Start the backend server (see Step 1)

#### Issue 2: Wrong Port
**Solution:** Ensure backend is on port 8000, or update `service_worker.js` line 6 to match your port

#### Issue 3: Firewall Blocking
**Solution:** Allow Python/uvicorn through Windows Firewall

#### Issue 4: CORS Error
**Solution:** Backend already has CORS enabled. If you still see CORS errors, check that backend is running and accessible

#### Issue 5: API Key Not Working
**Solution:** 
1. Verify the environment variable is set: `echo $env:SAFE_BROWSING_API_KEY` (PowerShell) or `echo $SAFE_BROWSING_API_KEY` (bash)
2. Restart the backend after setting the environment variable
3. Check backend console for the Safe Browsing status message

### Quick Test

1. Start backend with API key
2. Reload extension in Chrome
3. Visit: `https://testsafebrowsing.appspot.com/s/malware.html` (Google's test page)
4. Check extension popup - should show as malicious
5. Check dashboard - should show `google_safe: true` in details

