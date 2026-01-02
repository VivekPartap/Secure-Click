<<<<<<< HEAD
# Secure-Click 🔒

Secure-Click is a browser extension that automatically detects phishing and malicious URLs in real-time using machine learning. It provides a local backend API, a React dashboard for viewing scan history, and a Chrome extension that analyzes URLs as you browse.

## Features

- 🛡️ **Real-time URL Analysis**: Automatically scans URLs as you browse
- 🤖 **Machine Learning Detection**: Uses optimized ensemble of XGBoost, Logistic Regression, and Random Forest models trained on phishing datasets
- 📊 **Dashboard**: React-based dashboard to view scan history and statistics
- 🚨 **Badge Notifications**: Visual indicators for malicious sites
- 💾 **Local Storage**: All data stored locally using SQLite
- 🔄 **Caching**: Intelligent caching to reduce API calls
- 🌐 **CORS-enabled API**: FastAPI backend with CORS support

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8+** ([Download Python](https://www.python.org/downloads/))
- **Node.js 16+** and npm ([Download Node.js](https://nodejs.org/))
- **Google Chrome** (for the extension)
- **Git** (optional, for cloning the repository)

## Project Structure

```
secure-click/
├── backend/              # FastAPI backend server
│   ├── app.py           # Main API application
│   ├── models/          # ML model files (generated after training)
│   │   ├── model_xgb.joblib
│   │   ├── model_lr.joblib
│   │   ├── model_rf.joblib
│   │   ├── url_vectorizer.joblib
│   │   └── ensemble_weights.json
│   ├── env.example      # Template for backend environment variables
│   ├── db.sqlite        # SQLite database (created automatically)
│   └── requirements.txt # Python dependencies
├── dashboard/           # React dashboard
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   └── index.js
│   └── package.json
├── extension/           # Chrome extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── service_worker.js
│   └── icons/
├── ml/                  # Machine learning training scripts
│   └── train.py
└── data/                # Training datasets
    ├── malicious_phish.csv
    ├── PhiUSIIL_Phishing_URL_Dataset.csv
    └── secureclick_dataset.csv
```

## Installation

### 1. Clone the Repository (if using Git)

```bash
git clone <repository-url>
cd Secure-Click/secure-click
```

### 2. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

**Note**: On some systems, you may need to use `pip3` instead of `pip`.

### 3. Install Dashboard Dependencies

```bash
cd ../dashboard
npm install
```

### 4. Train the Machine Learning Model

The backend requires trained model files. If they don't exist in `backend/models/`, you need to train the model first:

```bash
cd ../ml
python train.py
```

This will:
- Load training data from the `data/` directory
- Train an XGBoost classifier
- Save the model and vectorizer to `backend/models/`

**Note**: Training may take several minutes depending on your system and dataset size.

## Running the Application

### Step 1: Start the Backend Server

Before starting the server:

1. Copy `backend/env.example` to `backend/.env`.
2. Update `.env` with the API keys you want to use:
   - `SAFE_BROWSING_API_KEY` (optional, enables the Google Safe Browsing checks)
   - `VIRUSTOTAL_API_KEY` (optional, enables VirusTotal lookups)
   - `SAFE_BROWSING_TTL_SECONDS` (ie. cache duration, default `3600`)

The backend loads `backend/.env` automatically via `python-dotenv`, so those values are in effect whenever you run `uvicorn app:app`.

**Windows (Easiest Method):**
1. Double-click `START_BACKEND.bat` from the project root to launch the server with the `.env` values.
2. You should see log output about the enabled APIs and Uvicorn listening on `http://127.0.0.1:8000`.

**Manual Method (Windows PowerShell):**
```
cd secure-click/backend
# Optional: override any `.env` value for the current session
$env:SAFE_BROWSING_API_KEY="AIzaSyDOoR_W2klXfNFlJnkwJEvKbKaeT4o8Qxg"
$env:VIRUSTOTAL_API_KEY="3dd819ac94e385f1ab2e6f76ef745d65f3b8967a7028b87a84fbee52e6327400"
uvicorn app:app --reload --port 8000
```

**Manual Method (macOS/Linux):**
```
cd secure-click/backend
# Optional: override any `.env` value for the current session
export SAFE_BROWSING_API_KEY="YOUR_KEY"
export VIRUSTOTAL_API_KEY="YOUR_KEY"
uvicorn app:app --reload --port 8000
```

You should see output indicating the server is running:
```
[Secure-Click] Google Safe Browsing API enabled (key: AIzaSy...)
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

The API will be available at `http://localhost:8000`

**Verify Backend is Running:**
- Open `http://localhost:8000/health` in your browser - should return `{"status":"ok","time":...}`
- Or double-click `TEST_BACKEND.bat` to test the endpoints

### Step 2: Start the Dashboard

Open a **new terminal** and navigate to the dashboard directory:

```bash
cd secure-click/dashboard
npm start
```

The dashboard will open automatically in your browser at `http://localhost:3000`

### Step 3: Load the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Navigate to and select the `secure-click/extension` folder
5. The Secure-Click extension should now appear in your extensions list

## Usage

### Browser Extension

1. **Automatic Scanning**: The extension automatically scans URLs as you browse. When you visit a website, it will analyze the URL in the background.$env:VIRUSTOTAL_API_KEY="3dd819ac94e385f1ab2e6f76ef745d65f3b8967a7028b87a84fbee52e6327400"

2. **View Results**: Click the Secure-Click extension icon in your browser toolbar to view the scan results for the current tab.

3. **Badge Indicators**: 
   - A red "!" badge appears on malicious/suspicious sites
   - No badge indicates the site is likely safe

4. **Notifications**: You'll receive a notification when a malicious site is detected.

### Dashboard

1. Open the dashboard at `http://localhost:3000`
2. View scan statistics (Total Scans, Safe, Malicious)
3. Browse the recent scan history
4. Click "Details" on any entry to see full scan information
5. Click "Refresh" to update the data manually (auto-refreshes every 15 seconds)

## API Endpoints

The backend provides the following API endpoints:

### Health Check
```
GET /health
```
Returns the server status and current timestamp.

**Response:**
```json
{
  "status": "ok",
  "time": 1234567890
}
```

### Predict URL
```
POST /predict
```
Analyzes a URL and returns a prediction.

**Request Body:**
```json
{
  "url": "https://example.com",
  "run_safe_browsing": false
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "score": 0.1234,
  "ml_score": 0.1500,
  "heuristics_score": 0.0800,
  "label": 0,
  "reason": "Uses HTTPS encryption; Very low risk score; Uses common trusted domain extension | Heuristics: Uses HTTPS (positive); Trusted domain extension",
  "google_safe": false,
  "ts": 1234567890
}
```

- `score`: Combined risk score (0.0 to 1.0) - weighted average of ML and Heuristics models
- `ml_score`: ML model probability (0.0 to 1.0) - 60% weight in combined score
- `heuristics_score`: Heuristics model score (0.0 to 1.0) - 40% weight in combined score
- `label`: 0 for safe, 1 for suspicious
- `reason`: Explanation of the prediction including ML analysis and triggered heuristics rules
- `google_safe`: Whether Google Safe Browsing flagged it (if enabled)
- `ts`: Unix timestamp

### Get Scan History
```
GET /history?limit=100
```
Returns the scan history.

**Query Parameters:**
- `limit`: Maximum number of records to return (default: 100)

**Response:**
```json
[
  {
    "id": 1,
    "url": "https://example.com",
    "score": 0.1234,
    "label": 0,
    "reason": "prob=0.1234",
    "google_safe": 0,
    "ts": 1234567890
  }
]
```

## Configuration

### Backend Configuration

- **Port**: Change the port in the uvicorn command (default: 8000)
- **Database**: SQLite database is created automatically at `backend/db.sqlite`
- **Models**: Model files must be in `backend/models/`

### Dashboard Configuration

- **API URL**: Change the API URL in `dashboard/src/App.jsx`:
  ```javascript
  const API = "http://localhost:8000";
  ```
- **Port**: React development server runs on port 3000 by default

### Extension Configuration

- **Backend URL**: The extension connects to `http://localhost:8000` by default
- **Cache Duration**: Results are cached for 5 minutes
- **Permissions**: The extension requires tabs, storage, and notifications permissions

## Troubleshooting

### Backend Issues

**Problem**: `Model artifacts missing` error
- **Solution**: Run `python ml/train.py` to generate the model files

**Problem**: `ModuleNotFoundError`
- **Solution**: Install all dependencies: `pip install -r requirements.txt`

**Problem**: Port 8000 already in use
- **Solution**: Change the port: `uvicorn app:app --reload --port 8001`

**Problem**: CORS errors
- **Solution**: CORS is already enabled in the backend. Ensure the backend is running and accessible.

### Dashboard Issues

**Problem**: Dashboard shows "No scan history found"
- **Solution**: 
  1. Ensure the backend is running on port 8000
  2. Visit some websites to generate scan data
  3. Check browser console for errors

**Problem**: Dashboard cannot connect to backend
- **Solution**: 
  1. Verify backend is running: `curl http://localhost:8000/health`
  2. Check if the API URL in `App.jsx` is correct
  3. Check browser console for CORS or network errors

**Problem**: `npm install` fails
- **Solution**: 
  1. Clear npm cache: `npm cache clean --force`
  2. Delete `node_modules` and `package-lock.json`
  3. Run `npm install` again

### Extension Issues

**Problem**: Popup shows "No scan result cached"
- **Solution**: 
  1. Ensure the backend is running
  2. Wait a few seconds for the extension to scan the page
  3. Refresh the page
  4. Check the service worker console for errors (chrome://extensions -> Secure-Click -> Service worker)

**Problem**: Extension doesn't scan URLs
- **Solution**: 
  1. Check if the backend is accessible from the extension
  2. Verify `host_permissions` in `manifest.json` includes `http://localhost:8000/*`
  3. Check the service worker console for errors
  4. Reload the extension

**Problem**: Badge doesn't appear
- **Solution**: 
  1. Check browser notifications are enabled
  2. Verify the extension has notification permissions
  3. Check service worker console for errors

## Development

### How the risk score is computed

Secure-Click uses a **hybrid approach** combining both **Machine Learning (ML)** and **Heuristics-based** models to assign a risk score to each URL. This dual-model approach improves accuracy and reduces false negatives.

#### ML Model Ensemble (60% weight)
- **Feature extraction:**
  - Character n‑gram representation of the full URL using 3–5 length n‑grams with up to 2000 features.
  - Lightweight lexical features:
    - `url_len`: total URL length
    - `count_dots`: number of '.' characters (deep subdomain chains can be suspicious)
    - `has_at`: presence of '@' (used in URL obfuscation)
    - `count_hyphen`: number of '-' (often used in typosquatting)
    - `has_ip`: whether the URL contains an IPv4 address instead of a hostname
- **Models (Ensemble with Optimized Weights):**
  - **XGBoost**: Gradient boosting classifier for capturing non-linear patterns
  - **Logistic Regression**: Linear model for interpretability and regularization
  - **Random Forest**: Ensemble of decision trees for additional diversity
  - **Weight Optimization**: During training, the system automatically tests multiple weight combinations and selects the optimal weights based on ROC-AUC score on the validation set
  - **Output**: Weighted ensemble probability \(p_{ml} ∈ [0,1]\) that the URL is suspicious
  - The optimal weights are saved to `backend/models/ensemble_weights.json` and automatically loaded by the backend

#### Heuristics Model (40% weight)
The heuristics model uses **13 predefined rules** to detect suspicious patterns:

1. **IP address instead of domain** (+0.3) - Highly suspicious
2. **@ symbol in URL** (+0.25) - Often used in obfuscation
3. **Excessive hyphens** (+0.08 to +0.15) - Common in typosquatting
4. **Excessive subdomains** (+0.1 to +0.2) - Subdomain abuse
5. **Brand impersonation patterns** (+0.25) - Suspicious domain patterns (e.g., paypal-verify.com)
6. **Suspicious path keywords** (+0.08 to +0.15) - verify, login, account, etc.
7. **URL length anomalies** (+0.05 to +0.1) - Very long or very short URLs
8. **Suspicious TLDs** (+0.15) - .tk, .ml, .ga, .cf, etc.
9. **Mixed case obfuscation** (+0.05) - Intentional case mixing
10. **Numeric domain** (+0.2) - Domains starting with numbers
11. **URL shorteners** (+0.1) - bit.ly, tinyurl.com, etc.
12. **HTTPS usage** (-0.05) - Positive indicator (reduces suspicion)
13. **Trusted TLDs** (-0.05) - .com, .org, .edu, etc. (reduces suspicion)

The heuristics model outputs a score \(p_{heur} ∈ [0,1]\) based on triggered rules.

#### Combined Score
- **Weighted average:** \(score = 0.6 × p_{ml} + 0.4 × p_{heur}\)
- **Decision threshold:**
  - Default label is `suspicious` if `score > 0.5`, otherwise `safe`
  - If Google Safe Browsing is enabled and returns a match, the label is forced to `suspicious` regardless of the combined score

### Enable Google Safe Browsing (reduces false negatives)

Google Safe Browsing adds a high‑precision reputation signal that can catch threats that look benign lexically (e.g., clean‑looking phishing URLs, compromised legit domains).

- Prerequisites:
  - Obtain API keys for Google Safe Browsing and/or VirusTotal (both are optional but improve coverage).
- Configure:
  - Copy `backend/env.example` to `backend/.env` and populate `SAFE_BROWSING_API_KEY` and/or `VIRUSTOTAL_API_KEY`; the backend loads this file automatically.
  - You can override those values per session:
    - Windows PowerShell:
      ```powershell
      $env:SAFE_BROWSING_API_KEY="YOUR_KEY"
      $env:VIRUSTOTAL_API_KEY="YOUR_KEY"
      ```
    - macOS/Linux:
      ```bash
      export SAFE_BROWSING_API_KEY="YOUR_KEY"
      export VIRUSTOTAL_API_KEY="YOUR_KEY"
      ```
  - Adjust `SAFE_BROWSING_TTL_SECONDS` in `.env` (default `3600`) or export it to control how long Safe Browsing results are cached.
- Behavior:
  - The Chrome extension requests Safe Browsing checks automatically.
  - The backend queries the API on first sight of a URL and caches the result for the TTL to save quota and latency.
  - If a match is returned, the verdict is `Malicious` and the reason includes “Flagged by Google Safe Browsing API”.

You can change the decision threshold by editing `backend/app.py` (search for `prob > 0.5`) to a lower value (e.g., `0.45`) to reduce false negatives, at the expense of more false positives.

### What "Analysis Parameters" shows and how it's built

The backend builds a human‑readable explanation from URL characteristics, ML model analysis, and heuristics rules. The analysis parameters may include:

**From ML Model Analysis:**
- Suspicious domain patterns suggesting brand impersonation
- URL length, hyphen count, subdomain analysis
- Character n-gram pattern matching

**From Heuristics Rules:**
- Specific rules that were triggered (e.g., "IP address used instead of domain name", "Excessive hyphens (6)", "Suspicious paypal domain pattern")
- Positive indicators (e.g., "Uses HTTPS (positive)", "Trusted domain extension")

**From Google Safe Browsing:**
- "Flagged by Google Safe Browsing API" when that integration is enabled and returns a hit

The final combined risk score is calculated as: **60% ML Model + 40% Heuristics Model**

### Why you may see false negatives (malicious but predicted safe)

Common causes:

- Evasive/benign‑looking URLs with minimal lexical signals (e.g., short, clean paths on newly registered domains)
- Compromised legitimate domains serving malicious content at deep paths (URL looks safe; content is not analyzed)
- URL shorteners and multi‑step redirects that hide the final destination
- Dataset drift: new attack patterns or TLDs under‑represented in the training data
- Internationalized domain names and homograph attacks (e.g., Unicode look‑alikes) not captured by current features
- Safe Browsing disabled (default); would have caught some threats via reputation lists

Ways to reduce false negatives:

- Lower the decision threshold (e.g., 0.50 → 0.45 or 0.40). Edit `backend/app.py` where `label = int(prob > 0.5)`.
- Enable Google Safe Browsing (set `SAFE_BROWSING_API_KEY` and run the backend with that environment variable).
- Retrain the model (`ml/train.py`) with more recent or larger phishing datasets (update `data/`).
- Add more features (future work ideas):
  - WHOIS/domain‑age, registrar reputation, and TLD risk features
  - Unicode normalization and homograph detection
  - Page‑level features (form presence, external scripts, login fields) fetched safely in the backend
  - Redirect‑aware scanning (follow shorteners in a controlled, sandboxed manner)

Tip: after changing the threshold or retraining, compare results on a validation set that reflects your real browsing mix to balance false positives vs. false negatives.

### Training a New Model

To retrain the model with updated data:

```bash
cd ml
python train.py
```

The script will:
1. Load datasets from the `data/` directory
2. Preprocess and combine the data
3. Train three models:
   - XGBoost classifier
   - Logistic Regression
   - Random Forest
4. Evaluate each model individually
5. Optimize ensemble weights by testing multiple combinations and selecting the best based on ROC-AUC
6. Evaluate the optimized ensemble
7. Save all models, vectorizer, and optimized weights to `backend/models/`

### Adding New Features

1. **Backend**: Add new endpoints in `backend/app.py`
2. **Dashboard**: Add new components in `dashboard/src/components/`
3. **Extension**: Modify `extension/service_worker.js` for background tasks or `extension/popup.js` for UI changes

### Testing

**Test Backend:**
```bash
# Health check
curl http://localhost:8000/health

# Predict URL
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Get history
curl http://localhost:8000/history?limit=10
```

## Security Notes

- ⚠️ This is a local development tool. For production use, implement proper authentication and security measures.
- ⚠️ The CORS configuration allows all origins (`*`). In production, restrict this to specific domains.
- ⚠️ The extension requires access to all URLs. Review the permissions before installing.
- ⚠️ Google Safe Browsing API requires an API key. Keep it secure and don't commit it to version control.

## License

This project is provided as-is for educational and development purposes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

For issues and questions:
1. Check the Troubleshooting section above
2. Review the browser console and backend logs
3. Open an issue on the repository

## Acknowledgments

- Training datasets from various phishing URL datasets
- Built with FastAPI, React, and Chrome Extension APIs
- Uses optimized ensemble of XGBoost, Logistic Regression, and Random Forest for machine learning classification

---

**Happy Secure Browsing! 🔒**

=======
# Secure-Click
>>>>>>> 9e65c7f11549f1a7f0eea7fd0008ca980804a78b
