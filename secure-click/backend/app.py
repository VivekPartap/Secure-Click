# backend/app.py
"""
FastAPI backend for Secure-Click (local).
Updated to work with Bagging/AdaBoost/GradientBoosting models and
either URL-vectorizer pipeline or tabular-model fallbacks.
Run with:
  uvicorn backend.app:app --reload --port 8000
"""
import os
import time
import re
import sqlite3
import joblib
import json
import logging
from typing import Optional, Dict, Any

import numpy as np
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scipy.sparse import hstack
from dotenv import load_dotenv
import requests

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# New model artifact names produced by updated ml/train.py
MODEL_BAG_PATH = os.path.join(BASE_DIR, "models", "model_bagging.joblib")
MODEL_AB_PATH = os.path.join(BASE_DIR, "models", "model_adaboost.joblib")
MODEL_GB_PATH = os.path.join(BASE_DIR, "models", "model_gb.joblib")
VECT_PATH = os.path.join(BASE_DIR, "models", "url_vectorizer.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "models", "feature_scaler.joblib")
WEIGHTS_PATH = os.path.join(BASE_DIR, "models", "ensemble_weights.json")
MODEL_METADATA_PATH = os.path.join(BASE_DIR, "models", "model_metadata.json")

# Load environment variables from .env if present
load_dotenv(os.path.join(BASE_DIR, ".env"))

# ---------------------------------------------------------------------------
# Global configuration and logging
# ---------------------------------------------------------------------------

APP_START_TS = int(time.time())


class Settings:
    """Central place for tunable configuration."""

    def __init__(self) -> None:
        self.suspicious_threshold: float = float(os.getenv("SC_SUSPICIOUS_THRESHOLD", "0.5"))
        self.block_threshold: float = float(os.getenv("SC_BLOCK_THRESHOLD", "0.7"))
        self.safe_browsing_ttl_seconds: int = int(os.getenv("SAFE_BROWSING_TTL_SECONDS", "3600"))
        self.slow_request_ms: int = int(os.getenv("SC_SLOW_REQUEST_MS", "1000"))
        # Minimum interval (seconds) between external calls; 0 disables rate limiting
        self.gsb_min_interval_sec: float = float(os.getenv("SC_GSB_MIN_INTERVAL_SEC", "0.0"))
        self.vt_min_interval_sec: float = float(os.getenv("SC_VT_MIN_INTERVAL_SEC", "0.0"))


settings = Settings()

# Simple JSON-style logger
logger = logging.getLogger("secure_click")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def log_event(level: str, message: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {
        "ts": int(time.time()),
        "level": level,
        "message": message,
    }
    if fields:
        payload.update(fields)
    line = json.dumps(payload, default=str)
    if level == "error":
        logger.error(line)
    elif level == "warning":
        logger.warning(line)
    else:
        logger.info(line)


# Load ML models if present
models = {}
if os.path.exists(MODEL_BAG_PATH):
    try:
        models['bagging'] = joblib.load(MODEL_BAG_PATH)
        print(f"[Backend] Loaded Bagging model from {MODEL_BAG_PATH}")
    except Exception as e:
        print(f"[Backend] Failed loading bagging model: {e}")
if os.path.exists(MODEL_AB_PATH):
    try:
        models['adaboost'] = joblib.load(MODEL_AB_PATH)
        print(f"[Backend] Loaded AdaBoost model from {MODEL_AB_PATH}")
    except Exception as e:
        print(f"[Backend] Failed loading adaboost model: {e}")
if os.path.exists(MODEL_GB_PATH):
    try:
        models['gradboost'] = joblib.load(MODEL_GB_PATH)
        print(f"[Backend] Loaded GradientBoosting model from {MODEL_GB_PATH}")
    except Exception as e:
        print(f"[Backend] Failed loading gradboost model: {e}")

# Load vectorizer / scaler if present
vect = None
scaler = None
if os.path.exists(VECT_PATH):
    try:
        vect = joblib.load(VECT_PATH)
        print(f"[Backend] Loaded URL vectorizer from {VECT_PATH}")
    except Exception as e:
        print(f"[Backend] Failed loading vectorizer: {e}")
if os.path.exists(SCALER_PATH):
    try:
        scaler = joblib.load(SCALER_PATH)
        print(f"[Backend] Loaded feature scaler from {SCALER_PATH}")
    except Exception as e:
        print(f"[Backend] Failed loading feature scaler: {e}")

# Parse ensemble weights (support old simple format and new nested metric format)
ensemble_weights = {'bagging': 0.33, 'adaboost': 0.33, 'gradboost': 0.34}  # fallback
if os.path.exists(WEIGHTS_PATH):
    try:
        raw = json.load(open(WEIGHTS_PATH, 'r'))
        # Old-style flat keys (xgb_weight, lr_weight, rf_weight) OR
        # New-style metrics object may contain 'ensemble' or similar.
        # We'll try multiple heuristics to extract model weights.
        if all(k in raw for k in ('bagging','adaboost','gradboost')):
            # If user saved direct mapping
            ensemble_weights = {
                'bagging': float(raw.get('bagging', ensemble_weights['bagging'])),
                'adaboost': float(raw.get('adaboost', ensemble_weights['adaboost'])),
                'gradboost': float(raw.get('gradboost', ensemble_weights['gradboost']))
            }
        elif 'ensemble' in raw and isinstance(raw['ensemble'], dict) and 'weights' in raw['ensemble']:
            w = raw['ensemble']['weights']
            if isinstance(w, (list,tuple)) and len(w) == 3:
                ensemble_weights = {'bagging': float(w[0]), 'adaboost': float(w[1]), 'gradboost': float(w[2])}
            elif isinstance(w, dict):
                ensemble_weights = {
                    'bagging': float(w.get('bagging', ensemble_weights['bagging'])),
                    'adaboost': float(w.get('adaboost', ensemble_weights['adaboost'])),
                    'gradboost': float(w.get('gradboost', ensemble_weights['gradboost']))
                }
        elif all(k in raw for k in ('xgb_weight','lr_weight','rf_weight')):
            # best-effort mapping if the old script produced xgb/lr/rf weights
            # map xgb -> bagging, lr -> adaboost, rf -> gradboost (not ideal but fallback)
            total = raw.get('xgb_weight',0)+raw.get('lr_weight',0)+raw.get('rf_weight',0)
            if total > 0:
                ensemble_weights = {
                    'bagging': float(raw.get('xgb_weight',0))/total,
                    'adaboost': float(raw.get('lr_weight',0))/total,
                    'gradboost': float(raw.get('rf_weight',0))/total
                }
        else:
            # If metrics object contains individual model metrics, but not explicit weights,
            # keep defaults (equal weights)
            print("[Backend] ensemble_weights.json found but no weight mapping detected; using defaults.")
    except Exception as e:
        print(f"[Backend] Could not parse ensemble weights at {WEIGHTS_PATH}: {e}. Using defaults.")
else:
    print(f"[Backend] Ensemble weights file not found at {WEIGHTS_PATH}. Using defaults.")

print(f"[Backend] Ensemble weights (bagging,adaboost,gradboost): {ensemble_weights['bagging']:.3f}, {ensemble_weights['adaboost']:.3f}, {ensemble_weights['gradboost']:.3f}")

# Load environment keys
SAFE_BROWSING_KEY = os.environ.get("SAFE_BROWSING_API_KEY", None)
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", None)
if SAFE_BROWSING_KEY:
    log_event("info", "Google Safe Browsing API enabled (key present)")
else:
    log_event("info", "Google Safe Browsing API disabled; set SAFE_BROWSING_API_KEY to enable")
if VIRUSTOTAL_KEY:
    log_event("info", "VirusTotal API enabled (key present)")
else:
    log_event("info", "VirusTotal API disabled; set VIRUSTOTAL_API_KEY to enable")

# FastAPI app setup
app = FastAPI(title="Secure-Click Local API", version="0.2")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logger(request: Request, call_next):
    """Log slow requests in a structured way."""
    start = time.time()
    try:
        response = await call_next(request)
    except Exception as exc:
        # Log unhandled exceptions and re-raise as HTTP 500
        duration_ms = int((time.time() - start) * 1000)
        log_event(
            "error",
            "Unhandled exception in request",
            path=request.url.path,
            method=request.method,
            duration_ms=duration_ms,
            error=str(exc)[:200],
        )
        raise

    duration_ms = int((time.time() - start) * 1000)
    if duration_ms >= settings.slow_request_ms:
        log_event(
            "warning",
            "Slow request",
            path=request.url.path,
            method=request.method,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
    return response

# Database (SQLite) setup
DB_PATH = os.path.join(BASE_DIR, "db.sqlite")
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.execute('''CREATE TABLE IF NOT EXISTS scans
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              url TEXT,
              score REAL,
              label INTEGER,
              reason TEXT,
              google_safe INTEGER,
              heuristics_score REAL,
              ml_score REAL,
              virustotal_flag INTEGER,
              virustotal_positives INTEGER,
              virustotal_total INTEGER,
              ts INTEGER)''')
conn.commit()

# Utility: check column existence in sqlite table
def column_exists(table_name, column_name):
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table_name):
        raise ValueError(f"Invalid table name: {table_name}")
    try:
        cursor = conn.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        return column_name in columns
    except sqlite3.Error as e:
        print(f"[Backend] Error checking column existence: {e}")
        return False

# Ensure optional columns exist (backwards compatibility)
for col, coltype in (('heuristics_score','REAL'), ('ml_score','REAL'), ('virustotal_flag','INTEGER'), ('virustotal_positives','INTEGER'), ('virustotal_total','INTEGER')):
    if not column_exists('scans', col):
        try:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {coltype}")
        except sqlite3.Error:
            # ignore if fails (older sqlite versions or race conditions)
            pass
conn.commit()

# Request model
class UrlRequest(BaseModel):
    url: str
    run_safe_browsing: Optional[bool] = False
    run_virustotal: Optional[bool] = None

# Simple lexical numeric features (keeps compatibility with url-vectorizer pipeline)
def lexical_numeric(url):
    url = str(url)
    url_len = len(url)
    count_dots = url.count('.')
    has_at = 1 if "@" in url else 0
    count_hyphen = url.count('-')
    has_ip = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
    return np.array([[url_len, count_dots, has_at, count_hyphen, has_ip]])

# Heuristics rules (kept same as your previous implementation)
def heuristics_model(url):
    url_str = str(url).lower()
    score = 0.0
    triggered_rules = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain_lower = domain.lower()
        path = parsed.path.lower()
    except (ValueError, AttributeError, IndexError):
        domain = ""
        domain_lower = url_str
        path = ""

    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str):
        score += 0.3
        triggered_rules.append("IP address used instead of domain name")
    if "@" in url_str:
        score += 0.25
        triggered_rules.append("Contains '@' symbol")
    hyphen_count = url_str.count('-')
    if hyphen_count > 5:
        score += 0.15
        triggered_rules.append(f"Excessive hyphens ({hyphen_count})")
    elif hyphen_count > 3:
        score += 0.08
        triggered_rules.append(f"Multiple hyphens ({hyphen_count})")
    dot_count = domain_lower.count('.')
    if dot_count > 4:
        score += 0.2
        triggered_rules.append(f"Excessive subdomains ({dot_count} dots)")
    elif dot_count > 3:
        score += 0.1
        triggered_rules.append(f"Multiple subdomains ({dot_count} dots)")
    suspicious_brands = ['paypal', 'bank', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay', 'visa', 'mastercard']
    legitimate_domains = {
        'paypal': ['paypal.com', 'paypal.co.uk', 'paypal.com.au'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in'],
        'microsoft': ['microsoft.com', 'microsoft.co.uk'],
        'apple': ['apple.com'],
        'google': ['google.com', 'google.co.uk', 'google.in'],
        'facebook': ['facebook.com'],
        'netflix': ['netflix.com'],
        'ebay': ['ebay.com', 'ebay.co.uk']
    }
    for brand in suspicious_brands:
        if brand in domain_lower:
            is_legitimate = False
            for legit in legitimate_domains.get(brand, []):
                if domain_lower == legit or domain_lower.endswith('.' + legit):
                    is_legitimate = True
                    break
            if not is_legitimate:
                if (re.search(rf'{brand}[.\-]', domain_lower) or 
                    re.search(rf'[.\-]{brand}[.\-]', domain_lower) or 
                    domain_lower.startswith(brand + '-')):
                    score += 0.25
                    triggered_rules.append(f"Suspicious {brand} domain pattern")
                    break
    phishing_keywords = ['verify', 'secure', 'login', 'account', 'update', 'confirm', 'suspended', 'locked', 'validate', 'authenticate']
    keyword_matches = [kw for kw in phishing_keywords if kw in url_str]
    if keyword_matches:
        if len(keyword_matches) >= 2:
            score += 0.15
            triggered_rules.append(f"Multiple suspicious keywords: {', '.join(keyword_matches[:3])}")
        else:
            score += 0.08
            triggered_rules.append(f"Suspicious keyword: {keyword_matches[0]}")
    if len(url_str) > 100:
        score += 0.1
        triggered_rules.append(f"Unusually long URL ({len(url_str)} chars)")
    elif len(url_str) < 15:
        score += 0.05
        triggered_rules.append(f"Very short URL ({len(url_str)} chars)")
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download']
    if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
        score += 0.15
        triggered_rules.append("Suspicious top-level domain")
    if url != url.lower() and url != url.upper():
        if re.search(r'[a-z][A-Z]|[A-Z][a-z]', url):
            score += 0.05
            triggered_rules.append("Mixed case obfuscation detected")
    if re.match(r'^https?://\d+\.', url_str):
        score += 0.2
        triggered_rules.append("Numeric domain detected")
    short_url_services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
    if any(service in domain_lower for service in short_url_services):
        score += 0.1
        triggered_rules.append("URL shortener detected")
    if url_str.startswith('https://'):
        score -= 0.05
        triggered_rules.append("Uses HTTPS (positive)")
    trusted_tlds = ['.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.in', '.au']
    if any(domain_lower.endswith(tld) for tld in trusted_tlds) and score < 0.3:
        score -= 0.05
        triggered_rules.append("Trusted domain extension")
    score = max(0.0, min(1.0, score))
    return score, triggered_rules

# VirusTotal helper, returns tuple, with basic caching + rate limiting
_safe_cache = {}  # simple in-memory cache shared by external checks
_last_vt_call_ts: Optional[int] = None
_last_gsb_call_ts: Optional[int] = None


def virustotal_check(url):
    global _last_vt_call_ts
    if not VIRUSTOTAL_KEY:
        return False, 0, 0, None
    cache_key = f"vt_{hash(url)}"
    now = int(time.time())
    cached = _safe_cache.get(cache_key)
    if cached and isinstance(cached, dict) and 'vt_result' in cached:
        if now - cached.get('timestamp', 0) < settings.safe_browsing_ttl_seconds:
            vt_data = cached['vt_result']
            return (
                vt_data.get('malicious', False),
                vt_data.get('positives', 0),
                vt_data.get('total', 0),
                vt_data.get('permalink'),
            )

    # Simple per-process rate limiting if configured
    if settings.vt_min_interval_sec > 0 and _last_vt_call_ts is not None:
        if now - _last_vt_call_ts < settings.vt_min_interval_sec:
            log_event(
                "warning",
                "VirusTotal rate-limit: skipping external call due to min interval",
                url=url,
            )
            return False, 0, 0, None

    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': VIRUSTOTAL_KEY, 'resource': url}
    try:
        _last_vt_call_ts = now
        r = requests.get(endpoint, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get('response_code') == 1:
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                is_malicious = positives > 0
                permalink = data.get('permalink')
                _safe_cache[cache_key] = {
                    'vt_result': {
                        'malicious': is_malicious,
                        'positives': positives,
                        'total': total,
                        'permalink': permalink,
                    },
                    'timestamp': now,
                }
                if is_malicious:
                    log_event(
                        "warning",
                        "VirusTotal URL flagged",
                        url=url,
                        positives=positives,
                        total=total,
                    )
                return is_malicious, positives, total, permalink
            else:
                return False, 0, 0, None
        elif r.status_code == 204:
            log_event("warning", "VirusTotal HTTP 204 rate-limit", url=url)
            return False, 0, 0, None
        else:
            log_event(
                "error",
                "VirusTotal API error",
                url=url,
                status_code=r.status_code,
                body=r.text[:200],
            )
            return False, 0, 0, None
    except requests.exceptions.Timeout:
        log_event("warning", "VirusTotal timeout", url=url)
        return False, 0, 0, None
    except Exception as e:
        log_event("error", "VirusTotal exception", url=url, error=str(e)[:200])
        return False, 0, 0, None


# Google Safe Browsing check with caching + rate limiting
def google_safe_browsing_check(url):
    global _last_gsb_call_ts
    if not SAFE_BROWSING_KEY:
        return False
    now = int(time.time())
    cached = _safe_cache.get(url)
    if cached:
        if isinstance(cached, tuple) and len(cached) == 2:
            if now - cached[1] < settings.safe_browsing_ttl_seconds:
                return cached[0]
        elif isinstance(cached, dict) and 'timestamp' in cached:
            if now - cached.get('timestamp', 0) < settings.safe_browsing_ttl_seconds:
                return cached.get('flag', False)

    # Simple per-process rate limiting if configured
    if settings.gsb_min_interval_sec > 0 and _last_gsb_call_ts is not None:
        if now - _last_gsb_call_ts < settings.gsb_min_interval_sec:
            log_event(
                "warning",
                "SafeBrowsing rate-limit: skipping external call due to min interval",
                url=url,
            )
            return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
    payload = {
      "client": {"clientId":"secure-click","clientVersion":"1.0"},
      "threatInfo": {
        "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": url}]
      }
    }
    result_flag = False
    try:
        _last_gsb_call_ts = now
        r = requests.post(endpoint, json=payload, timeout=10)
        if r.status_code == 200:
            response_data = r.json()
            if response_data and "matches" in response_data and len(response_data["matches"]) > 0:
                result_flag = True
                log_event("warning", "SafeBrowsing URL flagged", url=url)
            else:
                result_flag = False
        elif r.status_code == 400:
            error_data = r.json() if r.text else {}
            log_event(
                "error",
                "SafeBrowsing 400 error",
                url=url,
                message=error_data.get('error', {}).get('message', 'Bad request'),
            )
        elif r.status_code == 403:
            log_event("error", "SafeBrowsing 403 error (invalid key or quota)", url=url)
        else:
            log_event(
                "error",
                "SafeBrowsing API error",
                url=url,
                status_code=r.status_code,
                body=r.text[:200],
            )
    except requests.exceptions.Timeout:
        log_event("warning", "SafeBrowsing timeout", url=url)
        result_flag = False
    except requests.exceptions.RequestException as e:
        log_event("error", "SafeBrowsing request error", url=url, error=str(e)[:200])
        result_flag = False
    except Exception as e:
        log_event("error", "SafeBrowsing unexpected error", url=url, error=str(e)[:200])
        result_flag = False
    _safe_cache[url] = {'flag': result_flag, 'timestamp': now}
    return result_flag

# Reason generation (keeps original approach)
def generate_reason(url, prob, label, heuristics_rules=None, gs_flag=False, vt_flag=False, vt_positives=0, vt_total=0):
    url_str = str(url).lower()
    reasons = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain_lower = domain.lower()
    except (ValueError, AttributeError, IndexError):
        domain = ""
        domain_lower = url_str
    suspicious_keywords = ['paypal', 'bank', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay']
    phishing_patterns = ['verify', 'secure', 'login', 'account', 'update', 'confirm', 'suspended', 'locked']
    has_suspicious_domain = False
    legitimate_domains = {
        'paypal': ['paypal.com', 'paypal.co.uk', 'paypal.com.au'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in'],
        'microsoft': ['microsoft.com', 'microsoft.co.uk'],
        'apple': ['apple.com'],
        'google': ['google.com', 'google.co.uk', 'google.in'],
        'facebook': ['facebook.com'],
        'netflix': ['netflix.com'],
        'ebay': ['ebay.com', 'ebay.co.uk']
    }
    for keyword in suspicious_keywords:
        if keyword in domain_lower:
            is_legitimate = False
            for legit in legitimate_domains.get(keyword, []):
                if domain_lower == legit or domain_lower.endswith('.' + legit):
                    is_legitimate = True
                    break
            if not is_legitimate:
                if (re.search(rf'{keyword}[.\-]', domain_lower) or 
                    re.search(rf'[.\-]{keyword}[.\-]', domain_lower) or 
                    domain_lower.startswith(keyword + '-')):
                    has_suspicious_domain = True
                    reasons.append(f"Suspicious domain pattern detected (potential {keyword} phishing)")
                    break
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str):
        reasons.append("IP address used instead of domain name")
    if "@" in url_str:
        reasons.append("Contains '@' symbol (unusual in URLs)")
    hyphen_count = url_str.count('-')
    if hyphen_count > 5:
        reasons.append(f"Unusually high number of hyphens ({hyphen_count})")
    dot_count = domain_lower.count('.')
    if dot_count > 4:
        reasons.append(f"Excessive subdomains ({dot_count} dots in domain)")
    if any(pattern in url_str for pattern in phishing_patterns):
        if has_suspicious_domain or prob > 0.6:
            reasons.append("Contains suspicious path patterns (verify/login/account)")
    if len(url_str) > 100:
        reasons.append("Unusually long URL")
    elif len(url_str) < 15:
        reasons.append("Very short URL")
    if label == 0 and url_str.startswith('https://'):
        reasons.append("Uses HTTPS encryption")
    common_tlds = ['.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.in']
    has_common_tld = any(domain_lower.endswith(tld) for tld in common_tlds)
    if label == 1:
        if prob > 0.8:
            reasons.append("Very high malicious probability score")
        elif prob > 0.6:
            reasons.append("High malicious probability score")
        if not reasons:
            if prob > 0.7:
                reasons.append("High risk score from ML model analysis")
            else:
                reasons.append("Moderate risk indicators detected")
    else:
        if prob < 0.2:
            reasons.append("Very low risk score")
        elif prob < 0.4:
            reasons.append("Low risk score")
        if has_common_tld and not has_suspicious_domain:
            reasons.append("Uses common trusted domain extension")
        if not reasons:
            reasons.append("No significant threat indicators detected")
    if heuristics_rules:
        hr = "; ".join(heuristics_rules[:5])
        reasons.append(f"Heuristics: {hr}" + (f" (+{len(heuristics_rules)-5} more)" if len(heuristics_rules)>5 else ""))
    if gs_flag:
        reasons.append("Flagged by Google Safe Browsing")
    if vt_flag:
        reasons.append(f"Flagged by VirusTotal ({vt_positives}/{vt_total})")
    return "; ".join(reasons)

@app.get("/health")
def health():
    """Lightweight health and status endpoint."""
    db_ok = True
    try:
        conn.execute("SELECT 1")
    except sqlite3.Error as e:
        db_ok = False
        log_event("error", "Health DB check failed", error=str(e)[:200])

    model_metadata: Dict[str, Any] = {}
    if os.path.exists(MODEL_METADATA_PATH):
        try:
            with open(MODEL_METADATA_PATH, "r", encoding="utf-8") as fh:
                model_metadata = json.load(fh)
        except Exception as e:
            log_event("warning", "Failed to read model_metadata.json", error=str(e)[:200])

    last_model_ts: Optional[int] = None
    try:
        if os.path.exists(WEIGHTS_PATH):
            last_model_ts = int(os.path.getmtime(WEIGHTS_PATH))
    except Exception:
        last_model_ts = None

    return {
        "status": "ok" if db_ok else "degraded",
        "time": int(time.time()),
        "app_start_ts": APP_START_TS,
        "db_ok": db_ok,
        "ml_available": bool(models and (vect is not None or scaler is not None)),
        "model_metadata": model_metadata,
        "last_model_train_ts": last_model_ts,
        "config": {
            "suspicious_threshold": settings.suspicious_threshold,
            "block_threshold": settings.block_threshold,
            "safe_browsing_ttl_seconds": settings.safe_browsing_ttl_seconds,
        },
    }

@app.post("/predict")
def predict(body: UrlRequest):
    url = body.url
    if not url:
        raise HTTPException(status_code=400, detail="No URL provided")
    url = str(url).strip()

    # Feature extraction for ML:
    ml_available = bool(models) and (vect is not None or scaler is not None)
    ml_scores = {}
    ml_used = False
    ml_warning = None

    if vect is not None and models:
        # Preferred pipeline: vectorizer + lexical numeric features (sparse hstack)
        try:
            X_text = vect.transform([url])
            X_num = lexical_numeric(url)
            X = hstack([X_text, X_num])
            ml_used = True
            # Predict per-model probabilities if model supports predict_proba
            for name, m in models.items():
                try:
                    prob = float(m.predict_proba(X)[:,1][0])
                except Exception:
                    # Some estimators might not support predict_proba; fall back to predict
                    try:
                        prob = float(m.predict(X)[0])
                    except Exception:
                        prob = 0.0
                ml_scores[name] = prob
        except Exception as e:
            ml_warning = f"ML feature extraction failed: {e}"
            print(f"[Predict] Warning: {ml_warning}")
            ml_used = False
    elif scaler is not None and models:
        # Try minimal compatibility: scale lexical_numeric and attempt predict only if shapes match
        try:
            X_num = lexical_numeric(url)
            # scaler expects a different number of features in most cases; check compatibility
            n_expected = getattr(scaler, "mean_", None)
            if n_expected is not None and X_num.shape[1] == scaler.mean_.shape[0]:
                X_scaled = scaler.transform(X_num)
                X = X_scaled
                ml_used = True
                for name, m in models.items():
                    try:
                        prob = float(m.predict_proba(X)[:,1][0])
                    except Exception:
                        try:
                            prob = float(m.predict(X)[0])
                        except Exception:
                            prob = 0.0
                    ml_scores[name] = prob
            else:
                ml_warning = "Feature scaler present but feature dimensionality does not match lexical features; skipping ML."
                print(f"[Predict] {ml_warning}")
                ml_used = False
        except Exception as e:
            ml_warning = f"ML (scaler pipeline) failed: {e}"
            print(f"[Predict] Warning: {ml_warning}")
            ml_used = False
    else:
        # No viable ML pipeline available; fallback to heuristics only
        ml_warning = "No ML pipeline available (vectorizer/scaler missing or incompatible). Using heuristics and external APIs only."
        print(f"[Predict] {ml_warning}")
        ml_used = False

    # If ML used compute ensemble score according to ensemble_weights
    ml_score_ensemble = 0.0
    if ml_used and ml_scores:
        # Ensure we have keys for all expected models; default missing to 0
        b = ml_scores.get('bagging', 0.0)
        a = ml_scores.get('adaboost', 0.0)
        g = ml_scores.get('gradboost', 0.0)
        # Normalize weights
        total_w = ensemble_weights.get('bagging',0) + ensemble_weights.get('adaboost',0) + ensemble_weights.get('gradboost',0)
        if total_w <= 0:
            total_w = 1.0
        w_b = ensemble_weights.get('bagging',0)/total_w
        w_a = ensemble_weights.get('adaboost',0)/total_w
        w_g = ensemble_weights.get('gradboost',0)/total_w
        ml_score_ensemble = max(0.0, min(1.0, w_b*b + w_a*a + w_g*g))
    else:
        ml_score_ensemble = 0.0

    # Heuristics prediction
    heuristics_score, heuristics_rules = heuristics_model(url)

    # Combine ML and heuristics: prefer ML when available; default ML weight 0.6 if used else 0.0
    if ml_used:
        ml_weight = 0.6
        heuristics_weight = 0.4
    else:
        ml_weight = 0.0
        heuristics_weight = 1.0
    combined_score = (ml_score_ensemble * ml_weight) + (heuristics_score * heuristics_weight)
    combined_score = max(0.0, min(1.0, combined_score))
    # Tunable threshold for labelling as suspicious
    label = int(combined_score > settings.suspicious_threshold)

    # External checks
    gs_flag = 0
    vt_flag = 0
    vt_positives = 0
    vt_total = 0
    if body.run_safe_browsing and SAFE_BROWSING_KEY:
        gs_flag = 1 if google_safe_browsing_check(url) else 0
        if gs_flag:
            label = 1
            combined_score = max(combined_score, 0.9)
            print(f"[Predict] Safe Browsing flagged URL: {url[:50]}...")

    # Decide whether to call VirusTotal (default: True if key is present)
    use_vt = True
    if body.run_virustotal is not None:
        use_vt = bool(body.run_virustotal)

    if VIRUSTOTAL_KEY and use_vt:
        vt_malicious, vt_positives, vt_total, vt_permalink = virustotal_check(url)
        if vt_malicious:
            vt_flag = 1
            label = 1
            combined_score = max(combined_score, max(settings.block_threshold, 0.9))
            print(f"[Predict] VirusTotal flagged URL: {url[:50]}... ({vt_positives}/{vt_total})")

    # Generate reason and append ML warning if any
    reason = generate_reason(url, combined_score, label, heuristics_rules=heuristics_rules, gs_flag=bool(gs_flag), vt_flag=bool(vt_flag), vt_positives=vt_positives, vt_total=vt_total)
    if ml_warning:
        reason += f" | ML warning: {ml_warning}"

    # Log
    print(f"[Predict] URL: {url[:80]}..., ML used: {ml_used}, ML ensemble: {ml_score_ensemble:.4f}, Heuristics: {heuristics_score:.4f}, Combined: {combined_score:.4f}, Label: {label}, GSB: {bool(gs_flag)}, VT: {bool(vt_flag)}")

    # Save to DB (best-effort)
    ts = int(time.time())
    try:
        conn.execute("INSERT INTO scans (url, score, label, reason, google_safe, heuristics_score, ml_score, virustotal_flag, virustotal_positives, virustotal_total, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (url, combined_score, label, reason, gs_flag, heuristics_score, ml_score_ensemble, vt_flag, vt_positives, vt_total, ts))
        conn.commit()
    except sqlite3.Error as e:
        print(f"[Predict] Database error: {e}. Continuing without DB write.")

    result = {
        "url": url,
        "score": combined_score,
        "label": label,
        "reason": reason,
        "heuristics_score": heuristics_score,
        "heuristics_rules": heuristics_rules[:10] if heuristics_rules else [],
        "ml_used": ml_used,
        "ml_score_ensemble": ml_score_ensemble,
        "ml_scores_individual": ml_scores,
        "google_safe": bool(gs_flag),
        "virustotal_flag": bool(vt_flag),
        "virustotal_positives": vt_positives,
        "virustotal_total": vt_total,
        "ts": ts
    }
    return result

@app.get("/stats")
def stats():
    try:
        total_cur = conn.execute("SELECT COUNT(*) FROM scans")
        total = total_cur.fetchone()[0]
        suspicious_cur = conn.execute("SELECT COUNT(*) FROM scans WHERE label = 1")
        suspicious = suspicious_cur.fetchone()[0]
        safe = total - suspicious
        return {"total": total, "safe": safe, "suspicious": suspicious, "ml_available": bool(models and vect is not None)}
    except sqlite3.Error as e:
        print(f"[Stats] Database error: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/history")
def history(limit: int = 200):
    cur = conn.execute("SELECT id, url, score, label, reason, google_safe, heuristics_score, ml_score, virustotal_flag, virustotal_positives, virustotal_total, ts FROM scans ORDER BY ts DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    cols = ["id","url","score","label","reason","google_safe","heuristics_score","ml_score","virustotal_flag","virustotal_positives","virustotal_total","ts"]
    result = []
    for r in rows:
        row_dict = dict(zip(cols, r))
        if row_dict.get("heuristics_score") is None:
            row_dict["heuristics_score"] = row_dict.get("score", 0.0)
        if row_dict.get("ml_score") is None:
            row_dict["ml_score"] = row_dict.get("score", 0.0)
        if row_dict.get("virustotal_flag") is None:
            row_dict["virustotal_flag"] = 0
        if row_dict.get("virustotal_positives") is None:
            row_dict["virustotal_positives"] = 0
        if row_dict.get("virustotal_total") is None:
            row_dict["virustotal_total"] = 0
        result.append(row_dict)
    return result
