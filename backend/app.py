# backend/app.py
"""
FastAPI backend for Secure-Click (local).
Run with:
  uvicorn backend.app:app --reload --port 8000
"""

import os
import time
import re
import sqlite3
import joblib
import numpy as np
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scipy.sparse import hstack
from typing import Optional

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "model_xgb.joblib")
VECT_PATH = os.path.join(BASE_DIR, "models", "url_vectorizer.joblib")

if not os.path.exists(MODEL_PATH) or not os.path.exists(VECT_PATH):
    raise SystemExit(f"Model artifacts missing. Expected:\n  {MODEL_PATH}\n  {VECT_PATH}\n\nRun ml/train.py first to generate these files.")

model = joblib.load(MODEL_PATH)
vect = joblib.load(VECT_PATH)

app = FastAPI(title="Secure-Click Local API", version="0.1")

# Add CORS middleware to allow requests from dashboard and extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
              ts INTEGER)''')
# Add new columns if they don't exist (for existing databases)
try:
    conn.execute("ALTER TABLE scans ADD COLUMN heuristics_score REAL")
    conn.execute("ALTER TABLE scans ADD COLUMN ml_score REAL")
except sqlite3.OperationalError:
    pass  # Columns already exist
conn.commit()

class UrlRequest(BaseModel):
    url: str
    run_safe_browsing: Optional[bool] = False

def lexical_numeric(url):
    url = str(url)
    url_len = len(url)
    count_dots = url.count('.')
    has_at = 1 if "@" in url else 0
    count_hyphen = url.count('-')
    has_ip = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
    return np.array([[url_len, count_dots, has_at, count_hyphen, has_ip]])

def heuristics_model(url):
    """
    Heuristics-based model using predefined rules to detect suspicious URLs.
    Returns a score between 0.0 (safe) and 1.0 (suspicious) and a list of triggered rules.
    """
    url_str = str(url).lower()
    score = 0.0
    triggered_rules = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain_lower = domain.lower()
        path = parsed.path.lower()
    except:
        domain = ""
        domain_lower = url_str
        path = ""
    
    # Rule 1: IP address instead of domain (highly suspicious)
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str):
        score += 0.3
        triggered_rules.append("IP address used instead of domain name")
    
    # Rule 2: @ symbol in URL (unusual, often used in obfuscation)
    if "@" in url_str:
        score += 0.25
        triggered_rules.append("Contains '@' symbol")
    
    # Rule 3: Excessive hyphens (common in typosquatting)
    hyphen_count = url_str.count('-')
    if hyphen_count > 5:
        score += 0.15
        triggered_rules.append(f"Excessive hyphens ({hyphen_count})")
    elif hyphen_count > 3:
        score += 0.08
        triggered_rules.append(f"Multiple hyphens ({hyphen_count})")
    
    # Rule 4: Excessive subdomains (subdomain abuse)
    dot_count = domain_lower.count('.')
    if dot_count > 4:
        score += 0.2
        triggered_rules.append(f"Excessive subdomains ({dot_count} dots)")
    elif dot_count > 3:
        score += 0.1
        triggered_rules.append(f"Multiple subdomains ({dot_count} dots)")
    
    # Rule 5: Suspicious domain patterns (brand impersonation)
    suspicious_brands = ['paypal', 'bank', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay', 'amazon', 'visa', 'mastercard']
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
                # Check for suspicious patterns
                if (re.search(rf'{brand}[.\-]', domain_lower) or 
                    re.search(rf'[.\-]{brand}[.\-]', domain_lower) or 
                    domain_lower.startswith(brand + '-')):
                    score += 0.25
                    triggered_rules.append(f"Suspicious {brand} domain pattern")
                    break
    
    # Rule 6: Suspicious path keywords
    phishing_keywords = ['verify', 'secure', 'login', 'account', 'update', 'confirm', 'suspended', 'locked', 'validate', 'authenticate']
    keyword_matches = [kw for kw in phishing_keywords if kw in url_str]
    if keyword_matches:
        if len(keyword_matches) >= 2:
            score += 0.15
            triggered_rules.append(f"Multiple suspicious keywords: {', '.join(keyword_matches[:3])}")
        else:
            score += 0.08
            triggered_rules.append(f"Suspicious keyword: {keyword_matches[0]}")
    
    # Rule 7: URL length anomalies
    if len(url_str) > 100:
        score += 0.1
        triggered_rules.append(f"Unusually long URL ({len(url_str)} chars)")
    elif len(url_str) < 15:
        score += 0.05
        triggered_rules.append(f"Very short URL ({len(url_str)} chars)")
    
    # Rule 8: Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download']
    if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
        score += 0.15
        triggered_rules.append("Suspicious top-level domain")
    
    # Rule 9: Mixed case obfuscation (e.g., PayPAL.com)
    if url != url.lower() and url != url.upper():
        # Check if it's intentional obfuscation (not just normal capitalization)
        if re.search(r'[a-z][A-Z]|[A-Z][a-z]', url):
            score += 0.05
            triggered_rules.append("Mixed case obfuscation detected")
    
    # Rule 10: Numeric domain (suspicious)
    if re.match(r'^https?://\d+\.', url_str):
        score += 0.2
        triggered_rules.append("Numeric domain detected")
    
    # Rule 11: Short URL services (potential redirect)
    short_url_services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
    if any(service in domain_lower for service in short_url_services):
        score += 0.1
        triggered_rules.append("URL shortener detected")
    
    # Rule 12: HTTPS check (positive indicator)
    if url_str.startswith('https://'):
        score -= 0.05  # Reduce suspicion slightly
        triggered_rules.append("Uses HTTPS (positive)")
    
    # Rule 13: Common trusted TLDs (positive indicator)
    trusted_tlds = ['.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.in', '.au']
    if any(domain_lower.endswith(tld) for tld in trusted_tlds) and score < 0.3:
        score -= 0.05  # Reduce suspicion for trusted TLDs
        triggered_rules.append("Trusted domain extension")
    
    # Normalize score to [0, 1] range
    score = max(0.0, min(1.0, score))
    
    return score, triggered_rules

def generate_reason(url, prob, label):
    """
    Generate a human-readable reason for why a URL is classified as safe or malicious.
    """
    url_str = str(url).lower()
    reasons = []
    
    # Extract domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain_lower = domain.lower()
    except:
        domain = ""
        domain_lower = url_str
    
    # Check for suspicious patterns
    suspicious_keywords = ['paypal', 'bank', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay']
    phishing_patterns = ['verify', 'secure', 'login', 'account', 'update', 'confirm', 'suspended', 'locked']
    
    # Check for typosquatting/phishing patterns
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
            # Check if it's a legitimate domain (exact match or subdomain of legitimate domain)
            is_legitimate = False
            for legit in legitimate_domains.get(keyword, []):
                # Check if domain is exactly the legitimate domain or a subdomain of it
                # e.g., "paypal.com" or "www.paypal.com" should match "paypal.com"
                if domain_lower == legit or domain_lower.endswith('.' + legit):
                    is_legitimate = True
                    break
            
            if not is_legitimate:
                # Check for suspicious patterns like paypal.com.account.verify or paypal-verify.com
                # but exclude legitimate domains we already checked
                if (re.search(rf'{keyword}[.\-]', domain_lower) or 
                    re.search(rf'[.\-]{keyword}[.\-]', domain_lower) or 
                    domain_lower.startswith(keyword + '-')):
                    has_suspicious_domain = True
                    reasons.append(f"Suspicious domain pattern detected (potential {keyword} phishing)")
                    break
    
    # Check for IP address in URL (highly suspicious)
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str):
        reasons.append("IP address used instead of domain name")
    
    # Check for @ symbol (unusual in URLs)
    if "@" in url_str:
        reasons.append("Contains '@' symbol (unusual in URLs)")
    
    # Check for excessive hyphens
    hyphen_count = url_str.count('-')
    if hyphen_count > 5:
        reasons.append(f"Unusually high number of hyphens ({hyphen_count})")
    
    # Check for excessive dots (subdomain abuse)
    dot_count = domain_lower.count('.')
    if dot_count > 4:
        reasons.append(f"Excessive subdomains ({dot_count} dots in domain)")
    
    # Check for suspicious path patterns
    if any(pattern in url_str for pattern in phishing_patterns):
        if has_suspicious_domain or prob > 0.6:
            reasons.append("Contains suspicious path patterns (verify/login/account)")
    
    # Check URL length
    if len(url_str) > 100:
        reasons.append("Unusually long URL")
    elif len(url_str) < 15:
        reasons.append("Very short URL")
    
    # Check for HTTPS (positive indicator, but only mention if safe)
    if label == 0 and url_str.startswith('https://'):
        reasons.append("Uses HTTPS encryption")
    
    # Check for common TLDs (positive indicator for safe sites)
    common_tlds = ['.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.in']
    has_common_tld = any(domain_lower.endswith(tld) for tld in common_tlds)
    
    if label == 1:
        # Malicious indicators
        if prob > 0.8:
            reasons.append("Very high malicious probability score")
        elif prob > 0.6:
            reasons.append("High malicious probability score")
        
        if not reasons:
            # Fallback reasons for malicious
            if prob > 0.7:
                reasons.append("High risk score from ML model analysis")
            else:
                reasons.append("Moderate risk indicators detected")
    else:
        # Safe indicators
        if prob < 0.2:
            reasons.append("Very low risk score")
        elif prob < 0.4:
            reasons.append("Low risk score")
        
        if has_common_tld and not has_suspicious_domain:
            reasons.append("Uses common trusted domain extension")
        
        if not reasons:
            # Fallback reasons for safe
            reasons.append("No significant threat indicators detected")
    
    # Add Google Safe Browsing status if available
    # (This will be added later in the predict function)
    
    # Combine reasons
    if reasons:
        reason_text = "; ".join(reasons)
    else:
        reason_text = f"ML model score: {prob:.4f}"
    
    return reason_text

# Optional: Google Safe Browsing check (requires API KEY). Set env var SAFE_BROWSING_API_KEY to enable
import requests
SAFE_BROWSING_KEY = os.environ.get("SAFE_BROWSING_API_KEY", None)
if SAFE_BROWSING_KEY:
    print(f"[Secure-Click] Google Safe Browsing API enabled (key: {SAFE_BROWSING_KEY[:10]}...)")
else:
    print("[Secure-Click] Google Safe Browsing API disabled (set SAFE_BROWSING_API_KEY env var to enable)")
# TTL cache for Safe Browsing lookups to reduce quota/latency
SAFE_BROWSING_TTL_SECONDS = int(os.environ.get("SAFE_BROWSING_TTL_SECONDS", "3600"))  # default 1 hour
_safe_cache = {}  # url -> (flag: bool, ts: int)
def google_safe_browsing_check(url):
    if not SAFE_BROWSING_KEY:
        return False
    # Check cache first
    now = int(time.time())
    cached = _safe_cache.get(url)
    if cached and (now - cached[1] < SAFE_BROWSING_TTL_SECONDS):
        return cached[0]
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
        r = requests.post(endpoint, json=payload, timeout=10)
        if r.status_code == 200:
            response_data = r.json()
            # Google Safe Browsing returns {} (empty dict) if no threats found
            # Returns {"matches": [...]} if threats are found
            if response_data and "matches" in response_data and len(response_data["matches"]) > 0:
                result_flag = True
                print(f"[Safe Browsing] URL flagged: {url[:50]}...")
            else:
                result_flag = False
        elif r.status_code == 400:
            error_data = r.json() if r.text else {}
            print(f"[Safe Browsing] API error 400: {error_data.get('error', {}).get('message', 'Bad request')}")
        elif r.status_code == 403:
            print(f"[Safe Browsing] API error 403: Invalid API key or quota exceeded")
        else:
            print(f"[Safe Browsing] API error {r.status_code}: {r.text[:100]}")
    except requests.exceptions.Timeout:
        print(f"[Safe Browsing] Timeout checking URL: {url[:50]}...")
        result_flag = False
    except requests.exceptions.RequestException as e:
        print(f"[Safe Browsing] Request error: {str(e)[:100]}")
        result_flag = False
    except Exception as e:
        print(f"[Safe Browsing] Unexpected error: {str(e)[:100]}")
        result_flag = False
    # Update cache
    _safe_cache[url] = (result_flag, now)
    return result_flag

@app.get("/health")
def health():
    return {"status":"ok", "time": int(time.time())}

@app.post("/predict")
def predict(body: UrlRequest):
    url = body.url
    if not url or not str(url).startswith(("http://","https://")):
        # still handle bare domains
        url = str(url).strip()
    
    # ML Model Prediction
    X_text = vect.transform([url])
    X_num = lexical_numeric(url)
    X = hstack([X_text, X_num])
    try:
        ml_score = float(model.predict_proba(X)[:,1][0])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model error: {e}")
    
    # Heuristics Model Prediction
    heuristics_score, heuristics_rules = heuristics_model(url)
    
    # Combine ML and Heuristics scores (weighted average)
    # ML model gets 60% weight, Heuristics gets 40% weight
    ml_weight = 0.6
    heuristics_weight = 0.4
    combined_score = (ml_score * ml_weight) + (heuristics_score * heuristics_weight)
    
    # Determine label based on combined score
    label = int(combined_score > 0.5)
    
    # Check Google Safe Browsing first (before generating reason, so we can include it)
    gs_flag = 0
    if body.run_safe_browsing and SAFE_BROWSING_KEY:
        gs_flag = 1 if google_safe_browsing_check(url) else 0
        if gs_flag:
            label = 1  # Override label if Safe Browsing flags it
            print(f"[Predict] URL {url[:50]}... flagged by Safe Browsing, overriding label to suspicious")
    
    # Generate meaningful reason (after Safe Browsing check so we know the final label)
    reason = generate_reason(url, combined_score, label)
    
    # Add heuristics findings to reason
    if heuristics_rules:
        heuristics_summary = "; ".join(heuristics_rules[:5])  # Limit to first 5 rules
        if len(heuristics_rules) > 5:
            heuristics_summary += f" (+{len(heuristics_rules) - 5} more)"
        reason += f" | Heuristics: {heuristics_summary}"
    
    # Add Safe Browsing status to reason if checked
    if body.run_safe_browsing and SAFE_BROWSING_KEY:
        if gs_flag:
            reason += " | Flagged by Google Safe Browsing API"
    
    # Log for debugging
    print(f"[Predict] URL: {url[:50]}..., ML Score: {ml_score:.4f}, Heuristics Score: {heuristics_score:.4f}, Combined: {combined_score:.4f}, Label: {label}, Safe Browsing: {bool(gs_flag)}")
    
    ts = int(time.time())
    conn.execute("INSERT INTO scans (url, score, label, reason, google_safe, heuristics_score, ml_score, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (url, combined_score, label, reason, gs_flag, heuristics_score, ml_score, ts))
    conn.commit()
    return {
        "url": url, 
        "score": combined_score, 
        "ml_score": ml_score,
        "heuristics_score": heuristics_score,
        "label": label, 
        "reason": reason, 
        "google_safe": bool(gs_flag), 
        "ts": ts
    }

@app.get("/history")
def history(limit: int = 100):
    cur = conn.execute("SELECT id, url, score, label, reason, google_safe, heuristics_score, ml_score, ts FROM scans ORDER BY ts DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    cols = ["id","url","score","label","reason","google_safe","heuristics_score","ml_score","ts"]
    # Handle old records that might not have heuristics_score/ml_score
    result = []
    for r in rows:
        row_dict = dict(zip(cols, r))
        # Set defaults for missing columns
        if row_dict.get("heuristics_score") is None:
            row_dict["heuristics_score"] = row_dict.get("score", 0.0)
        if row_dict.get("ml_score") is None:
            row_dict["ml_score"] = row_dict.get("score", 0.0)
        result.append(row_dict)
    return result
