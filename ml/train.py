# ml/train.py
"""
Train a simple URL phishing detector and save artifacts to backend/models/
Usage:
  python ml/train.py
"""

import os
import re
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Get the secure-click directory (parent of ml/)
SECURE_CLICK_DIR = os.path.dirname(SCRIPT_DIR)

# Set up paths relative to the script location
DATA_DIR = os.path.join(SECURE_CLICK_DIR, "data")
BACKEND_DIR = os.path.join(SECURE_CLICK_DIR, "backend")
MODELS_DIR = os.path.join(BACKEND_DIR, "models")

DATA_FILES = [
    os.path.join(DATA_DIR, "malicious_phish.csv"),
    os.path.join(DATA_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv"),
    os.path.join(DATA_DIR, "secureclick_dataset.csv")
]

OUT_DIR = MODELS_DIR
os.makedirs(OUT_DIR, exist_ok=True)

def load_and_normalize(path):
    df = pd.read_csv(path, low_memory=False)
    # find URL column
    url_col = None
    for cand in ["url", "URL", "Url", "link", "link_url"]:
        if cand in df.columns:
            url_col = cand
            break
    if url_col is None:
        url_col = df.columns[0]
    # find label column
    label_col = None
    for cand in ["label", "type", "class", "is_phish"]:
        if cand in df.columns:
            label_col = cand
            break
    # copy and standardize
    df2 = df[[c for c in df.columns if c is not None]].copy()
    df2 = df2.rename(columns={url_col: "url"})
    if label_col:
        df2 = df2.rename(columns={label_col: "label"})
    else:
        # try infer from 'type'
        if "type" in df2.columns:
            df2["label"] = df2["type"].apply(lambda v: 1 if str(v).strip().lower() not in ("benign", "good", "legitimate", "0", "none") else 0)
        else:
            # if no label present, drop
            df2["label"] = np.nan
    return df2[["url", "label"]]

def unify_datasets(paths):
    frames = []
    for p in paths:
        try:
            if not os.path.exists(p):
                print(f"Warning: File not found: {p}")
                continue
            df = load_and_normalize(p)
            if df is not None and not df.empty:
                frames.append(df)
                print(f"Loaded {os.path.basename(p)} -> {df.shape}")
            else:
                print(f"Warning: Empty dataset from {os.path.basename(p)}")
        except Exception as e:
            print(f"Failed to load {os.path.basename(p)}: {e}")
    
    if not frames:
        raise ValueError("No valid datasets could be loaded. Please check the data files exist in the data/ directory.")
    
    unified = pd.concat(frames, ignore_index=True)
    unified = unified.dropna(subset=["url"]).drop_duplicates(subset=["url"]).reset_index(drop=True)
    # drop rows with missing labels
    unified = unified[unified['label'].notnull()].copy()
    # try to convert labels to binary ints
    def to_bin(v):
        try:
            s = str(v).strip().lower()
            if s in ("1","true","phishing","phish","malicious","attack"):
                return 1
            if s in ("0","false","benign","legitimate","good"):
                return 0
        except:
            pass
        try:
            return int(float(v))
        except:
            return 0
    unified['label'] = unified['label'].apply(to_bin)
    print("Unified dataset shape after cleaning:", unified.shape)
    return unified

def lexical_features(urls_series):
    urls = urls_series.astype(str)
    url_len = urls.apply(len).values.reshape(-1,1)
    count_dots = urls.apply(lambda s: s.count('.')).values.reshape(-1,1)
    has_at = urls.apply(lambda s: 1 if "@" in s else 0).values.reshape(-1,1)
    count_hyphen = urls.apply(lambda s: s.count('-')).values.reshape(-1,1)
    has_ip = urls.apply(lambda s: 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s) else 0).values.reshape(-1,1)
    return np.hstack([url_len, count_dots, has_at, count_hyphen, has_ip])

def main():
    print("=" * 60)
    print("Secure-Click Model Training")
    print("=" * 60)
    print(f"Data directory: {DATA_DIR}")
    print(f"Output directory: {OUT_DIR}")
    print(f"Looking for data files:")
    for f in DATA_FILES:
        exists = "[OK]" if os.path.exists(f) else "[MISSING]"
        print(f"  {exists} {os.path.basename(f)}")
    print("=" * 60)
    
    df = unify_datasets(DATA_FILES)
    if df.shape[0] < 50:
        raise SystemExit("Not enough labeled data found. Check CSVs in data/")

    # vectorize URL (char ngrams)
    vect = CountVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=2000)
    X_text = vect.fit_transform(df['url'].astype(str))
    X_nums = lexical_features(df['url'])
    X = hstack([X_text, X_nums])
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)

    model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss', n_estimators=200, max_depth=6, verbosity=0)
    print("Training XGBoost...")
    model.fit(X_train, y_train)

    print("Predicting on test set...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:,1]

    print(classification_report(y_test, y_pred, digits=4))
    try:
        print("ROC AUC:", roc_auc_score(y_test, y_prob))
    except Exception:
        pass

    print("Saving artifacts...")
    joblib.dump(model, os.path.join(OUT_DIR, "model_xgb.joblib"))
    joblib.dump(vect, os.path.join(OUT_DIR, "url_vectorizer.joblib"))
    print("Saved to", OUT_DIR)

if __name__ == "__main__":
    main()
