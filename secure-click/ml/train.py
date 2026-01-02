"""
Train script for Secure-Click using Bagging + Boosting (AdaBoost + GradientBoosting).
Saves artifacts to backend/models/

Usage:
  python ml/train.py
"""
import os
import re
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    accuracy_score,
    precision_score,
    recall_score,
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import BaggingClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.utils import resample
from sklearn.feature_extraction.text import CountVectorizer
from scipy.sparse import hstack

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SECURE_CLICK_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(SECURE_CLICK_DIR, "data")
BACKEND_MODELS = os.path.join(SECURE_CLICK_DIR, "backend", "models")
os.makedirs(BACKEND_MODELS, exist_ok=True)

# Candidate data files (common names)
DATA_FILES = [
    os.path.join(DATA_DIR, "dataset.csv"),
    os.path.join(DATA_DIR, "dataset_full.csv"),
    os.path.join(DATA_DIR, "dataset_small.csv"),
]

def load_csv(path):
    try:
        df = pd.read_csv(path, low_memory=False)
        print(f"Loaded {os.path.basename(path)} -> {df.shape}")
        return df
    except Exception as e:
        print(f"Failed to load {path}: {e}")
        return None

def find_label_column(df):
    # Common label names
    for cand in ["label", "phishing", "is_phish", "is_phishing", "target", "class", "y"]:
        if cand in df.columns:
            return cand
    # heuristics: pick a column with only 0/1 values
    for c in df.columns:
        uniques = df[c].dropna().unique()
        if len(uniques) <= 3 and set(map(str, uniques)).issubset(set(["0","1","0.0","1.0","true","false","True","False"])):
            return c
    return None

def to_binary_series(s):
    def conv(v):
        try:
            v2 = str(v).strip().lower()
            if v2 in ("1","1.0","true","t","yes","y","phishing","malicious"):
                return 1
            if v2 in ("0","0.0","false","f","no","n","benign","legitimate","good"):
                return 0
            return int(float(v))
        except Exception:
            return 0
    return s.apply(conv)

def lexical_features_from_urls(urls):
    """Simple lexical features derivable from raw URL string."""
    urls = urls.astype(str)
    url_len = urls.apply(len).values.reshape(-1,1)
    count_dots = urls.apply(lambda s: s.count('.')).values.reshape(-1,1)
    has_at = urls.apply(lambda s: 1 if "@" in s else 0).values.reshape(-1,1)
    count_hyphen = urls.apply(lambda s: s.count('-')).values.reshape(-1,1)
    has_ip = urls.apply(lambda s: 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s) else 0).values.reshape(-1,1)
    count_slash = urls.apply(lambda s: s.count('/')).values.reshape(-1,1)
    return np.hstack([url_len, count_dots, has_at, count_hyphen, has_ip, count_slash])

def select_numeric_tabular_features(df, exclude=None):
    if exclude is None:
        exclude = []
    numerics = df.select_dtypes(include=[np.number]).columns.tolist()
    # keep numeric features except label-like and exclude
    return [c for c in numerics if c not in exclude]

def train_tabular_ensemble(X_train, y_train):
    print("Training Bagging (DecisionTree base)...")
    base_dt = DecisionTreeClassifier(max_depth=8, random_state=42)
    model_bag = BaggingClassifier(estimator=base_dt, n_estimators=100, random_state=42, n_jobs=-1)
    model_bag.fit(X_train, y_train)

    print("Training AdaBoost...")
    # Newer versions of scikit-learn use the 'estimator' argument instead of 'base_estimator'
    model_ada = AdaBoostClassifier(
        estimator=DecisionTreeClassifier(max_depth=4, random_state=42),
        n_estimators=200,
        learning_rate=0.5,
        random_state=42,
    )
    model_ada.fit(X_train, y_train)

    print("Training GradientBoosting...")
    model_gb = GradientBoostingClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42)
    model_gb.fit(X_train, y_train)

    # Optional probability calibration (Platt/isotonic scaling) on top of each model.
    # This refits a small calibration model using cross-validation to improve probability estimates.
    print("Calibrating probability estimates (isotonic, 3-fold CV)...")
    model_bag = CalibratedClassifierCV(estimator=model_bag, cv=3, method="isotonic")
    model_bag.fit(X_train, y_train)

    model_ada = CalibratedClassifierCV(estimator=model_ada, cv=3, method="isotonic")
    model_ada.fit(X_train, y_train)

    model_gb = CalibratedClassifierCV(estimator=model_gb, cv=3, method="isotonic")
    model_gb.fit(X_train, y_train)

    return model_bag, model_ada, model_gb

def evaluate_models(models, X_test, y_test, names):
    results = {}
    probs = {}
    for m, name in zip(models, names):
        try:
            y_pred = m.predict(X_test)
            y_prob = m.predict_proba(X_test)[:,1] if hasattr(m, "predict_proba") else m.decision_function(X_test)
        except Exception:
            # fallback: use decision_function if no predict_proba
            try:
                y_prob = m.decision_function(X_test)
                y_pred = (y_prob > 0.5).astype(int)
            except Exception:
                y_pred = np.zeros_like(y_test)
                y_prob = np.zeros_like(y_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_test, y_prob)
        except Exception:
            auc = 0.0
        results[name] = {'accuracy': acc, 'precision': prec, 'recall': rec, 'auc': auc}
        probs[name] = y_prob
        print(f"\n{name} Classification Report:\n", classification_report(y_test, y_pred, digits=4))
        print(f"{name} metrics: Acc={acc:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, AUC={auc:.4f}")
    return results, probs

def find_best_ensemble(probs_dict, y_test):
    # probs_dict: name->prob_array
    names = list(probs_dict.keys())
    p_arrays = [probs_dict[n] for n in names]
    best_auc = 0.0
    best_weights = None
    best_metrics = None
    # try some weight combinations
    combos = [
        (0.33,0.33,0.34),
        (0.5,0.25,0.25),
        (0.25,0.5,0.25),
        (0.25,0.25,0.5),
        (0.4,0.3,0.3),
        (0.6,0.2,0.2),
        (0.2,0.6,0.2),
        (0.2,0.2,0.6),
    ]
    # add performance normalized combination
    aucs = []
    for arr in p_arrays:
        try:
            aucs.append(roc_auc_score(y_test, arr))
        except Exception:
            aucs.append(0.0)
    if sum(aucs) > 0:
        total = sum(aucs)
        combos.append(tuple(a/total for a in aucs))

    for w in combos:
        # normalize to length
        if len(w) != len(p_arrays):
            continue
        total_w = sum(w)
        ws = [wi/total_w for wi in w]
        ensemble_prob = np.zeros_like(p_arrays[0])
        for wi, pa in zip(ws, p_arrays):
            ensemble_prob += wi * pa
        try:
            auc = roc_auc_score(y_test, ensemble_prob)
            pred = (ensemble_prob > 0.5).astype(int)
            acc = accuracy_score(y_test, pred)
            prec = precision_score(y_test, pred, zero_division=0)
            rec = recall_score(y_test, pred, zero_division=0)
            if auc > best_auc:
                best_auc = auc
                best_weights = dict(zip(names, ws))
                best_metrics = {'accuracy': acc, 'precision': prec, 'recall': rec, 'auc': auc}
        except Exception:
            continue
    return best_weights, best_metrics

def main():
    print("="*60)
    print("Secure-Click: Bagging + Boosting Trainer")
    print("="*60)
    print("Data candidates:")
    for p in DATA_FILES:
        print(f"  {'[OK]' if os.path.exists(p) else '[MISSING]'} {p}")
    print("="*60)

    frames = []
    for p in DATA_FILES:
        if os.path.exists(p):
            df = load_csv(p)
            if df is not None:
                frames.append(df)
    if not frames:
        raise SystemExit("No data files found in data/ — add CSVs and re-run.")

    df = pd.concat(frames, ignore_index=True)
    print("Concatenated shape (before cleaning):", df.shape)

    # ------------------------------------------------------------------
    # Basic dataset hygiene: de-duplicate and class-balance
    # ------------------------------------------------------------------
    # 1) Remove exact duplicate rows to avoid biased training on repeated samples.
    before_dedup = len(df)
    # If URL column exists, de-duplicate by URL; otherwise de-duplicate full rows.
    if "url" in df.columns:
        df = df.drop_duplicates(subset=["url"])
    else:
        df = df.drop_duplicates()
    after_dedup = len(df)
    if after_dedup != before_dedup:
        print(f"Removed {before_dedup - after_dedup} duplicate rows.")

    # find label column
    label_col = find_label_column(df)
    if not label_col:
        raise SystemExit("No label column found. Rename your label column to 'phishing' or 'label' or one of common names.")
    print("Using label column:", label_col)

    # If there's a 'url' column -> URL mode
    if 'url' in df.columns:
        mode = "url"
    else:
        mode = "tabular"
    print("Detected mode:", mode)

    # Standardize label
    df = df.dropna(subset=[label_col]).copy()
    df['label_bin'] = to_binary_series(df[label_col])

    if df['label_bin'].nunique() < 2:
        raise SystemExit("Need at least two label classes in data to train.")

    # 2) Simple class balancing via undersampling if there is strong imbalance.
    class_counts = df['label_bin'].value_counts()
    print("Class distribution before balancing:", class_counts.to_dict())
    if len(class_counts) == 2:
        maj_class = class_counts.idxmax()
        min_class = class_counts.idxmin()
        ratio = class_counts.max() / max(class_counts.min(), 1)
        if ratio > 1.5:
            print(f"Imbalance detected (ratio ~{ratio:.2f}). Undersampling majority class {maj_class}...")
            df_majority = df[df['label_bin'] == maj_class]
            df_minority = df[df['label_bin'] == min_class]
            # Undersample majority down to minority count
            df_majority_down = resample(
                df_majority,
                replace=False,
                n_samples=len(df_minority),
                random_state=42,
            )
            df = pd.concat([df_majority_down, df_minority], ignore_index=True)
            df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
            print("Class distribution after balancing:", df['label_bin'].value_counts().to_dict())
        else:
            print("Class balance is acceptable; no undersampling applied.")
    else:
        print("More than two label classes detected; skipping simple balancing.")

    if mode == "url":
        # URL mode: vectorize char ngrams and combine lexical features
        vect = CountVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=3000)
        X_text = vect.fit_transform(df['url'].astype(str))
        X_lex = lexical_features_from_urls(df['url'].astype(str))
        X = hstack([X_text, X_lex])
        y = df['label_bin'].values

        # Hold-out evaluation with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )

        # Optional cross-validation for a more robust estimate (printed only)
        print("\nRunning 3-fold stratified CV (AUC) for reference...")
        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        for name, estimator in [
            ("bagging", BaggingClassifier(estimator=DecisionTreeClassifier(max_depth=8, random_state=42), n_estimators=100, random_state=42, n_jobs=-1)),
            ("adaboost", AdaBoostClassifier(estimator=DecisionTreeClassifier(max_depth=4, random_state=42), n_estimators=200, learning_rate=0.5, random_state=42)),
            ("gradboost", GradientBoostingClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42)),
        ]:
            cv_scores = cross_val_score(estimator, X_train, y_train, cv=skf, scoring="roc_auc", n_jobs=-1)
            print(f"{name} CV AUC: mean={cv_scores.mean():.4f}, std={cv_scores.std():.4f}")

        model_bag, model_ada, model_gb = train_tabular_ensemble(X_train, y_train)
        results, probs = evaluate_models([model_bag, model_ada, model_gb], X_test, y_test, ['bagging','adaboost','gradboost'])

        best_weights, best_metrics = find_best_ensemble(probs, y_test)
        if best_weights is None:
            best_weights = {'bagging': 0.33, 'adaboost': 0.33, 'gradboost': 0.34}
            best_metrics = {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'auc': 0.0}

        # Save artifacts using names expected by backend/app.py
        joblib.dump(model_bag, os.path.join(BACKEND_MODELS, "model_bagging.joblib"))
        joblib.dump(model_ada, os.path.join(BACKEND_MODELS, "model_adaboost.joblib"))
        joblib.dump(model_gb, os.path.join(BACKEND_MODELS, "model_gb.joblib"))
        joblib.dump(vect, os.path.join(BACKEND_MODELS, "url_vectorizer.joblib"))

        # Save metadata
        meta = {'mode': 'url', 'features': 'vectorizer+lexical'}
        with open(os.path.join(BACKEND_MODELS, "model_metadata.json"), 'w') as f:
            json.dump(meta, f, indent=2)

    else:
        # Tabular mode: use numeric columns (excluding label) for training
        exclude = [label_col, 'label_bin']
        numeric_cols = select_numeric_tabular_features(df, exclude=exclude)
        if not numeric_cols:
            raise SystemExit("No numeric columns found for tabular training.")
        print(f"Using numeric tabular features (count={len(numeric_cols)}). Sample: {numeric_cols[:10]}")

        X_all = df[numeric_cols].fillna(-1).astype(float).values
        y = df['label_bin'].values

        # scaler for numeric features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_all)

        # Hold-out evaluation with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, stratify=y, random_state=42
        )

        # Optional cross-validation for a more robust estimate (printed only)
        print("\nRunning 3-fold stratified CV (AUC) for reference...")
        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        for name, estimator in [
            ("bagging", BaggingClassifier(estimator=DecisionTreeClassifier(max_depth=8, random_state=42), n_estimators=100, random_state=42, n_jobs=-1)),
            ("adaboost", AdaBoostClassifier(estimator=DecisionTreeClassifier(max_depth=4, random_state=42), n_estimators=200, learning_rate=0.5, random_state=42)),
            ("gradboost", GradientBoostingClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42)),
        ]:
            cv_scores = cross_val_score(estimator, X_train, y_train, cv=skf, scoring="roc_auc", n_jobs=-1)
            print(f"{name} CV AUC: mean={cv_scores.mean():.4f}, std={cv_scores.std():.4f}")

        model_bag, model_ada, model_gb = train_tabular_ensemble(X_train, y_train)
        results, probs = evaluate_models([model_bag, model_ada, model_gb], X_test, y_test, ['bagging','adaboost','gradboost'])

        best_weights, best_metrics = find_best_ensemble(probs, y_test)
        if best_weights is None:
            best_weights = {'bagging': 0.33, 'adaboost': 0.33, 'gradboost': 0.34}
            best_metrics = {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'auc': 0.0}

        # Save tabular models + scaler + feature list
        joblib.dump(model_bag, os.path.join(BACKEND_MODELS, "model_bagging.joblib"))
        joblib.dump(model_ada, os.path.join(BACKEND_MODELS, "model_adaboost.joblib"))
        joblib.dump(model_gb, os.path.join(BACKEND_MODELS, "model_gb.joblib"))
        # Backend expects this scaler under the name feature_scaler.joblib
        joblib.dump(scaler, os.path.join(BACKEND_MODELS, "feature_scaler.joblib"))

        feature_list = numeric_cols
        with open(os.path.join(BACKEND_MODELS, "tabular_features.json"), 'w') as f:
            json.dump(feature_list, f, indent=2)

        # Try to find a small subset of "computable from URL" features (if present in dataset)
        candidates = [
            'length_url','qty_dot_url','qty_hyphen_url','qty_underline_url','qty_slash_url',
            'qty_questionmark_url','qty_equal_url','qty_at_url','qty_and_url','qty_exclamation_url',
            'qty_space_url','qty_tld_url','email_in_url'
        ]
        compute_feats = [c for c in candidates if c in numeric_cols]
        if len(compute_feats) >= 3:
            print("Training small lexical fallback model using features:", compute_feats)
            X_small = df[compute_feats].fillna(-1).astype(float).values
            # scale small
            scaler_small = StandardScaler()
            X_small_s = scaler_small.fit_transform(X_small)
            # Train a compact ensemble (use Bagging+Ada+GB but for speed we will train a single Bagging here)
            small_model = BaggingClassifier(estimator=DecisionTreeClassifier(max_depth=6), n_estimators=100, random_state=42, n_jobs=-1)
            small_model.fit(X_small_s, y)
            # save fallback model, scaler and features
            joblib.dump(small_model, os.path.join(BACKEND_MODELS, "url_lexical_model.joblib"))
            joblib.dump(scaler_small, os.path.join(BACKEND_MODELS, "url_lexical_scaler.joblib"))
            with open(os.path.join(BACKEND_MODELS, "url_lexical_features.json"), 'w') as f:
                json.dump(compute_feats, f, indent=2)
            print("Saved lexical fallback model with features:", compute_feats)
        else:
            print("Not enough computable URL features present in tabular dataset; lexical fallback model will not be created.")

        # Save metadata
        meta = {'mode': 'tabular', 'feature_count': len(numeric_cols)}
        with open(os.path.join(BACKEND_MODELS, "model_metadata.json"), 'w') as f:
            json.dump(meta, f, indent=2)

    # Save ensemble weights & per-model metrics in a backend-compatible format
    weights_config = {
        # Top-level simple mapping for backend.app to read directly
        'bagging': float(best_weights.get('bagging', 0.33)),
        'adaboost': float(best_weights.get('adaboost', 0.33)),
        'gradboost': float(best_weights.get('gradboost', 0.34)),
        # Extra metadata preserved under nested keys (ignored by backend if not needed)
        'ensemble': {
            'weights': {
                'bagging': float(best_weights.get('bagging', 0.33)),
                'adaboost': float(best_weights.get('adaboost', 0.33)),
                'gradboost': float(best_weights.get('gradboost', 0.34)),
            },
            'metrics': best_metrics,
        },
        'individual_model_metrics': results if 'results' in locals() else {}
    }
    with open(os.path.join(BACKEND_MODELS, "ensemble_weights.json"), 'w') as f:
        json.dump(weights_config, f, indent=2)

    print("\nSaved artifacts to:", BACKEND_MODELS)
    print(" - model_bagging.joblib")
    print(" - model_adaboost.joblib")
    print(" - model_gb.joblib")
    if os.path.exists(os.path.join(BACKEND_MODELS, "url_vectorizer.joblib")):
        print(" - url_vectorizer.joblib")
    if os.path.exists(os.path.join(BACKEND_MODELS, "feature_scaler.joblib")):
        print(" - feature_scaler.joblib")
    if os.path.exists(os.path.join(BACKEND_MODELS, "url_lexical_model.joblib")):
        print(" - url_lexical_model.joblib (fallback for URL-only predictions)")
    print(" - ensemble_weights.json")
    print(" - model_metadata.json")
    print("Training completed successfully!")

if __name__ == "__main__":
    main()
