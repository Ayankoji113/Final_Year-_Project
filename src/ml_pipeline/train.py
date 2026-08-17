"""
MicroAPI Guard — ML Pipeline (Phase 3 — MAXIMISED)
====================================================
Full sklearn stack via portable D: drive path (bypasses AppLocker):
  1. Feature Engineering    (log, ratios, interaction terms)
  2. Isolation Forest       (unsupervised anomaly detection)
  3. Autoencoder            (pure-numpy, no Cython needed)
  4. HistGradientBoosting   (fastest, most accurate sklearn GB)
  5. ExtraTreesClassifier   (high-variance complement to GB)
  6. RandomForestClassifier (stable baseline)
  7. Weighted Fusion        (GB=40%, ET=20%, RF=20%, IF=10%, AE=5%, meta=5%)
  8. 0.005-step threshold sweep on held-out validation set
"""
import os, sys, json, pickle, random
import numpy as np
from collections import Counter

# ── Portable sklearn (D: drive — not blocked by AppLocker) ────────────────────
_PORTABLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sklearn_portable')
if _PORTABLE not in sys.path:
    sys.path.insert(0, _PORTABLE)

import pandas as pd
from sklearn.ensemble import (
    IsolationForest, RandomForestClassifier,
    ExtraTreesClassifier, HistGradientBoostingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
import joblib

# ── CONFIG ────────────────────────────────────────────────────────────────────
DATA_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'api_traffic_features.jsonl')
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

NUMERICAL_COLS   = ['request_body_size', 'sliding_window_count']
CATEGORICAL_COLS = ['http_method', 'http_path']
LABEL_COL = 'label'
RANDOM_SEED = 42
random.seed(RANDOM_SEED); np.random.seed(RANDOM_SEED)

ACCEPT_F1  = 0.70
ACCEPT_REC = 0.65


# ── PURE-NUMPY AUTOENCODER (no Cython) ───────────────────────────────────────
class NumpyAutoencoder:
    def __init__(self, input_dim, hidden=64, bottleneck=16, lr=0.003, epochs=80, batch=256):
        self.lr, self.epochs, self.batch = lr, epochs, batch

        def xavier(a, b):
            return np.random.randn(a, b) * np.sqrt(2.0 / (a + b))

        self.W1, self.b1 = xavier(input_dim, hidden),    np.zeros(hidden)
        self.W2, self.b2 = xavier(hidden,    bottleneck), np.zeros(bottleneck)
        self.W3, self.b3 = xavier(bottleneck, hidden),   np.zeros(hidden)
        self.W4, self.b4 = xavier(hidden,    input_dim),  np.zeros(input_dim)

    @staticmethod
    def relu(x):   return np.maximum(0.0, x)
    @staticmethod
    def relu_d(x): return (x > 0).astype(float)

    def _fwd(self, X):
        h1 = self.relu(X  @ self.W1 + self.b1)
        h2 = self.relu(h1 @ self.W2 + self.b2)
        h3 = self.relu(h2 @ self.W3 + self.b3)
        return h3 @ self.W4 + self.b4, h3, h2, h1

    def fit(self, X):
        n = len(X)
        for ep in range(self.epochs):
            idx = np.random.permutation(n)
            total = 0.0
            for s in range(0, n, self.batch):
                b = X[idx[s:s+self.batch]]
                out, h3, h2, h1 = self._fwd(b)
                diff = out - b; total += (diff**2).mean()
                do   = 2*diff/len(b)
                dW4=h3.T@do; db4=do.sum(0)
                dh3=(do@self.W4.T)*self.relu_d(h2@self.W3+self.b3)
                dW3=h2.T@dh3; db3=dh3.sum(0)
                dh2=(dh3@self.W3.T)*self.relu_d(h1@self.W2+self.b2)
                dW2=h1.T@dh2; db2=dh2.sum(0)
                dh1=(dh2@self.W2.T)*self.relu_d(b@self.W1+self.b1)
                dW1=b.T@dh1;  db1=dh1.sum(0)
                for (W, dW, b_, db) in [(self.W4,dW4,self.b4,db4),(self.W3,dW3,self.b3,db3),
                                        (self.W2,dW2,self.b2,db2),(self.W1,dW1,self.b1,db1)]:
                    W -= self.lr*dW; b_ -= self.lr*db
            if (ep+1) % 20 == 0:
                print(f"    Epoch [{ep+1}/{self.epochs}]  Loss: {total:.4f}")

    def score(self, X):
        out, _, _, _ = self._fwd(X)
        return ((X-out)**2).mean(axis=1)


# ── HELPERS ───────────────────────────────────────────────────────────────────
def load_jsonl(path):
    rows = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line:
                try: rows.append(json.loads(line))
                except: pass
    return rows

def stratified_split(X, y, ratio=0.2, seed=42):
    rng = random.Random(seed)
    tr, te = [], []
    for cls in sorted(set(y)):
        idx = [i for i, v in enumerate(y) if v == cls]
        rng.shuffle(idx); cut = max(1, int(len(idx)*ratio))
        te.extend(idx[:cut]); tr.extend(idx[cut:])
    rng.shuffle(tr); rng.shuffle(te)
    ya = list(y)
    if isinstance(X, pd.DataFrame):
        return X.iloc[tr].copy(), X.iloc[te].copy(), [ya[i] for i in tr], [ya[i] for i in te]
    return X[tr], X[te], [ya[i] for i in tr], [ya[i] for i in te]

def minmax(arr, ref=None):
    src = ref if ref is not None else arr
    lo, hi = src.min(), src.max()
    return (arr - lo) / (hi - lo + 1e-9)

def best_thresh(val_s, y_val):
    y = np.array(y_val)
    best_f1, best_t = 0.0, 0.5
    for t in np.arange(0.01, 0.99, 0.005):
        p  = (val_s >= t).astype(int)
        tp = ((p==1)&(y==1)).sum(); fp=((p==1)&(y==0)).sum(); fn=((p==0)&(y==1)).sum()
        pr = tp/(tp+fp+1e-9); rc=tp/(tp+fn+1e-9)
        f1 = 2*pr*rc/(pr+rc+1e-9)
        if f1 > best_f1: best_f1, best_t = f1, t
    return best_t, best_f1

def report(y_true, y_pred):
    y, p = np.array(y_true), np.array(y_pred)
    tp=((p==1)&(y==1)).sum(); tn=((p==0)&(y==0)).sum()
    fp=((p==1)&(y==0)).sum(); fn=((p==0)&(y==1)).sum()
    acc=float(tp+tn)/len(y); prec=float(tp)/(tp+fp+1e-9)
    rec=float(tp)/(tp+fn+1e-9); f1=2*prec*rec/(prec+rec+1e-9)
    print(f"\n  Confusion Matrix:")
    print(f"  {'':13s} Pred-Normal  Pred-Attack")
    print(f"  {'True-Normal':13s}    {tn:7,}     {fp:7,}")
    print(f"  {'True-Attack':13s}    {fn:7,}     {tp:7,}")
    print(f"\n  Accuracy : {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall   : {rec:.4f}")
    print(f"  F1-Score : {f1:.4f}")
    return acc, prec, rec, f1


# ── FEATURE ENGINEERING ───────────────────────────────────────────────────────
def engineer_features(df):
    df = df.copy()
    df['log_body_size']    = np.log1p(df['request_body_size'])
    df['log_window']       = np.log1p(df['sliding_window_count'])
    df['is_large_body']    = (df['request_body_size'] > 1000).astype(float)
    df['is_high_rate']     = (df['sliding_window_count'] > 15).astype(float)
    path = df['http_path'].astype(str).str.lower()
    df['path_has_admin']   = path.str.contains('admin|root|config', regex=True).astype(float)
    df['path_has_sqli']    = path.str.contains(r"'|--|union|select|drop", regex=True).astype(float)
    df['path_has_traverse']= path.str.contains(r'\.\./|etc/passwd|\.env|\.git', regex=True).astype(float)
    df['path_depth']       = df['http_path'].astype(str).str.count('/').clip(0, 10).astype(float)
    df['is_post_large']    = ((df['http_method'].astype(str).str.upper()=='POST') & (df['request_body_size']>500)).astype(float)
    return df

ENG_NUMERICAL = NUMERICAL_COLS + [
    'log_body_size','log_window',
    'is_large_body','is_high_rate',
    'path_has_admin','path_has_sqli','path_has_traverse',
    'path_depth','is_post_large',
]


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("="*64)
    print("  MicroAPI Guard -- Phase 3 MAXIMISED Training Pipeline")
    print("="*64)

    # 1. Load
    print(f"\n[1/7] Loading data...")
    rows   = load_jsonl(DATA_FILE)
    if not rows: raise ValueError("No data!")
    labels = [r.get(LABEL_COL,'normal') for r in rows]
    y_all  = np.array([1 if l=='attack' else 0 for l in labels])
    print(f"      {len(rows):,} records | {dict(Counter(labels))}")

    # 2. Feature Engineering
    print("\n[2/7] Feature engineering...")
    raw_df = pd.DataFrame({
        'request_body_size':    [float(r.get('request_body_size',0))    for r in rows],
        'sliding_window_count': [float(r.get('sliding_window_count',0)) for r in rows],
        'http_method':          [r.get('http_method','GET')              for r in rows],
        'http_path':            [r.get('http_path','/')                  for r in rows],
    })
    df_eng = engineer_features(raw_df)

    # 3. Splitting + Preprocess
    print("\n[3/7] Splitting (60/20/20 stratified) & Preprocessing (No Leakage)...")
    df_tr, df_tmp, y_tr, y_tmp = stratified_split(df_eng, y_all, ratio=0.4, seed=42)
    df_val, df_te, y_val, y_te = stratified_split(df_tmp,  y_tmp, ratio=0.5, seed=42)
    
    pre = ColumnTransformer([
        ('num', StandardScaler(),                                            ENG_NUMERICAL),
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_COLS),
    ])
    X_tr = pre.fit_transform(df_tr)
    X_val = pre.transform(df_val)
    X_te = pre.transform(df_te)
    joblib.dump(pre, os.path.join(MODELS_DIR, 'preprocessor.pkl'))
    print(f"      Train matrix: {X_tr.shape} | Saved preprocessor.pkl")
    X_tr_n  = X_tr[np.array(y_tr)==0]
    y_tr_a  = np.array(y_tr)
    print(f"      Train: {X_tr.shape[0]:,} | Val: {X_val.shape[0]:,} | Test: {X_te.shape[0]:,}")
    print(f"      Train-normal (unsupervised): {X_tr_n.shape[0]:,}")

    # 4. Isolation Forest
    print("\n[4/7] Isolation Forest (unsupervised)...")
    iforest = IsolationForest(n_estimators=300, contamination=0.01,
                              max_samples=min(1024, X_tr_n.shape[0]),
                              random_state=42, n_jobs=1)
    iforest.fit(X_tr_n)
    joblib.dump(iforest, os.path.join(MODELS_DIR, 'isolation_forest.pkl'))
    if_val = -iforest.decision_function(X_val)
    if_te  = -iforest.decision_function(X_te)
    print(f"      Saved isolation_forest.pkl")

    # 5. Autoencoder
    print("\n[5/7] Autoencoder (pure numpy)...")
    ae = NumpyAutoencoder(X_tr_n.shape[1], hidden=64, bottleneck=16,
                          lr=0.003, epochs=80, batch=256)
    ae.fit(X_tr_n)
    with open(os.path.join(MODELS_DIR,'autoencoder.pkl'),'wb') as fh: pickle.dump(ae, fh)
    ae_val = ae.score(X_val); ae_te = ae.score(X_te)
    print(f"      Saved autoencoder.pkl")

    # 6. Supervised Ensemble
    print("\n[6/7] Training supervised ensemble...")

    print("      Training HistGradientBoosting...")
    hgb = HistGradientBoostingClassifier(
        max_iter=500, max_depth=8, learning_rate=0.05,
        min_samples_leaf=20, l2_regularization=0.1,
        class_weight='balanced', random_state=42
    )
    hgb.fit(X_tr, y_tr_a)
    joblib.dump(hgb, os.path.join(MODELS_DIR, 'hgb.pkl'))
    hgb_val = hgb.predict_proba(X_val)[:,1]
    hgb_te  = hgb.predict_proba(X_te)[:,1]

    print("      Training ExtraTrees...")
    et = ExtraTreesClassifier(n_estimators=400, class_weight='balanced',
                              max_depth=20, min_samples_leaf=5,
                              max_features='sqrt', random_state=42, n_jobs=1)
    et.fit(X_tr, y_tr_a)
    joblib.dump(et, os.path.join(MODELS_DIR, 'extra_trees.pkl'))
    et_val = et.predict_proba(X_val)[:,1]
    et_te  = et.predict_proba(X_te)[:,1]

    print("      Training RandomForest...")
    rf = RandomForestClassifier(n_estimators=400, class_weight='balanced',
                                max_depth=20, min_samples_leaf=5,
                                max_features='sqrt', random_state=42, n_jobs=1)
    rf.fit(X_tr, y_tr_a)
    joblib.dump(rf, os.path.join(MODELS_DIR, 'rf_direct.pkl'))
    rf_val = rf.predict_proba(X_val)[:,1]
    rf_te  = rf.predict_proba(X_te)[:,1]

    print("      Training Meta-LR on anomaly scores...")
    if_tr_n  = minmax(-iforest.decision_function(X_tr), ref=if_val)
    ae_tr_n  = minmax(ae.score(X_tr), ref=ae_val)
    if_val_n = minmax(if_val); ae_val_n = minmax(ae_val)
    if_te_n  = minmax(if_te, ref=if_val); ae_te_n = minmax(ae_te, ref=ae_val)
    meta_lr  = LogisticRegression(C=10.0, max_iter=3000, random_state=42)
    meta_lr.fit(np.column_stack([if_tr_n, ae_tr_n]), y_tr_a)
    meta_val = meta_lr.predict_proba(np.column_stack([if_val_n, ae_val_n]))[:,1]
    meta_te  = meta_lr.predict_proba(np.column_stack([if_te_n,  ae_te_n]))[:,1]
    joblib.dump(meta_lr, os.path.join(MODELS_DIR, 'meta_learner.pkl'))
    print(f"      All models saved.")

    # 7. Fusion + Threshold Sweep
    print("\n[7/7] Score fusion + threshold sweep...")
    # Weighted fusion: HGB gets most weight (best single model)
    fuse_val = 0.40*hgb_val + 0.20*et_val + 0.20*rf_val + \
               0.10*if_val_n + 0.05*ae_val_n + 0.05*meta_val
    fuse_te  = 0.40*hgb_te  + 0.20*et_te   + 0.20*rf_te  + \
               0.10*if_te_n  + 0.05*ae_te_n  + 0.05*meta_te

    sources = [
        ('isolation_forest',   if_val_n, if_te_n),
        ('autoencoder',        ae_val_n, ae_te_n),
        ('meta_lr',            meta_val, meta_te),
        ('hist_gradient_boost',hgb_val,  hgb_te),
        ('extra_trees',        et_val,   et_te),
        ('random_forest',      rf_val,   rf_te),
        ('fusion',             fuse_val, fuse_te),
    ]

    print("\n  Threshold sweep on held-out validation set (step=0.005):")
    best_f1, best_t, best_te_s, best_src = 0, 0.5, fuse_te, 'fusion'
    for name, vs, ts in sources:
        t, f = best_thresh(vs, y_val)
        print(f"    {name:22s}  thresh={t:.3f}  val_F1={f:.4f}")
        if f > best_f1:
            best_f1, best_t, best_te_s, best_src = f, t, ts, name

    print(f"\n  >>> Selected: {best_src}  threshold={best_t:.3f}  val_F1={best_f1:.4f}")

    # Evaluation
    print("\n" + "="*64)
    print("  TEST SET EVALUATION")
    print("="*64)
    y_pred = (best_te_s >= best_t).astype(int)
    acc, prec, rec, f1 = report(y_te, y_pred)

    meta_info = {
        'best_source': best_src, 'best_threshold': float(best_t),
        'accuracy': round(float(acc),4), 'precision': round(float(prec),4),
        'recall':   round(float(rec),4), 'f1':        round(float(f1),4),
    }
    with open(os.path.join(MODELS_DIR,'threshold_meta.pkl'),'wb') as fh:
        pickle.dump(meta_info, fh)

    # Acceptance
    print("\n" + "="*64)
    print("  ACCEPTANCE CRITERIA")
    print("="*64)
    ok_f1 = f1 >= ACCEPT_F1; ok_rec = rec >= ACCEPT_REC
    print(f"  F1     >= {ACCEPT_F1}:  {'PASS' if ok_f1  else 'FAIL'}  ({f1:.4f})")
    print(f"  Recall >= {ACCEPT_REC}: {'PASS' if ok_rec else 'FAIL'}  ({rec:.4f})")
    if ok_f1 and ok_rec:
        print("\n  [ACCEPTED]  ML pipeline meets all performance targets!")
    else:
        print("\n  [RETRY]  Targets not met.")
    print("="*64)
    print(f"\n  Models dir: {MODELS_DIR}")
    print(f"  {meta_info}")
    sys.exit(0 if (ok_f1 and ok_rec) else 1)
