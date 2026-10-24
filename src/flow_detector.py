
import glob, os, re, sys
import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
MODEL_PATH = os.path.join(ROOT, "data", "flow_model.joblib")
RESULTS_PATH = os.path.join(ROOT, "output", "flow_detection_results.txt")


def _norm(label):

    return re.sub(r"[^a-z0-9]+", " ", str(label).lower()).strip()



LABELS = {
    "BENIGN":                   ("Benign", None),
    "PortScan":                 ("Reconnaissance", "T1595"),          # Active Scanning
    "FTP-Patator":              ("Credential Access", "T1110"),       # Brute Force
    "SSH-Patator":              ("Credential Access", "T1110"),
    "Web Attack Brute Force":   ("Credential Access", "T1110"),
    "Web Attack Sql Injection": ("Initial Access", "T1190"),          # Exploit Public-Facing Application
    "Web Attack XSS":           ("Initial Access", "T1190"),
    "Heartbleed":               ("Initial Access", "T1190"),
    "Infiltration":             ("Privilege Escalation", "T1068"),    # weak mapping, confidence is capped
    "Bot":                      ("Command and Control", "T1071"),     # Application Layer Protocol
    "DoS Hulk":                 ("Impact", "T1498"),                  # Network Denial of Service
    "DoS GoldenEye":            ("Impact", "T1498"),
    "DoS slowloris":            ("Impact", "T1498"),
    "DoS Slowhttptest":         ("Impact", "T1498"),
    "DDoS":                     ("Impact", "T1498"),
}
BY_NORM = {_norm(k): (k, *v) for k, v in LABELS.items()}     
UNCERTAIN = {"infiltration"}                                    
NOT_FEATURES = {"flow id", "source ip", "src ip", "destination ip", "dst ip", "timestamp", "source port",
                "src port", "unnamed 0", "_source", "label", "stage", "label_norm"}


def load_flows(path):
    if os.path.isfile(path):
        files = [path]
    else:
        files = sorted(sum((glob.glob(os.path.join(path, p)) for p in ("*.csv", "*.xlsx", "*.xls", "*.parquet")), []))
    if not files:
        raise FileNotFoundError(f"No .csv/.xlsx/.xls files found in {path}")
    frames = []
    for f in files:
        fl = f.lower()
        if fl.endswith((".xlsx", ".xls")):
            df = pd.read_excel(f)
        elif fl.endswith(".parquet"):
            df = pd.read_parquet(f)
        else:
            df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = df.columns.astype(str).str.strip()
        df["_source"] = os.path.basename(f)
        frames.append(df)
        print(f"  loaded {os.path.basename(f)}: {len(df):,} rows")
    return pd.concat(frames, ignore_index=True)


def _features(df, columns=None):
    drop = [c for c in df.columns if c.lower() in NOT_FEATURES]
    X = df.drop(columns=drop).apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    if columns is None:
        columns = [c for c in X.columns if X[c].notna().mean() > 0.5]
    return X.reindex(columns=columns).fillna(0).astype("float32"), columns


def train(path, test_path=None, max_per_label=25000, n_estimators=80, seed=0):
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    df = load_flows(path)
    if "Label" not in df.columns:
        raise ValueError("Training needs a 'Label' column (e.g. BENIGN, PortScan, DoS Hulk).")
    df["label_norm"] = df["Label"].map(_norm)
    unknown = sorted(set(df.label_norm) - set(BY_NORM))
    if unknown:
        print("WARNING - labels not in the mapping (ignored):", unknown)
    df = df[df.label_norm.isin(BY_NORM)].drop_duplicates()
    counts = df.label_norm.value_counts()
    keep = counts[counts >= 10].index
    for l in counts.index.difference(keep):
        print(f"WARNING - '{l}' has fewer than 10 rows, skipped")
    df = df[df.label_norm.isin(keep)]
    df = pd.concat([g.sample(min(len(g), max_per_label), random_state=seed) for _, g in df.groupby("label_norm")])
    X, columns = _features(df)
    y = df.label_norm.values
    if test_path:                                   
        te = load_flows(test_path)
        te["label_norm"] = te["Label"].map(_norm)
        te = te[te.label_norm.isin(BY_NORM)]
        Xtr, ytr = X, y
        Xte, _ = _features(te, columns); yte = te.label_norm.values
        how = f"separate test set ({len(te):,} rows)"
    else:
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)
        how = "random 25% of the rows (optimistic)"
    clf = RandomForestClassifier(n_estimators=n_estimators, n_jobs=-1, min_samples_leaf=3,
                                 class_weight="balanced_subsample", random_state=seed).fit(Xtr, ytr)
    pred = clf.predict(Xte)
    rep = classification_report(yte, pred, digits=3, zero_division=0)
    prec = {k: round(v["precision"], 3) for k, v in classification_report(yte, pred, output_dict=True, zero_division=0).items()
            if isinstance(v, dict) and k in clf.classes_}
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    note = ("\nNOTE: rows from the same attack are near-duplicates and the dataset's splits are random rows, so these scores\n"
            "are optimistic for brand-new traffic. Report them as 'on held-out rows of the same dataset'.\n"
            "Classes with only a handful of examples (e.g. Web Attack SQL Injection, Infiltration) are not reliable.\n")
    open(RESULTS_PATH, "w", encoding="utf-8").write(
        f"Training rows: {len(Xtr):,}   Features: {len(columns)}   Evaluated on: {how}\n\n{rep}{note}")
    joblib.dump({"model": clf, "columns": columns, "precision": prec}, MODEL_PATH, compress=3)
    print(rep + note + f"\nSaved model -> {MODEL_PATH}")


def detect(path_or_df, min_flows=20, min_prob=0.8):
    import joblib
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("data/flow_model.joblib not found. Train first: python -m src.flow_detector train <your-data-folder>")
    b = joblib.load(MODEL_PATH); clf = b["model"]; prec = b.get("precision", {})
    df = load_flows(path_or_df) if isinstance(path_or_df, str) else path_or_df
    X, _ = _features(df, b["columns"])
    labels, probs = [], []
    for i in range(0, len(X), 100000):
        p = clf.predict_proba(X.iloc[i:i + 100000])
        labels += list(clf.classes_[p.argmax(1)]); probs += list(p.max(1))
    s = pd.DataFrame({"label": labels, "p": probs})
    total = max(len(s), 1)
    out = []
    from .attack_names import name
    for lab, g in s[s.p >= min_prob].groupby("label"):
        display, stage, tech = BY_NORM[lab]
        pr = prec.get(lab, 0.8)
        need_share = 0.01 if pr >= 0.9 else 0.05
        if tech is None or len(g) < min_flows or len(g) / total < need_share:
            continue
        conf = float(np.clip(g.p.mean() * pr, 0.3, 0.95))
        if lab in UNCERTAIN:
            conf = min(conf, 0.4)
        out.append({"technique": tech, "name": name(tech), "tactic": stage, "confidence": round(conf, 2),
                    "evidence": [f"{len(g):,} of {total:,} network flows ({len(g)/total:.1%}) classified as {display} "
                                 f"(mean probability {g.p.mean():.2f}, model precision for this type {pr:.2f})"],
                    "source": "network-flow", "type": "observed-network-detection"})
    return merge_mappings(out)


def merge_mappings(mappings):
    merged = {}
    for m in mappings:
        k = m["technique"]
        if k in merged:
            merged[k]["evidence"] = merged[k]["evidence"] + m["evidence"]
            merged[k]["confidence"] = round(min(0.95, max(merged[k]["confidence"], m["confidence"]) + 0.05), 2)
        else:
            merged[k] = dict(m, evidence=list(m["evidence"]))
    return list(merged.values())


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] not in ("train", "detect"):
        sys.exit(__doc__)
    if sys.argv[1] == "train":
        test = sys.argv[sys.argv.index("--test") + 1] if "--test" in sys.argv else None
        train(sys.argv[2], test_path=test)
    else:
        for m in detect(sys.argv[2]):
            print(m["technique"], m["name"], m["confidence"], "|", "; ".join(m["evidence"]))
