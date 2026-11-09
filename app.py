"""
Firewall Rule Drift Detection - web app
---------------------------------------
Serves the Tuned Random Forest trained in Firewall_project.ipynb.

The notebook did not save its LabelEncoder / StandardScaler, so they are
rebuilt here from the raw UNSW-NB15 training file using exactly the same
steps as the notebook (cells 17-23):
    drop attack_cat -> LabelEncoder on proto/service/state
    -> drop label, id -> StandardScaler on the 42 features

Explanations use SHAP (pip install shap):
    single flow  -> exact Tree SHAP (about 1-2 s for a 200-tree forest)
    uploaded CSV -> fast approximate Tree SHAP (Saabas), so large files stay quick
"""
import io
import json
import os
import uuid
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from flask import (Flask, Response, abort, jsonify, redirect,
                   render_template, request, url_for)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

try:
    import shap
    HAS_SHAP = True
except ImportError:  # the site still works, just without per-flow explanations
    HAS_SHAP = False

# ---------------------------------------------------------------------------
# Paths - change these two lines, or set the environment variables.
# ---------------------------------------------------------------------------
RAW_CSV = os.environ.get(
    "DRIFT_RAW_CSV",
    r"C:\Users\Advith\Downloads\Training and Testing Sets\UNSW_NB15_training-set.csv",
)
MODEL_PATH = os.environ.get("DRIFT_MODEL", r"C:\Users\Advith\rf_tuned_model.pkl")

# Small deploy files written by export_artifacts.py (used first when present)
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACTS = os.environ.get("DRIFT_ARTIFACTS", os.path.join(HERE, "artifacts", "drift_artifacts.joblib"))
DEPLOY_MODEL = os.environ.get("DRIFT_DEPLOY_MODEL", os.path.join(HERE, "artifacts", "rf_model.joblib"))

TEXT_COLS = ["proto", "service", "state"]
MAX_UPLOAD_ROWS = 200_000
SHAP_SAMPLE = 300        # flows used for the file-level SHAP summary
EXPLAIN_TOP = 10         # top-scoring flows explained one by one in a report

# Severity tiers from the paper (Table III)
TIERS = [
    {"name": "Low", "lo": 0.00, "hi": 0.30, "action": "Monitor only"},
    {"name": "Medium", "lo": 0.30, "hi": 0.60, "action": "Investigate"},
    {"name": "High", "lo": 0.60, "hi": 0.80, "action": "Alert"},
    {"name": "Critical", "lo": 0.80, "hi": 1.01, "action": "Immediate action"},
]

# The 42 UNSW-NB15 input features: (column, short name, meaning)
FEATURES = [
    ("dur", "Duration", "Total duration of the flow, in seconds"),
    ("proto", "Protocol", "Transport protocol, e.g. tcp, udp, arp, ospf"),
    ("service", "Service", "Application service, e.g. http, dns, ftp; '-' if none"),
    ("state", "State", "Connection state, e.g. FIN, INT, CON, REQ, RST"),
    ("spkts", "Source packets", "Packets sent from source to destination"),
    ("dpkts", "Destination packets", "Packets sent from destination to source"),
    ("sbytes", "Source bytes", "Bytes sent from source to destination"),
    ("dbytes", "Destination bytes", "Bytes sent from destination to source"),
    ("rate", "Packet rate", "Packets per second"),
    ("sttl", "Source TTL", "Time-to-live of source-to-destination packets"),
    ("dttl", "Destination TTL", "Time-to-live of destination-to-source packets"),
    ("sload", "Source load", "Source bits per second"),
    ("dload", "Destination load", "Destination bits per second"),
    ("sloss", "Source loss", "Source packets retransmitted or dropped"),
    ("dloss", "Destination loss", "Destination packets retransmitted or dropped"),
    ("sinpkt", "Source inter-packet time", "Mean time between source packets (ms)"),
    ("dinpkt", "Destination inter-packet time", "Mean time between destination packets (ms)"),
    ("sjit", "Source jitter", "Source jitter (ms)"),
    ("djit", "Destination jitter", "Destination jitter (ms)"),
    ("swin", "Source TCP window", "Source TCP window advertisement"),
    ("stcpb", "Source TCP base seq.", "Source TCP base sequence number"),
    ("dtcpb", "Destination TCP base seq.", "Destination TCP base sequence number"),
    ("dwin", "Destination TCP window", "Destination TCP window advertisement"),
    ("tcprtt", "TCP round-trip time", "TCP setup round-trip time (synack + ackdat)"),
    ("synack", "SYN to SYN-ACK time", "Time between SYN and SYN-ACK"),
    ("ackdat", "SYN-ACK to ACK time", "Time between SYN-ACK and ACK"),
    ("smean", "Source mean packet size", "Mean size of source packets (bytes)"),
    ("dmean", "Destination mean packet size", "Mean size of destination packets (bytes)"),
    ("trans_depth", "HTTP pipeline depth", "Depth of the HTTP request/response pipeline"),
    ("response_body_len", "HTTP response size", "Uncompressed size of the HTTP response body"),
    ("ct_srv_src", "Same service + source", "Connections with the same service and source in the last 100"),
    ("ct_state_ttl", "State/TTL count", "Count for each state within a TTL range"),
    ("ct_dst_ltm", "Same destination", "Connections to the same destination in the last 100"),
    ("ct_src_dport_ltm", "Same source + dest. port", "Same source address and destination port in the last 100"),
    ("ct_dst_sport_ltm", "Same dest. + source port", "Same destination address and source port in the last 100"),
    ("ct_dst_src_ltm", "Same source + destination", "Same source and destination address in the last 100"),
    ("is_ftp_login", "FTP login", "1 if an FTP session logged in with user and password, else 0"),
    ("ct_ftp_cmd", "FTP commands", "Flows with a command in an FTP session"),
    ("ct_flw_http_mthd", "HTTP methods", "Flows with HTTP methods such as GET and POST"),
    ("ct_src_ltm", "Same source", "Connections from the same source in the last 100"),
    ("ct_srv_dst", "Same service + destination", "Connections with the same service and destination in the last 100"),
    ("is_sm_ips_ports", "Same IPs and ports", "1 if source and destination IPs and ports are equal, else 0"),
]
FEATURE_NAME = {k: n for k, n, _ in FEATURES}

# Fields shown on the single-flow form (the rest default to training medians)
FORM_FIELDS = [
    ("proto", "Protocol", "text"),
    ("service", "Service", "text"),
    ("state", "Connection state", "text"),
    ("dur", "Duration (s)", "num"),
    ("spkts", "Source packets", "num"),
    ("dpkts", "Destination packets", "num"),
    ("sbytes", "Source bytes", "num"),
    ("dbytes", "Destination bytes", "num"),
    ("sttl", "Source TTL", "num"),
    ("dttl", "Destination TTL", "num"),
    ("rate", "Packet rate", "num"),
    ("sload", "Source load (bits/s)", "num"),
    ("ct_state_ttl", "State/TTL count (ct_state_ttl)", "num"),
    ("ct_srv_src", "Same-service connections (ct_srv_src)", "num"),
]


def tier_for(p):
    for t in TIERS:
        if t["lo"] <= p < t["hi"]:
            return t
    return TIERS[-1]


def _num(v):
    try:
        f = float(v)
        if not np.isfinite(f):
            return None
        return int(f) if f.is_integer() else float(f"{f:.4g}") if abs(f) < 1 else round(f, 2)
    except (TypeError, ValueError):
        return None


def build_state(raw_csv, demo_size=None):
    """Rebuild the notebook's preprocessing from the raw UNSW-NB15 CSV.
    demo_size: keep only this many held-out test flows (for a small deploy file)."""
    raw = pd.read_csv(raw_csv)
    df = raw.drop(columns=["attack_cat"])
    encoders = {}
    for col in TEXT_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    X = df.drop(columns=["label", "id"])
    columns = X.columns.tolist()
    scaler = StandardScaler().fit(X)

    # Medians (raw units) used to fill fields the form does not ask for
    medians = raw[columns].median(numeric_only=True)
    for col in TEXT_COLS:
        medians[col] = raw[col].mode()[0]
    options = {c: sorted(map(str, raw[c].unique())) for c in TEXT_COLS}

    # Held-out test rows (same split as the notebook) for the live demo
    _, test_idx = train_test_split(
        np.arange(len(df)), test_size=0.2, random_state=42, stratify=df["label"])
    demo = raw.iloc[test_idx].reset_index(drop=True)
    if demo_size and demo_size < len(demo):
        demo, _ = train_test_split(demo, train_size=demo_size, random_state=42,
                                   stratify=demo["label"])
        demo = demo.reset_index(drop=True)
    return {"encoders": encoders, "columns": columns, "scaler": scaler,
            "medians": medians, "options": options, "demo": demo}


class DriftModel:
    """Holds preprocessing + model; scores and explains raw UNSW-format rows."""

    def __init__(self, state, model):
        self.encoders = state["encoders"]
        self.columns = state["columns"]
        self.scaler = state["scaler"]
        self.medians = state["medians"]
        self.options = state["options"]
        self.demo = state["demo"]
        self.model = model
        self.explainer = shap.TreeExplainer(self.model) if HAS_SHAP else None

        # Score the test flows once, so the Detect page can offer real examples
        # that the model gets right (normal -> Low tier, attack -> Critical tier)
        self.demo_prob, _ = self.score(self.demo)

        # Template rows for the CSV guide: one normal flow, two attacks
        normal = self.demo[self.demo["label"] == 0].head(1)
        attack = self.demo[self.demo["label"] == 1].head(2)
        self.template = pd.concat([normal, attack])[self.columns + ["attack_cat", "label"]]

    # -- scoring ---------------------------------------------------------------
    def prepare(self, frame):
        """Raw UNSW-format DataFrame -> scaled 42-feature matrix."""
        frame = frame.copy()
        missing = [c for c in self.columns if c not in frame.columns]
        if missing:
            raise ValueError(
                "These columns are missing from the file: " + ", ".join(missing[:8])
                + (" and %d more" % (len(missing) - 8) if len(missing) > 8 else "")
                + ". See 'What the CSV needs' below.")
        for col in TEXT_COLS:
            known = set(self.encoders[col].classes_)
            values = frame[col].astype(str).str.strip()
            unknown = sorted(set(values) - known)
            if unknown:
                raise ValueError(
                    f"Unknown {col} value(s): {', '.join(unknown[:5])}. "
                    f"Use one of the values listed under 'Allowed text values'.")
            frame[col] = self.encoders[col].transform(values)
        X = frame[self.columns].apply(pd.to_numeric, errors="coerce")
        bad = X.columns[X.isna().any()].tolist()
        if bad:
            raise ValueError("Non-numeric or empty values in: " + ", ".join(bad[:8]))
        return pd.DataFrame(self.scaler.transform(X), columns=self.columns)

    def score(self, frame):
        Xs = self.prepare(frame)
        return self.model.predict_proba(Xs)[:, 1], Xs

    # -- explanations ---------------------------------------------------------
    def contributions(self, Xs, exact=False):
        """SHAP contribution of every feature toward 'drift' (class 1).
        Returns (n_rows, 42) array, or None when shap is not installed."""
        if self.explainer is None or len(Xs) == 0:
            return None
        sv = self.explainer.shap_values(Xs, approximate=not exact, check_additivity=False)
        if isinstance(sv, list):
            sv = sv[1]
        sv = np.asarray(sv)
        if sv.ndim == 3:
            sv = sv[:, :, 1]
        return sv

    def explain_row(self, raw_row, contrib, k=8):
        """Top-k features for one flow, signed (+ pushes toward drift)."""
        order = np.argsort(-np.abs(contrib))[:k]
        top = float(np.abs(contrib[order]).max()) or 1.0
        out = []
        for i in order:
            col = self.columns[i]
            v = raw_row.get(col)
            out.append({
                "feature": col,
                "name": FEATURE_NAME.get(col, col),
                "value": v if col in TEXT_COLS else _num(v),
                "contribution": round(float(contrib[i]), 4),
                "width": round(100 * abs(float(contrib[i])) / top, 1),
            })
        return out

    def describe(self, row, p):
        t = tier_for(p)
        return {
            "proto": str(row.get("proto", "")),
            "service": str(row.get("service", "")),
            "state": str(row.get("state", "")),
            "sttl": _num(row.get("sttl")),
            "sbytes": _num(row.get("sbytes")),
            "probability": round(float(p), 4),
            "drift": bool(p >= 0.5),
            "tier": t["name"],
            "action": t["action"],
        }


# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB
REPORTS = {}  # report_id -> dict (kept in memory while the app runs)

def load_model():
    """Deployed: use the small files made by export_artifacts.py.
    On the laptop: fall back to the raw CSV + original model."""
    if os.path.exists(ARTIFACTS) and os.path.exists(DEPLOY_MODEL):
        return DriftModel(joblib.load(ARTIFACTS), joblib.load(DEPLOY_MODEL))
    return DriftModel(build_state(RAW_CSV), joblib.load(MODEL_PATH))


DM, LOAD_ERROR = None, None
if not os.environ.get("DRIFT_SKIP_LOAD"):
    try:
        DM = load_model()
    except Exception as exc:  # show a clear page instead of crashing
        LOAD_ERROR = f"{type(exc).__name__}: {exc}"


@app.context_processor
def inject_globals():
    return {"tiers": TIERS, "load_error": LOAD_ERROR, "nav": request.endpoint,
            "has_shap": HAS_SHAP}


def need_model():
    if DM is None:
        abort(503)


@app.errorhandler(503)
def model_missing(_):
    return render_template("error.html", raw_csv=RAW_CSV, model_path=MODEL_PATH,
                           artifacts=ARTIFACTS, deploy_model=DEPLOY_MODEL), 503


def default_values():
    """Training medians for the form, rounded so they read cleanly."""
    out = {}
    for k, _, kind in FORM_FIELDS:
        v = DM.medians.get(k, "")
        out[k] = v if kind == "text" else _num(v)
    return out


def detect_page(**extra):
    """Render the Detect page with everything the CSV guide needs."""
    ctx = dict(fields=FORM_FIELDS, values=default_values(), options=DM.options,
               features=FEATURES, template=DM.template.to_dict("records"),
               template_cols=DM.columns[:9], result=None, error=None, upload_error=None,
               extras={}, example=None)
    ctx.update(extra)
    return render_template("detect.html", **ctx)


# -- pages ------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


def score_flow(row, values, extras=None, example=None):
    """Score one flow (all 42 features in `row`) and render the Detect page."""
    try:
        probs, Xs = DM.score(pd.DataFrame([row]))
        p = float(probs[0])
        result = DM.describe(row, p)
        contrib = DM.contributions(Xs, exact=True)
        if contrib is not None:
            result["why"] = DM.explain_row(row, contrib[0], k=8)
    except ValueError as exc:
        return detect_page(values=values, extras=extras or {}, error=str(exc))
    return detect_page(values=values, extras=extras or {}, result=result, example=example)


@app.route("/detect", methods=["GET", "POST"])
def detect():
    need_model()
    form_keys = {k for k, _, _ in FORM_FIELDS}

    if request.method == "GET":
        kind = request.args.get("example")
        if kind not in ("normal", "attack"):
            return detect_page()
        # A real held-out test flow the model classifies correctly
        if kind == "normal":
            pool = np.flatnonzero((DM.demo["label"] == 0).to_numpy() & (DM.demo_prob < 0.30))
        else:
            pool = np.flatnonzero((DM.demo["label"] == 1).to_numpy() & (DM.demo_prob >= 0.80))
        if len(pool) == 0:
            return detect_page(error="No suitable example found in the test set.")
        i = int(np.random.default_rng().choice(pool))
        src = DM.demo.iloc[i]
        row = DM.medians.copy()
        for c in DM.columns:
            row[c] = src[c]
        values = {k: (str(src[k]) if k in TEXT_COLS else _num(src[k])) for k in form_keys}
        extras = {c: src[c] for c in DM.columns if c not in form_keys}
        example = {"kind": kind, "actual": "Attack" if int(src["label"]) == 1 else "Normal",
                   "category": str(src.get("attack_cat", "")), "id": int(src.get("id", i))}
        return score_flow(row, values, extras, example)

    # POST: the visible form fields, plus any hidden fields from a loaded example
    row = DM.medians.copy()
    values, extras = {}, {}
    for c in DM.columns:
        if c in request.form:
            v = request.form.get(c, "").strip()
            row[c] = v
            if c in form_keys:
                values[c] = v
            else:
                extras[c] = v
    return score_flow(row, values, extras)


@app.route("/template.csv")
def template_csv():
    need_model()
    buf = io.StringIO()
    DM.template.to_csv(buf, index=False)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=drift_template.csv"})


@app.route("/upload", methods=["POST"])
def upload():
    need_model()
    f = request.files.get("file")
    if not f or not f.filename:
        return detect_page(upload_error="Choose a CSV file to upload.")
    try:
        frame = pd.read_csv(io.BytesIO(f.read()), nrows=MAX_UPLOAD_ROWS)
        frame.columns = [c.strip() for c in frame.columns]
        probs, Xs = DM.score(frame)
    except (ValueError, pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        return detect_page(upload_error=f"Could not score {f.filename}: {exc}")
    report = build_report(frame, probs, Xs, f.filename)
    rid = uuid.uuid4().hex[:12]
    REPORTS[rid] = report
    return redirect(url_for("report_page", rid=rid))


def build_report(frame, probs, Xs, source):
    n = len(frame)
    records = frame.to_dict("records")
    rows = []
    for i, (r, p) in enumerate(zip(records, probs)):
        d = DM.describe(r, p)
        d["row"] = i + 1  # line number in the file, counting the first data row as 1
        rows.append(d)

    counts = {t["name"]: 0 for t in TIERS}
    for r in rows:
        counts[r["tier"]] += 1

    # score histogram: 20 bins of 5 percentage points
    hist, _ = np.histogram(probs, bins=20, range=(0, 1))
    peak = int(hist.max()) or 1
    histogram = [{"lo": 5 * i, "hi": 5 * (i + 1), "count": int(c),
                  "height": round(100 * c / peak, 1),
                  "tier": tier_for((5 * i + 2.5) / 100)["name"]} for i, c in enumerate(hist)]

    report = {
        "source": source,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "flows": n,
        "flagged": int(sum(r["drift"] for r in rows)),
        "tiers": [{"name": t["name"], "action": t["action"], "count": counts[t["name"]],
                   "share": round(100 * counts[t["name"]] / n, 1) if n else 0}
                  for t in TIERS],
        "histogram": histogram,
        "rows": rows,
    }

    # -- SHAP: what drove the scores in this file ------------------------------
    if DM.explainer is not None and n:
        rng = np.random.default_rng(0)
        idx = np.sort(rng.choice(n, min(n, SHAP_SAMPLE), replace=False))
        sv = DM.contributions(Xs.iloc[idx])
        mean_abs = np.abs(sv).mean(axis=0)
        mean_signed = sv.mean(axis=0)
        order = np.argsort(-mean_abs)[:10]
        top = float(mean_abs[order[0]]) or 1.0
        report["shap_global"] = [{
            "feature": DM.columns[i], "name": FEATURE_NAME.get(DM.columns[i], DM.columns[i]),
            "value": round(float(mean_abs[i]), 4), "width": round(100 * mean_abs[i] / top, 1),
            "direction": "drift" if mean_signed[i] > 0 else "normal",
        } for i in order]
        report["shap_sample"] = len(idx)

        top_idx = np.argsort(-probs, kind="stable")[:EXPLAIN_TOP]  # same order as the report list
        sv_top = DM.contributions(Xs.iloc[top_idx])
        for j, i in enumerate(top_idx):
            rows[i]["why"] = DM.explain_row(records[i], sv_top[j], k=6)

    # -- labelled file: how the model did ---------------------------------------
    if "label" in frame.columns:
        y = pd.to_numeric(frame["label"], errors="coerce").fillna(-1).astype(int).to_numpy()
        pred = (probs >= 0.5).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
        fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 0
        rec = tp / (tp + fn) if tp + fn else 0
        report["evaluation"] = {
            "accuracy": round(100 * (tp + tn) / n, 2) if n else 0,
            "precision": round(100 * prec, 2),
            "recall": round(100 * rec, 2),
            "f1": round(100 * 2 * prec * rec / (prec + rec), 2) if prec + rec else 0,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        }
        if "attack_cat" in frame.columns:
            cats = frame["attack_cat"].fillna("Normal").astype(str).str.strip().replace("", "Normal")
            per = []
            for cat in sorted(cats.unique()):
                m = (cats == cat).to_numpy()
                expected = 0 if cat.lower() == "normal" else 1
                per.append({"name": cat, "count": int(m.sum()),
                            "rate": round(100 * float((pred[m] == expected).mean()), 2)})
            per.sort(key=lambda d: -d["rate"])
            report["categories"] = per
    return report


@app.route("/report/<rid>")
def report_page(rid):
    report = REPORTS.get(rid) or abort(404)
    top = sorted(report["rows"], key=lambda r: -r["probability"])[:200]
    return render_template("report.html", r=report, rid=rid, top=top)


@app.route("/report/<rid>.json")
def report_json(rid):
    report = REPORTS.get(rid) or abort(404)
    name = os.path.splitext(report["source"])[0] + "_drift_report.json"
    return Response(json.dumps(report, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@app.route("/results")
def results():
    return render_template("results.html")


@app.route("/method")
def method():
    return render_template("method.html")


# -- JSON API ---------------------------------------------------------------
@app.route("/api/samples")
def api_samples():
    need_model()
    n = min(int(request.args.get("n", 6)), 20)
    rng = np.random.default_rng()
    # mix of normal and attack rows so the demo shows both verdicts
    normal = DM.demo[DM.demo["label"] == 0]
    attack = DM.demo[DM.demo["label"] == 1]
    k = n // 2
    pick = pd.concat([normal.iloc[rng.choice(len(normal), k, replace=False)],
                      attack.iloc[rng.choice(len(attack), n - k, replace=False)]])
    pick = pick.sample(frac=1, random_state=int(rng.integers(1e9)))
    probs, _ = DM.score(pick)
    out = []
    for row, p in zip(pick.to_dict("records"), probs):
        d = DM.describe(row, p)
        d["actual"] = "Attack" if int(row["label"]) == 1 else "Normal"
        out.append(d)
    return jsonify(out)


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """POST a JSON object or list of objects in UNSW-NB15 column format.
    Missing fields are filled with training medians."""
    need_model()
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify(error="Send a JSON object or a list of objects."), 400
    items = payload if isinstance(payload, list) else [payload]
    rows = []
    for item in items:
        row = DM.medians.copy()
        for k, v in item.items():
            row[k] = v
        rows.append(row)
    frame = pd.DataFrame(rows)
    try:
        probs, _ = DM.score(frame)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify([DM.describe(r, p) for r, p in zip(frame.to_dict("records"), probs)])


if __name__ == "__main__":
    # Local use only. On a server, gunicorn runs the app (see Dockerfile).
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
