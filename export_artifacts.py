"""
Prepare the website for deployment. Run ONCE on the laptop that has the
dataset and the trained model, from the same Python environment as the notebook:

    python export_artifacts.py

It creates:
    artifacts/drift_artifacts.joblib  encoders, scaler, medians and 4,000 held-out
                                      test flows - everything the site needs from the
                                      dataset, so the 175k-row CSV is not deployed
    artifacts/rf_model.joblib         compressed copy of rf_tuned_model.pkl
    requirements.txt                  pinned to this laptop's library versions
    Dockerfile                        uses this laptop's Python version

The pins matter: a scikit-learn model must be loaded with the same scikit-learn
(and numpy) version that saved it.
"""
import os
import platform
import sys

os.environ["DRIFT_SKIP_LOAD"] = "1"  # import app.py without starting the model
import joblib  # noqa: E402

import app as site  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "artifacts")
DEMO_FLOWS = 4000


def mb(path):
    return os.path.getsize(path) / 1024 / 1024


def version(dist):
    from importlib.metadata import PackageNotFoundError, version as v
    try:
        return v(dist)
    except PackageNotFoundError:
        return None


def main():
    os.makedirs(OUT, exist_ok=True)

    print(f"Reading {site.RAW_CSV} ...")
    state = site.build_state(site.RAW_CSV, demo_size=DEMO_FLOWS)
    a_path = os.path.join(OUT, "drift_artifacts.joblib")
    joblib.dump(state, a_path, compress=3)
    print(f"  wrote {a_path}  ({mb(a_path):.1f} MB)")

    print(f"Loading {site.MODEL_PATH} ...")
    model = joblib.load(site.MODEL_PATH)
    m_path = os.path.join(OUT, "rf_model.joblib")
    joblib.dump(model, m_path, compress=3)
    print(f"  wrote {m_path}  ({mb(m_path):.1f} MB, original {mb(site.MODEL_PATH):.1f} MB)")

    # Quick check: the exported files give the same scores as the originals
    check = site.DriftModel(joblib.load(a_path), joblib.load(m_path))
    sample = state["demo"].head(200)
    p_new, _ = check.score(sample)
    p_old = model.predict_proba(check.prepare(sample))[:, 1]
    assert abs(p_new - p_old).max() < 1e-9, "exported model gives different scores"
    print("  check passed: exported model scores match the original")

    # Pin versions so the server loads the model exactly as this laptop does
    pins = {
        "flask": version("flask") or "3.0.3",
        "gunicorn": "22.0.0",
        "pandas": version("pandas"),
        "numpy": version("numpy"),
        "scikit-learn": version("scikit-learn"),
        "joblib": version("joblib"),
        "shap": version("shap"),
    }
    with open(os.path.join(HERE, "requirements.txt"), "w") as f:
        for pkg, ver in pins.items():
            if ver:
                f.write(f"{pkg}=={ver}\n")
    print("  wrote requirements.txt:", ", ".join(f"{k} {v}" for k, v in pins.items() if v))

    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    with open(os.path.join(HERE, "Dockerfile"), "w") as f:
        f.write(DOCKERFILE.format(py=py))
    print(f"  wrote Dockerfile (Python {py}, {platform.system()} laptop)")

    size = mb(m_path)
    print()
    if size > 100:
        print(f"NOTE: rf_model.joblib is {size:.0f} MB, over GitHub's 100 MB limit.")
        print("      The included .gitattributes stores it with Git LFS - see README, step 2.")
    print("Done. Next: follow 'Deploy' in README.md.")


DOCKERFILE = """# Hugging Face Spaces (Docker) - also works on any Docker host
FROM python:{py}-slim

RUN useradd -m -u 1000 user
USER user
ENV PATH=/home/user/.local/bin:$PATH \\
    PYTHONUNBUFFERED=1
WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .

EXPOSE 7860
# One worker so uploaded reports stay in the same process; threads for concurrency
CMD ["gunicorn", "-w", "1", "--threads", "4", "--timeout", "180", "-b", "0.0.0.0:7860", "app:app"]
"""

if __name__ == "__main__":
    main()
