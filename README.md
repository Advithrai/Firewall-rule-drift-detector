---
title: Rule Drift Detector
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

# Rule Drift Detector

A website for the project *Firewall Rule Drift Detection Using a Hybrid
Semi-Supervised Machine Learning Framework* (NMAMIT, Department of Cyber Security).
It runs the Tuned Random Forest from the notebook and scores network flows in
UNSW-NB15 format, with SHAP explanations.

Authors: Varshitha B A, Advith Rai, Krithi G Rao, Hridya Harindran K

## Pages

| Page | What it does |
|---|---|
| Home `/` | Live demo: scores 7 random held-out test flows with the real model |
| Detect `/detect` | Score one flow (exact SHAP explanation), load a real normal/attack example, or upload a CSV. Includes a CSV format guide and template |
| Report `/report/<id>` | For an uploaded CSV: flows per severity tier, score histogram, features that drove the scores (SHAP), "why" for each top flow, accuracy and per-category detection if the file has `label` / `attack_cat`, JSON download |
| Results `/results` | All the numbers from the paper, as charts |
| Method `/method` | How drift is defined, the data, the model, explanations and limits |
| API `POST /api/predict` | JSON in, drift probability + tier out |

---

## Run on the laptop

Use the same Python environment as the notebook (e.g. Anaconda Prompt).

```bat
cd path\to\driftsite
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. On the laptop the app reads the raw dataset and the
original model from the paths at the top of `app.py`:

```python
RAW_CSV    = r"C:\Users\Advith\Downloads\Training and Testing Sets\UNSW_NB15_training-set.csv"
MODEL_PATH = r"C:\Users\Advith\rf_tuned_model.pkl"
```

`python make_sample_csv.py` creates demo CSVs for the Upload page.

---

## Deploy

The server does not get the 175k-row dataset or the original `.pkl`. Instead, one
script packs everything the site needs into two small files.

### Step 1 — Export (on the laptop, once)

```bat
python export_artifacts.py
```

This creates `artifacts/drift_artifacts.joblib` and `artifacts/rf_model.joblib`,
checks that the exported model gives exactly the same scores, and rewrites
`requirements.txt` and `Dockerfile` with **your laptop's exact versions** of
Python, scikit-learn, numpy and the rest. A scikit-learn model must be loaded with
the same version that saved it, so do not edit those pins.

Start `python app.py` once more: it now loads from `artifacts/` (faster).

### Step 2 — Private GitHub repository

**Easiest: GitHub Desktop** (https://desktop.github.com)

1. *File → Add local repository →* choose the `driftsite` folder → *create a repository* here.
3. Commit with a message such as "First version", then **Publish repository**.
4. Keep **"Keep this code private"** ticked.

**Or the command line**

```bat
cd path\to\driftsite
git init
git add .
git commit -m "Rule Drift Detector website"
git branch -M main
git remote add origin https://github.com/<your-username>/rule-drift-detector.git
git push -u origin main
```

(Create the empty **private** repository on github.com first, without a README.)

`.gitignore` keeps the dataset (`*.csv`) and the original `*.pkl` out of the repo.
The compressed model (about 34 MB) is under GitHub's 100 MB limit, so no Git LFS is needed.

### Step 3 — Host on Hugging Face Spaces (free)

1. Create an account at https://huggingface.co and choose **New Space**.
2. Name it (e.g. `rule-drift-detector`), **SDK: Docker → Blank**, hardware **CPU basic (free)**.
   Visibility: **Public** to share the link, or **Private** for only you.
3. Open the Space's **Files** tab → **Add file → Upload files**, and drag in everything
   from `driftsite` **except** any `.csv` and `.pkl` files. Include the `artifacts`,
   `static` and `templates` folders and the `README.md` (its header tells Hugging Face
   how to run the app).
4. Commit. The **Logs** tab shows the build (about 3–5 minutes). When it says
   *Running*, the site is live at `https://huggingface.co/spaces/<username>/rule-drift-detector`.

Free Spaces sleep after about 48 hours without visitors and wake up on the next visit
(the first load then takes a minute).

### If something fails

| Symptom | Fix |
|---|---|
| Build log: `No matching distribution found for scikit-learn==…` | Edit the first line of `Dockerfile` to a Python version that has that scikit-learn release (e.g. `python:3.11-slim`) |
| Site shows "The model is not loaded" | The `artifacts/` folder was not uploaded. Upload both `.joblib` files through the Space's Files page |
| `InconsistentVersionWarning` in the logs | `requirements.txt` was edited. Run `export_artifacts.py` again and re-upload it |

---

## Notes

- Severity tiers follow the paper: Low < 30%, Medium 30–60%, High 60–80%, Critical > 80%.
- SHAP: a single flow uses exact Tree SHAP (about 1–2 s); uploaded files use the fast approximation.
- Uploaded reports are kept in memory and disappear when the app restarts.
- The Archivo font is bundled in `static/fonts` (SIL Open Font License).
- Data: UNSW-NB15, Moustafa & Slay (2015). The deploy file contains 4,000 held-out test flows for the live demo.
