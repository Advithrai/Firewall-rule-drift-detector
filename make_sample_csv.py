"""
Make small demo CSVs from the real UNSW-NB15 file, for the Upload page.

    python make_sample_csv.py

Creates two files next to this script:
    demo_flows_labelled.csv  - 1,000 random flows WITH the label column
                               (the report then also shows accuracy)
    demo_flows.csv           - 300 random flows WITHOUT labels
"""
import os
import pandas as pd

RAW_CSV = os.environ.get(
    "DRIFT_RAW_CSV",
    r"C:\Users\Advith\Downloads\Training and Testing Sets\UNSW_NB15_training-set.csv",
)

raw = pd.read_csv(RAW_CSV)
here = os.path.dirname(os.path.abspath(__file__))

raw.sample(1000, random_state=7).to_csv(os.path.join(here, "demo_flows_labelled.csv"), index=False)
raw.sample(300, random_state=8).drop(columns=["label", "attack_cat"]).to_csv(
    os.path.join(here, "demo_flows.csv"), index=False)
print("Created demo_flows_labelled.csv and demo_flows.csv")
