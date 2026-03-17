#!/usr/bin/env python3
import joblib
import pandas as pd

# Load model, scaler, and feature list
bundle = joblib.load("ultimate_ransomware_model.pkl")
model = bundle["model"]
scaler = bundle["scaler"]
feature_names = bundle["features"]

def predict_from_features(feature_dict: dict):
    """
    feature_dict: {feature_name: value, ...}
    Must contain at least the keys in feature_names.
    """
    # Build DataFrame with the exact training columns
    df = pd.DataFrame([feature_dict])
    # Add any missing columns with 0
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_names]

    X_scaled = scaler.transform(df)
    proba = model.predict_proba(X_scaled)[0][1]
    pred = int(proba >= 0.5)

    return {
        "prediction": pred,          # 1 = WithVirus, 0 = NoVirus
        "probability_malicious": float(proba),
    }

if __name__ == "__main__":
    # Example: Cerber-WithVirus‑style features (fill with real values from a row)
    example = {
        "pslist_n": 44,
        "psscan_n": 95,
        "hidden_procs": 51,
        "malfind_n": 6,
        "malfind_private_total": 6,
        "netscan_n": 168,
        "handles_n": 14204,
        "filescan_n": 8627,
        # you can omit the rest; they will default to 0
    }

    result = predict_from_features(example)
    print(result)
