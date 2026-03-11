"""
Phishing Website Detection - Model Training Pipeline
Trains Random Forest, Gradient Boosting, and SVM classifiers, then saves the best model.
"""

import os
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

from feature_extractor import extract_features_batch, get_feature_names

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

MODELS_DIR = "models"
BEST_MODEL_PATH = os.path.join(MODELS_DIR, "best_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
TEST_SIZE = 0.2
RANDOM_STATE = 42


# ──────────────────────────────────────────────────────────────────────────────
# Model Definitions
# ──────────────────────────────────────────────────────────────────────────────

def get_models():
    """Return dictionary of models to train."""
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=6,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=RANDOM_STATE,
        ),
        "SVM (RBF)": SVC(
            kernel="rbf",
            C=10.0,
            gamma="scale",
            probability=True,
            random_state=RANDOM_STATE,
        ),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Training Pipeline
# ──────────────────────────────────────────────────────────────────────────────

def train(dataset_path="phishing_dataset.csv"):
    """
    Full training pipeline: load data → extract features → train models → save best.
    
    Args:
        dataset_path: Path to the CSV dataset
    """
    # ── Load Dataset ──────────────────────────────────────────────────────
    print("=" * 70)
    print("  PHISHING WEBSITE DETECTION - MODEL TRAINING")
    print("=" * 70)

    print(f"\n📂 Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    print(f"   Samples loaded: {len(df)}")
    print(f"   Legitimate (0): {(df['label'] == 0).sum()}")
    print(f"   Phishing   (1): {(df['label'] == 1).sum()}")

    # ── Feature Extraction ────────────────────────────────────────────────
    print(f"\n🔍 Extracting {len(get_feature_names())} features from URLs...")
    t0 = time.time()
    X = extract_features_batch(df["url"].tolist())
    y = df["label"].values
    elapsed = time.time() - t0
    print(f"   Feature extraction completed in {elapsed:.1f}s")
    print(f"   Feature matrix shape: {X.shape}")

    # ── Train-Test Split ──────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n📊 Train-test split ({int((1-TEST_SIZE)*100)}/{int(TEST_SIZE*100)}):")
    print(f"   Training samples: {len(X_train)}")
    print(f"   Testing samples : {len(X_test)}")

    # ── Scale Features ────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ── Train Models ──────────────────────────────────────────────────────
    models = get_models()
    results = {}

    for name, model in models.items():
        print(f"\n{'─'*70}")
        print(f"🤖 Training: {name}")
        print(f"{'─'*70}")

        t0 = time.time()
        model.fit(X_train_scaled, y_train)
        train_time = time.time() - t0

        y_pred = model.predict(X_test_scaled)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            "model": model,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "confusion_matrix": cm,
            "train_time": train_time,
        }

        print(f"   Training time : {train_time:.2f}s")
        print(f"   Accuracy      : {acc:.4f}")
        print(f"   Precision     : {prec:.4f}")
        print(f"   Recall        : {rec:.4f}")
        print(f"   F1-Score      : {f1:.4f}")
        print(f"\n   Confusion Matrix:")
        print(f"   {'':>12s} Pred:Legit  Pred:Phish")
        print(f"   {'True:Legit':>12s}   {cm[0][0]:>6d}      {cm[0][1]:>6d}")
        print(f"   {'True:Phish':>12s}   {cm[1][0]:>6d}      {cm[1][1]:>6d}")
        print(f"\n   Classification Report:")
        print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # ── Model Comparison ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  MODEL COMPARISON")
    print("=" * 70)
    print(f"\n  {'Model':<22s} {'Accuracy':>10s} {'Precision':>10s} {'Recall':>10s} {'F1-Score':>10s} {'Time':>8s}")
    print(f"  {'─'*22} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*8}")

    for name, res in results.items():
        print(f"  {name:<22s} {res['accuracy']:>10.4f} {res['precision']:>10.4f} "
              f"{res['recall']:>10.4f} {res['f1_score']:>10.4f} {res['train_time']:>7.2f}s")

    # ── Save Best Model ───────────────────────────────────────────────────
    best_name = max(results, key=lambda k: results[k]["f1_score"])
    best_result = results[best_name]

    print(f"\n🏆 Best Model: {best_name} (F1-Score: {best_result['f1_score']:.4f})")

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(best_result["model"], BEST_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print(f"\n💾 Model saved to: {BEST_MODEL_PATH}")
    print(f"💾 Scaler saved to: {SCALER_PATH}")

    # ── Feature Importance (for tree-based models) ────────────────────────
    if hasattr(best_result["model"], "feature_importances_"):
        print(f"\n📊 Feature Importance ({best_name}):")
        importances = best_result["model"].feature_importances_
        feature_names = get_feature_names()
        sorted_idx = np.argsort(importances)[::-1]
        for rank, idx in enumerate(sorted_idx[:10], 1):
            bar = "█" * int(importances[idx] * 50)
            print(f"   {rank:>2d}. {feature_names[idx]:<35s} {importances[idx]:.4f}  {bar}")

    print(f"\n{'='*70}")
    print(f"  Training complete! Run 'python main.py detect <url>' to test.")
    print(f"{'='*70}\n")

    return best_name, best_result


if __name__ == "__main__":
    train()
