"""
Phishing Website Detection - URL Detector
Loads the trained model and classifies URLs as phishing or legitimate.
"""

import os
import sys
import joblib
import numpy as np

from feature_extractor import extract_features, get_feature_names

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

MODELS_DIR = "models"
MODEL_PATH = os.path.join(MODELS_DIR, "best_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")


# ──────────────────────────────────────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────────────────────────────────────

class PhishingDetector:
    """Loads a trained model and classifies URLs."""

    def __init__(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        if not os.path.exists(model_path):
            print(f"{Fore.RED}❌ Model not found at: {model_path}")
            print(f"{Fore.YELLOW}   Run 'python main.py train' first to train a model.")
            sys.exit(1)

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_names = get_feature_names()

    def predict(self, url):
        """
        Classify a URL and return prediction details.
        
        Args:
            url: URL string to classify
            
        Returns:
            dict with keys: url, prediction, label, confidence, features
        """
        features = extract_features(url)
        features_scaled = self.scaler.transform(features.reshape(1, -1))

        prediction = self.model.predict(features_scaled)[0]
        
        # Get probability if available
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(features_scaled)[0]
            confidence = proba[int(prediction)]
        else:
            confidence = None

        return {
            "url": url,
            "prediction": int(prediction),
            "label": "PHISHING" if prediction == 1 else "LEGITIMATE",
            "confidence": confidence,
            "features": dict(zip(self.feature_names, features)),
        }

    def display_result(self, result):
        """Display a color-coded classification result in the terminal."""
        print()
        print(f"{'='*70}")
        print(f"  {Style.BRIGHT}PHISHING WEBSITE DETECTION RESULT")
        print(f"{'='*70}")
        print(f"\n  {Fore.CYAN}URL:{Style.RESET_ALL} {result['url']}")

        if result["prediction"] == 1:
            print(f"\n  {Fore.RED}{Style.BRIGHT}🔴 VERDICT: PHISHING DETECTED!")
            risk_bar = f"{Fore.RED}{'█' * 20}"
        else:
            print(f"\n  {Fore.GREEN}{Style.BRIGHT}🟢 VERDICT: LEGITIMATE WEBSITE")
            risk_bar = f"{Fore.GREEN}{'█' * 20}"

        if result["confidence"] is not None:
            pct = result["confidence"] * 100
            print(f"  {Style.BRIGHT}   Confidence: {pct:.1f}%")

        print(f"\n  Risk Level: {risk_bar}{Style.RESET_ALL}")

        # ── Feature Breakdown ─────────────────────────────────────────────
        print(f"\n{'─'*70}")
        print(f"  {Style.BRIGHT}FEATURE ANALYSIS")
        print(f"{'─'*70}")

        features = result["features"]

        # URL-Based Features
        print(f"\n  {Fore.CYAN}{Style.BRIGHT}URL-Based Features:{Style.RESET_ALL}")
        url_features = list(features.items())[:12]
        for name, val in url_features:
            flag = self._get_feature_flag(name, val)
            print(f"    {name:<35s}: {val:>8.2f}  {flag}")

        # Domain-Based Features
        print(f"\n  {Fore.CYAN}{Style.BRIGHT}Domain-Based Features:{Style.RESET_ALL}")
        domain_features = list(features.items())[12:]
        for name, val in domain_features:
            flag = self._get_feature_flag(name, val)
            print(f"    {name:<35s}: {val:>8.2f}  {flag}")

        print(f"\n{'='*70}\n")

    def _get_feature_flag(self, name, value):
        """Return a risk indicator for suspicious feature values."""
        suspicious_conditions = {
            "url_length": value > 75,
            "hostname_length": value > 30,
            "num_dots": value > 4,
            "num_hyphens": value > 3,
            "num_at_symbols": value > 0,
            "num_digits_in_domain": value > 4,
            "has_ip_address": value == 1,
            "has_https": value == 0,
            "num_subdomains": value > 2,
            "has_suspicious_tld": value == 1,
            "has_suspicious_keywords": value > 0,
            "path_has_suspicious_keywords": value > 0,
            "num_redirects": value > 0,
            "special_char_ratio": value > 0.05,
        }

        if name in suspicious_conditions and suspicious_conditions[name]:
            return f"{Fore.RED}⚠ suspicious"
        return f"{Fore.GREEN}✓"


def detect(url):
    """Quick detection function - creates detector and classifies a URL."""
    detector = PhishingDetector()
    result = detector.predict(url)
    detector.display_result(result)
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector.py <url>")
        sys.exit(1)
    detect(sys.argv[1])
