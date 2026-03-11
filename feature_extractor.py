"""
Phishing Website Detection - Feature Extractor
Extracts 20 URL-based and domain-based security features from a given URL.
"""

import re
from urllib.parse import urlparse
import tldextract
import numpy as np

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
    "work", "click", "link", "info", "online", "site", "buzz",
    "cam", "icu", "monster", "rest", "beauty",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "security", "authenticate", "validation",
    "password", "credential", "wallet", "payment", "suspend",
    "unlock", "restore", "recover", "alert", "notification",
    "urgent", "expire", "limited", "free", "winner", "prize",
    "bank", "paypal", "ebay", "apple", "microsoft",
}

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

FEATURE_NAMES = [
    # URL-Based Features (12)
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_at_symbols",
    "num_digits_in_domain",
    "has_ip_address",
    "has_https",
    # Domain-Based Features (8)
    "num_subdomains",
    "domain_length",
    "tld_length",
    "has_suspicious_tld",
    "has_suspicious_keywords",
    "path_has_suspicious_keywords",
    "num_redirects",
    "special_char_ratio",
]


# ──────────────────────────────────────────────────────────────────────────────
# Feature Extraction
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(url):
    """
    Extract 20 security-relevant features from a URL.
    
    Args:
        url: URL string to analyze
        
    Returns:
        numpy array of 20 features
    """
    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    domain = extracted.domain or ""
    suffix = extracted.suffix or ""
    subdomain = extracted.subdomain or ""

    features = []

    # ── URL-Based Features ────────────────────────────────────────────────

    # 1. URL length
    features.append(len(url))

    # 2. Hostname length
    features.append(len(hostname))

    # 3. Path length
    features.append(len(path))

    # 4. Number of dots in URL
    features.append(url.count('.'))

    # 5. Number of hyphens in URL
    features.append(url.count('-'))

    # 6. Number of underscores in URL
    features.append(url.count('_'))

    # 7. Number of slashes in path
    features.append(path.count('/'))

    # 8. Number of question marks
    features.append(url.count('?'))

    # 9. Number of @ symbols (deception indicator)
    features.append(url.count('@'))

    # 10. Number of digits in domain
    features.append(sum(c.isdigit() for c in hostname))

    # 11. Whether hostname is an IP address
    features.append(1 if IP_PATTERN.match(hostname) else 0)

    # 12. Whether URL uses HTTPS
    features.append(1 if parsed.scheme == "https" else 0)

    # ── Domain-Based Features ─────────────────────────────────────────────

    # 13. Number of subdomains
    subdomain_parts = [s for s in subdomain.split('.') if s]
    features.append(len(subdomain_parts))

    # 14. Registered domain length
    features.append(len(domain))

    # 15. TLD length
    features.append(len(suffix))

    # 16. Has suspicious TLD
    features.append(1 if suffix.lower() in SUSPICIOUS_TLDS else 0)

    # 17. URL contains suspicious keywords
    url_lower = url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    features.append(min(keyword_count, 10))  # Cap at 10

    # 18. Path contains suspicious keywords
    path_lower = path.lower()
    path_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path_lower)
    features.append(min(path_keyword_count, 10))  # Cap at 10

    # 19. Number of redirect patterns (double slashes after protocol)
    url_after_protocol = url.split("://", 1)[-1] if "://" in url else url
    features.append(url_after_protocol.count("//"))

    # 20. Special character ratio
    special_chars = sum(1 for c in url if c in "!@#$%^&*()+=[]{}|;':\"<>,?~`")
    features.append(round(special_chars / max(len(url), 1), 4))

    return np.array(features, dtype=np.float64)


def extract_features_batch(urls):
    """
    Extract features for a batch of URLs.
    
    Args:
        urls: List of URL strings
        
    Returns:
        numpy array of shape (n_urls, 20)
    """
    return np.array([extract_features(url) for url in urls])


def get_feature_names():
    """Return the list of feature names."""
    return FEATURE_NAMES.copy()


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://192.168.1.1/login/verify-account.php",
        "http://secure-paypal-login.suspicious-site.tk/update",
    ]
    for url in test_urls:
        feats = extract_features(url)
        print(f"\n{'─'*60}")
        print(f"URL: {url}")
        for name, val in zip(FEATURE_NAMES, feats):
            print(f"  {name:35s}: {val}")
