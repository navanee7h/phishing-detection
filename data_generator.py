"""
Phishing Website Detection - Synthetic Data Generator
Generates a labeled dataset of phishing and legitimate URLs with realistic patterns.
"""

import csv
import random
import string
import os

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

LEGITIMATE_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "netflix.com", "twitter.com", "linkedin.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "reddit.com", "youtube.com", "instagram.com", "whatsapp.com",
    "zoom.us", "dropbox.com", "slack.com", "spotify.com", "paypal.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "capitalone.com",
    "adobe.com", "salesforce.com", "oracle.com", "ibm.com", "intel.com",
    "nvidia.com", "amd.com", "samsung.com", "sony.com", "dell.com",
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "bloomberg.com",
    "medium.com", "quora.com", "pinterest.com", "tumblr.com", "twitch.tv",
]

LEGITIMATE_PATHS = [
    "/", "/about", "/contact", "/help", "/support", "/products",
    "/services", "/blog", "/news", "/careers", "/login", "/signup",
    "/account", "/settings", "/profile", "/dashboard", "/search",
    "/docs", "/api", "/pricing", "/terms", "/privacy",
    "/store", "/shop", "/cart", "/checkout", "/orders",
    "/faq", "/resources", "/partners", "/investors", "/press",
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "security", "authenticate", "validation",
    "password", "credential", "wallet", "payment", "suspend",
    "unlock", "restore", "recover", "alert", "notification",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".work", ".click", ".link", ".info", ".online", ".site", ".buzz",
]

TYPO_TARGETS = {
    "google": ["go0gle", "googl3", "gooogle", "g00gle", "googie"],
    "facebook": ["facebo0k", "faceb00k", "facebok", "faceboook"],
    "paypal": ["paypa1", "paypall", "payp4l", "paypaI"],
    "amazon": ["amaz0n", "amazom", "arnazon", "amaz0m"],
    "apple": ["app1e", "appie", "appl3", "aple"],
    "microsoft": ["micr0soft", "mircosoft", "microsft", "micros0ft"],
    "netflix": ["netf1ix", "netfllx", "n3tflix", "netfl1x"],
    "chase": ["chas3", "chace", "chasse"],
    "bankofamerica": ["bankofamer1ca", "bank0famerica", "bankofarnerlca"],
    "wellsfargo": ["wellsfarg0", "we11sfargo", "wellsfargo0"],
}


def _random_string(length):
    """Generate a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _random_hex(length):
    """Generate a random hexadecimal string."""
    return ''.join(random.choices('0123456789abcdef', k=length))


# ──────────────────────────────────────────────────────────────────────────────
# Legitimate URL Generators
# ──────────────────────────────────────────────────────────────────────────────

def _generate_legitimate_standard(domain):
    """Standard legitimate URL with clean path."""
    protocol = random.choice(["https://", "https://www."])
    path = random.choice(LEGITIMATE_PATHS)
    return f"{protocol}{domain}{path}"


def _generate_legitimate_with_query(domain):
    """Legitimate URL with query parameters."""
    protocol = "https://www."
    path = random.choice(["/search", "/products", "/results", "/browse"])
    key = random.choice(["q", "id", "ref", "page", "category", "sort"])
    val = random.choice(["electronics", "books", "shoes", "home", "1", "2", "asc"])
    return f"{protocol}{domain}{path}?{key}={val}"


def _generate_legitimate_with_subpath(domain):
    """Legitimate URL with nested path."""
    protocol = "https://"
    segments = random.sample(["en", "us", "help", "docs", "v2", "api", "blog", "2024"], k=random.randint(2, 3))
    path = "/" + "/".join(segments)
    return f"{protocol}{domain}{path}"


def _generate_legitimate_subdomain(domain):
    """Legitimate URL with a common subdomain."""
    protocol = "https://"
    sub = random.choice(["mail", "support", "help", "docs", "blog", "api", "dev", "app", "store", "my"])
    path = random.choice(LEGITIMATE_PATHS)
    return f"{protocol}{sub}.{domain}{path}"


# ──────────────────────────────────────────────────────────────────────────────
# Phishing URL Generators
# ──────────────────────────────────────────────────────────────────────────────

def _generate_phishing_ip():
    """Phishing URL using raw IP address."""
    ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    protocol = random.choice(["http://", "https://"])
    keyword = random.choice(PHISHING_KEYWORDS)
    path = f"/{keyword}/{_random_string(random.randint(5,15))}"
    return f"{protocol}{ip}{path}"


def _generate_phishing_typosquatting():
    """Phishing URL using typo-squatting of popular domains."""
    brand = random.choice(list(TYPO_TARGETS.keys()))
    typo = random.choice(TYPO_TARGETS[brand])
    tld = random.choice([".com", ".net", ".org"] + SUSPICIOUS_TLDS[:5])
    protocol = random.choice(["http://", "https://"])
    keyword = random.choice(PHISHING_KEYWORDS)
    return f"{protocol}{typo}{tld}/{keyword}"


def _generate_phishing_suspicious_tld():
    """Phishing URL with a suspicious TLD."""
    keyword1 = random.choice(PHISHING_KEYWORDS)
    keyword2 = random.choice(PHISHING_KEYWORDS)
    brand = random.choice(["paypal", "amazon", "apple", "google", "microsoft", "netflix", "chase", "bank"])
    tld = random.choice(SUSPICIOUS_TLDS)
    protocol = "http://"
    domain = f"{keyword1}-{brand}-{keyword2}{tld}"
    return f"{protocol}{domain}/{_random_string(8)}"


def _generate_phishing_excessive_subdomains():
    """Phishing URL with excessive subdomains to hide real domain."""
    brand = random.choice(["paypal", "amazon", "apple", "google", "microsoft"])
    subs = [brand, random.choice(PHISHING_KEYWORDS), _random_string(5)]
    random.shuffle(subs)
    real_domain = f"{_random_string(8)}{random.choice(SUSPICIOUS_TLDS)}"
    protocol = random.choice(["http://", "https://"])
    return f"{protocol}{'.'.join(subs)}.{real_domain}/{random.choice(PHISHING_KEYWORDS)}"


def _generate_phishing_long_url():
    """Phishing URL that is excessively long with random characters."""
    brand = random.choice(["paypal", "amazon", "google", "microsoft"])
    protocol = "http://"
    domain = f"{brand}-{random.choice(PHISHING_KEYWORDS)}.com"
    long_path = "/" + "/".join([_random_hex(random.randint(8, 20)) for _ in range(random.randint(3, 6))])
    return f"{protocol}{domain}{long_path}"


def _generate_phishing_at_symbol():
    """Phishing URL using @ symbol to disguise real destination."""
    fake_domain = random.choice(LEGITIMATE_DOMAINS)
    real_domain = f"{_random_string(10)}{random.choice(SUSPICIOUS_TLDS)}"
    protocol = "http://"
    return f"{protocol}{fake_domain}@{real_domain}/{random.choice(PHISHING_KEYWORDS)}"


def _generate_phishing_redirect():
    """Phishing URL with embedded redirect patterns."""
    brand = random.choice(["paypal", "chase", "bankofamerica", "wellsfargo"])
    protocol = "http://"
    domain = f"{brand}-{random.choice(PHISHING_KEYWORDS)}{random.choice(SUSPICIOUS_TLDS)}"
    redirect = f"//redirect//{_random_string(10)}//{random.choice(PHISHING_KEYWORDS)}"
    return f"{protocol}{domain}{redirect}"


def _generate_phishing_encoded():
    """Phishing URL with special characters and encoded patterns."""
    brand = random.choice(["paypal", "amazon", "apple", "google"])
    protocol = "http://"
    keyword = random.choice(PHISHING_KEYWORDS)
    domain = f"{brand}.{keyword}-{_random_string(6)}{random.choice(SUSPICIOUS_TLDS)}"
    path = f"/{keyword}?id={_random_hex(16)}&token={_random_hex(24)}&ref={_random_string(8)}"
    return f"{protocol}{domain}{path}"


# ──────────────────────────────────────────────────────────────────────────────
# Main Generator
# ──────────────────────────────────────────────────────────────────────────────

LEGITIMATE_GENERATORS = [
    _generate_legitimate_standard,
    _generate_legitimate_with_query,
    _generate_legitimate_with_subpath,
    _generate_legitimate_subdomain,
]

PHISHING_GENERATORS = [
    _generate_phishing_ip,
    _generate_phishing_typosquatting,
    _generate_phishing_suspicious_tld,
    _generate_phishing_excessive_subdomains,
    _generate_phishing_long_url,
    _generate_phishing_at_symbol,
    _generate_phishing_redirect,
    _generate_phishing_encoded,
]


def generate_dataset(output_path="phishing_dataset.csv", num_samples=10000):
    """
    Generate a synthetic phishing dataset.
    
    Args:
        output_path: Path to save the CSV file
        num_samples: Total number of samples (split ~50/50 between classes)
    """
    num_legitimate = num_samples // 2
    num_phishing = num_samples - num_legitimate

    urls = []

    # Generate legitimate URLs
    for _ in range(num_legitimate):
        domain = random.choice(LEGITIMATE_DOMAINS)
        generator = random.choice(LEGITIMATE_GENERATORS)
        url = generator(domain)
        urls.append((url, 0))  # 0 = legitimate

    # Generate phishing URLs
    for _ in range(num_phishing):
        generator = random.choice(PHISHING_GENERATORS)
        url = generator()
        urls.append((url, 1))  # 1 = phishing

    # Shuffle the dataset
    random.shuffle(urls)

    # Write to CSV
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(urls)

    print(f"✅ Dataset generated: {output_path}")
    print(f"   Total samples  : {num_samples}")
    print(f"   Legitimate (0) : {num_legitimate}")
    print(f"   Phishing   (1) : {num_phishing}")

    return output_path


if __name__ == "__main__":
    generate_dataset()
