# Phishing Website Detection System

A complete machine learning solution for detecting phishing websites based on URL and domain security indicators. This project extracts 20 distinct features from URLs and uses an SVM classifier to accurately identify malicious sites.

## Highlights
- **Synthetic Data Generation**: Creates a labeled dataset of 10,000 URLs encompassing legitimate patterns and realistic phishing tactics (e.g., typo-squatting, excessive subdomains, numeric IPs).
- **Feature Extraction**: Computes 12 URL-based features and 8 Domain-based features for comprehensive analysis.
- **Model Training**: Evaluates Random Forest, Gradient Boosting, and Support Vector Machines (SVM). SVM achieved **99.7% Accuracy** and **100% Recall** on synthetic data.
- **Explainable Detection**: A CLI tool that not only predicts the label but also flags the specific suspicious features contributing to the result.

## Features Extracted

**URL-Based Features**
- URL length, Hostname length, Path length
- Counts of dots, hyphens, underscores, slashes, question marks, `@` symbols
- Number of digits in the domain
- Presence of an IP address
- Usage of HTTPS

**Domain-Based Features**
- Subdomain depth, Domain length, TLD length
- Presence of suspicious TLDs (e.g., .tk, .ml, .ga)
- Presence of suspicious keywords in the domain or path (e.g., "login", "secure", "verify")
- Number of redirect patterns (`//`)
- Ratio of special characters

## Getting Started

### Prerequisites
- Python 3.8+
- Scikit-learn, Pandas, Numpy, and other dependencies.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/navanee7h/phishing-detection.git
   cd phishing-detection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

This project is orchestrated through the `main.py` CLI.

### 1. Generate the Dataset
Create a dataset of 10,000 URLs (`phishing_dataset.csv`):
```bash
python main.py generate
```

### 2. Train the Models
Extract features, split the dataset, train the models, and save the best performer (`models/best_model.pkl`):
```bash
python main.py train
```

### 3. Detect Phishing URLs
Use the trained model to classify a specific URL and view the feature breakdown:
```bash
# Test a legitimate URL
python main.py detect "https://www.google.com"

# Test a typo-squatting phishing URL
python main.py detect "http://secure-paypal-login.suspicious-site.tk/update"
```

To enter interactive mode and test multiple URLs sequentially:
```bash
python main.py detect
```

## Project Structure

```
├── data_generator.py     # Generates synthetic URLs
├── feature_extractor.py  # Computes the 20 security indicators
├── train_model.py        # Pipeline for training and saving the ML model
├── detector.py           # Inference engine and results display
├── main.py               # Central CLI interface
├── requirements.txt      # Project dependencies
└── README.md             # Project documentation
```

*Note: The generated dataset and trained models are intentionally ignored from version control to save space.*
