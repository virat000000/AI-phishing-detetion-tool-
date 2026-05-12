import pandas as pd
import numpy as np
import re
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

def load_dataset():
    """Load and prepare the phishing dataset"""
    
    # Sample dataset - In production, load from CSV
    urls = [
        # Legitimate URLs (0)
        "https://www.google.com", "https://www.facebook.com", "https://www.amazon.com",
        "https://www.youtube.com", "https://www.wikipedia.org", "https://www.reddit.com",
        "https://www.linkedin.com", "https://www.twitter.com", "https://www.instagram.com",
        "https://www.netflix.com", "https://www.microsoft.com", "https://www.apple.com",
        "https://www.paypal.com", "https://www.bankofamerica.com", "https://www.chase.com",
        "https://github.com", "https://stackoverflow.com", "https://medium.com",
        "https://www.wellsfargo.com", "https://www.capitalone.com", "https://www.spotify.com",
        "https://www.dropbox.com", "https://www.slack.com", "https://www.zoom.us",
        "https://www.adobe.com", "https://www.salesforce.com", "https://www.oracle.com",
        "https://www.ibm.com", "https://www.cisco.com", "https://www.intel.com",
        
        # Phishing URLs (1)
        "http://paypal-verify-account.xyz", "http://secure-login-apple.com",
        "https://amazon-account-update.tk", "http://facebook-security-verify.ml",
        "https://netflix-account-suspended.ga", "http://apple-id-verify.cf",
        "https://bankofamerica-login.gq", "http://chase-secure-message.xyz",
        "https://paypal-verification.tk", "http://microsoft-account-alert.ml",
        "https://google-security-alert.ga", "http://instagram-verify-account.cf",
        "https://wellsfargo-online-banking.gq", "http://capitalone-secure.xyz",
        "https://update-account-now.ru", "http://secure-banking-login.net",
        "https://verify-identity.com", "http://account-security-alert.org",
        "https://confirm-payment.info", "http://login-secure-verify.xyz",
        "https://appleid-verify.com", "http://paypal-center.net",
        "https://amazon-verification.ru", "http://facebook-login-verify.xyz",
        "https://netflix-verify-account.tk", "http://microsoft-update.ml",
        "https://google-verification.ga", "http://instagram-security.cf",
        "https://bank-verification.gq", "http://secure-paypal.xyz"
    ]
    
    labels = [0] * 30 + [1] * 30  # 30 legitimate, 30 phishing
    
    return urls, labels

def extract_features(url):
    """Extract all features from a URL"""
    features = {}
    
    # Basic length features
    features['url_length'] = len(url)
    from urllib.parse import urlparse
    parsed = urlparse(url)
    features['hostname_length'] = len(parsed.hostname or '')
    features['path_length'] = len(parsed.path)
    
    # Count features
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equal_signs'] = url.count('=')
    features['num_at_symbols'] = url.count('@')
    features['num_and_symbols'] = url.count('&')
    features['num_exclamation'] = url.count('!')
    features['num_tilde'] = url.count('~')
    features['num_comma'] = url.count(',')
    features['num_dollar'] = url.count('$')
    features['num_percent'] = url.count('%')
    features['num_colon'] = url.count(':')
    features['num_semicolon'] = url.count(';')
    
    # Security features
    features['has_https'] = 1 if url.startswith('https') else 0
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
    
    # Suspicious keywords
    suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 
                          'confirm', 'banking', 'paypal', 'apple', 'microsoft', 'amazon',
                          'netflix', 'google', 'facebook', 'instagram', 'whatsapp']
    features['suspicious_keyword_count'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
    
    # Domain structure
    hostname = parsed.hostname or ''
    parts = hostname.split('.')
    features['subdomain_count'] = max(0, len(parts) - 2)
    
    # Character analysis
    features['digit_count'] = sum(c.isdigit() for c in url)
    features['letter_count'] = sum(c.isalpha() for c in url)
    
    # Special character ratio
    special_chars = sum(c in '!@#$%^&*()_+-=[]\\{}|;:\'",.<>/?`~' for c in url)
    features['special_char_ratio'] = special_chars / max(len(url), 1)
    
    # Entropy
    if url:
        from collections import Counter
        freq = Counter(url)
        probs = [freq[c]/len(url) for c in freq]
        features['entropy'] = -sum(p * np.log2(p) for p in probs)
    else:
        features['entropy'] = 0
    
    return features

def train_model():
    """Main training function"""
    print("=" * 60)
    print("🛡️ AiPhishGuard - AI Model Training")
    print("=" * 60)
    
    # Load dataset
    print("\n📊 Loading dataset...")
    urls, labels = load_dataset()
    print(f"   Total URLs: {len(urls)}")
    print(f"   Legitimate: {labels.count(0)}")
    print(f"   Phishing: {labels.count(1)}")
    
    # Extract features
    print("\n🔍 Extracting features...")
    features_list = []
    for i, url in enumerate(urls):
        features_list.append(extract_features(url))
        if (i + 1) % 10 == 0:
            print(f"   Processed {i + 1}/{len(urls)} URLs")
    
    # Create DataFrame
    X = pd.DataFrame(features_list)
    y = np.array(labels)
    
    print(f"\n📈 Feature matrix shape: {X.shape}")
    print(f"   Features: {list(X.columns)}")
    
    # Split data
    print("\n✂️ Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")
    
    # Train model
    print("\n🧠 Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n📊 Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ Model Accuracy: {accuracy * 100:.2f}%")
    print("\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\n🔢 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"   True Negatives: {cm[0][0]}")
    print(f"   False Positives: {cm[0][1]}")
    print(f"   False Negatives: {cm[1][0]}")
    print(f"   True Positives: {cm[1][1]}")
    
    # Feature importance
    print("\n🎯 Top 10 Important Features:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False).head(10)
    
    for i, row in feature_importance.iterrows():
        print(f"   {row['feature']}: {row['importance']:.4f}")
    
    # Save model
    print("\n💾 Saving model...")
    joblib.dump(model, 'phishing_model.pkl')
    print("   ✅ Model saved as 'phishing_model.pkl'")
    
    # Save feature names
    feature_names = list(X.columns)
    joblib.dump(feature_names, 'feature_names.pkl')
    print("   ✅ Feature names saved")
    
    print("\n" + "=" * 60)
    print("🎉 Training Complete! Model ready for deployment.")
    print("=" * 60)
    
    return model

def test_model_with_examples():
    """Test the trained model with example URLs"""
    print("\n" + "=" * 60)
    print("🧪 Testing Model with Examples")
    print("=" * 60)
    
    try:
        model = joblib.load('phishing_model.pkl')
        
        test_urls = [
            ("https://www.google.com", "Legitimate"),
            ("https://www.paypal.com", "Legitimate"),
            ("http://paypal-verify.xyz", "Phishing"),
            ("https://amazon-account-update.tk", "Phishing"),
            ("https://secure-login-apple.com", "Phishing"),
            ("https://www.microsoft.com", "Legitimate")
        ]
        
        print("\n📊 Test Results:")
        print("-" * 60)
        
        for url, expected in test_urls:
            features = extract_features(url)
            X = pd.DataFrame([features])
            proba = model.predict_proba(X)[0]
            prediction = "Phishing" if proba[1] > 0.5 else "Legitimate"
            confidence = max(proba) * 100
            
            status = "✅" if prediction == expected else "❌"
            print(f"{status} URL: {url}")
            print(f"   Expected: {expected} | Predicted: {prediction}")
            print(f"   Confidence: {confidence:.1f}%")
            print()
            
    except Exception as e:
        print(f"Error testing model: {e}")

if __name__ == '__main__':
    # Train the model
    model = train_model()
    
    # Test with examples
    test_model_with_examples()