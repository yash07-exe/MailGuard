"""
MailGuard - Phishing Email Detection Model Training Script

This script trains a Random Forest classifier on a labeled phishing email dataset
and saves the model artifacts for use by the Flask backend.

To run: python models\train.py
"""

import re
import json
import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import warnings

warnings.filterwarnings('ignore')

def preprocess_text(text):
    """Preprocess email text for ML model input."""
    if not text:
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove HTML tags
    text = re.sub(r'<.*?>', '', text)
    
    # Remove URLs
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    
    # Remove email addresses
    text = re.sub(r'\S+@\S+', '', text)
    
    # Remove special characters but keep spaces
    text = re.sub(r'[^\w\s]', '', text)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text


def extract_features(text):
    """Extract features from email text for ML model."""
    features = {}
    
    # Length of text
    features['text_length'] = len(text)
    
    # Number of uppercase words
    uppercase_words = len(re.findall(r'\b[A-Z]{2,}\b', text))
    features['uppercase_count'] = uppercase_words
    
    # Number of exclamation marks
    features['exclamation_count'] = text.count('!')
    
    # Number of urgent words
    urgent_words = ['urgent', 'alert', 'warning', 'important', 'expire', 'expired']
    urgent_count = sum(1 for word in urgent_words if word in text.lower())
    features['urgent_word_count'] = urgent_count
    
    # Caps lock ratio
    caps_ratio = uppercase_words / max(len(text.split()), 1)
    features['caps_ratio'] = caps_ratio
    
    # Presence of suspicious keywords
    suspicious_keywords = [
        'password', 'verify', 'account', 'suspended', 'limited', 'confirm',
        'security', 'login', 'bank', 'update', 'inheritance', 'winner',
        'transfer', 'refund', 'click here', 'act now'
    ]
    suspicious_count = sum(1 for kw in suspicious_keywords if kw in text.lower())
    features['suspicious_keyword_count'] = suspicious_count
    
    # Urgent phrases
    urgent_phrases = ['immediately', 'within 24 hours', 'within 48 hours', 'urgent action required']
    urgent_phrase_count = sum(1 for phrase in urgent_phrases if phrase in text.lower())
    features['urgent_phrase_count'] = urgent_phrase_count
    
    # Number of links
    link_count = len(re.findall(r'http\S+|https\S+|\S+\.com|\S+\.org|\S+\.net', text))
    features['link_count'] = link_count
    
    return features


def main():
    """Main training function."""
    print("=" * 60)
    print("MailGuard - Phishing Email Detection Model Training")
    print("=" * 60)
    
    # Sample labeled dataset for demonstration
    # In production, use a proper phishing email dataset
    # This dataset contains 20 emails: 10 phishing, 10 legitimate
    sample_data = [
        # Phishing emails (label 1)
        ("Dear user, your account has been suspended. Click here to verify your identity immediately.", "phishing"),
        ("Urgent: Your password will expire in 24 hours. Update now or lose access.", "phishing"),
        ("You have won a million dollars! Claim your prize now by clicking the link.", "phishing"),
        ("Security alert: Unusual login activity detected. Verify your account immediately.", "phishing"),
        ("Invoice attached. Please review the payment details and transfer funds.", "phishing"),
        ("Your bank account has been limited. Click here to restore access within 24 hours.", "phishing"),
        ("Congratulations! You selected for a random drawing. Claim your reward now.", "phishing"),
        ("Urgent: Verify your identity to prevent account suspension. Act within 12 hours.", "phishing"),
        ("You received a refund. Provide your banking details to process the payment.", "phishing"),
        ("Important: Your account will be deleted unless you verify within 24 hours.", "phishing"),
        
        # Legitimate emails (label 0)
        ("Meeting rescheduled to 3 PM tomorrow. Regards, John.", "legitimate"),
        ("Please find the attached document as requested.", "legitimate"),
        ("Happy Birthday! Best wishes from your team.", "legitimate"),
        ("Project update: The quarterly review has been completed on schedule.", "legitimate"),
        ("Confirmation of your order #12345 has been sent to your email.", "legitimate"),
        ("Weekly newsletter: Latest tech trends and updates.", "legitimate"),
        ("Dinner reservation confirmed for 8 PM tonight.", "legitimate"),
        ("Meeting minutes from yesterday's session are attached.", "legitimate"),
        ("Your monthly statement is now available online.", "legitimate"),
        ("Thank you for your feedback and valuable input.", "legitimate"),
    ]
    
    # Prepare data
    texts = [item[0] for item in sample_data]
    labels = [0 if item[1] == "legitimate" else 1 for item in sample_data]  # 0=legitimate, 1=phishing
    
    print(f"Training on {len(texts)} samples ({sum(labels)} phishing, {len(labels)-sum(labels)} legitimate)")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.3, random_state=42, stratify=labels)
    
    # Vectorize text using TF-IDF
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words='english')
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Train Random Forest classifier
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train_vec, y_train)
    
    # Evaluate model
    print("\n" + "=" * 60)
    print("Model Evaluation")
    print("=" * 60)
    
    y_pred = model.predict(X_test_vec)
    accuracy = np.mean(y_pred == y_test)
    print(f"\nModel Accuracy: {accuracy:.2f} ({accuracy*100:.1f}%)")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(f"True Negatives: {cm[0][0]}")
    print(f"False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]}")
    print(f"True Positives: {cm[1][1]}")
    
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Save model artifacts
    import joblib
    
    print("\nSaving model artifacts...")
    joblib.dump(model, 'models/phishing_model.pkl')
    print("✓ Saved: models/phishing_model.pkl")
    
    joblib.dump(vectorizer, 'models/vectorizer.pkl')
    print("✓ Saved: models/vectorizer.pkl")
    
    # Save scaler (not strictly needed for tree-based models, but kept for compatibility)
    scaler = None  # Random Forest doesn't need scaling
    joblib.dump(scaler, 'models/scaler.pkl', compress=1)
    print("✓ Saved: models/scaler.pkl (placeholder)")
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("Model can now be used by the MailGuard Flask backend.")
    print("=" * 60)


if __name__ == '__main__':
    main()