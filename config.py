"""MailGuard Configuration Settings"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Flask Configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'mailguard-secret-key-2024-change-in-production')
DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'

# Gmail API Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/callback')
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Database Configuration
DATABASE_PATH = os.getenv('DATABASE_PATH', 'database/mailguard.db')

# Email Scanning Configuration
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB max upload
ALLOWED_EXTENSIONS = {'eml'}

# ML Model Configuration
MODEL_PATH = 'models/phishing_model.pkl'
SCALER_PATH = 'models/scaler.pkl'
MODEL_ENABLED = os.getenv('MODEL_ENABLED', 'True').lower() == 'true'

# Risk Score Thresholds
RISK_LOW = 20
RISK_MODERATE = 40
RISK_HIGH = 70

# OAuth State Token Duration (seconds)
OAUTH_STATE_TIMEOUT = 300