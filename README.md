# MailGuard - AI-Powered Email Phishing Detection

## Overview

MailGuard is a comprehensive, AI-powered email security platform that analyzes emails and detects potential phishing attempts, fraudulent messages, suspicious links, fake sender addresses, and social engineering attacks.

Built with a modern cybersecurity aesthetic, MailGuard combines machine learning models with rule-based heuristics to provide accurate, explainable phishing detection across three input methods: pasting email content, uploading .eml files, and connecting Gmail accounts via OAuth 2.0.

---

## Features

### 🔍 Three Scanning Methods

1. **Paste Email Content** - Copy and paste email sender, subject, and body for immediate analysis
2. **Upload .eml Files** - Upload email files to extract headers, sender, subject, and body automatically
3. **Gmail Integration** - Securely connect your Gmail account via OAuth 2.0 to scan recent emails

### 🛡️ Comprehensive Phishing Detection

The detection engine analyzes 13+ phishing indicators:

- Suspicious sender address analysis
- Sender domain mismatch detection
- Urgent/suspicious subject lines
- Threatening or coercive language
- Suspicious hyperlinks and URLs
- Shortened URL detection (bit.ly, tinyurl, etc.)
- IP-based URL detection
- Punycode domain (IDN homograph attack) detection
- SPF authentication results
- DKIM authentication results
- DMARC authentication results
- Suspicious attachment detection
- Machine learning model predictions

### 📊 Risk Assessment

- **Risk Score**: 0-100 scale (0 = Low Risk, 100 = Critical Risk)
- **Classification**: Low Risk (0-19), Moderate Risk (20-39), High Risk (40-69), Critical Risk (70-100)
- **Transparent Fallback**: Rule-based scanner if ML model unavailable
- **Important**: Scores are estimates, not guarantees of safety

### 📈 Analytics & History

- Scan history with date, sender, subject, and results
- Search history by sender or subject, filter by risk level, and navigate results in pages
- Export matching scan history to CSV (up to the latest 1,000 scans)
- Clear scanner inputs and uploaded files with one click
- Scanner analytics refresh automatically after each scan
- Analytics dashboard with charts and statistics
- Weekly scanning activity tracking
- Risk distribution analysis
- Phishing detection percentage

### 🔒 Security Features

- Environment variable configuration for API credentials
- Google OAuth 2.0 authentication (read-only access)
- No password storage - ever
- Token encryption and secure session management
- File upload validation (10MB limit, .eml only)
- Input sanitization to prevent XSS
- No automatic link opening or attachment execution
- Secure Gmail token revocation support

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **UI Framework** | Bootstrap 5 |
| **Backend** | Python Flask |
| **ML Engine** | Scikit-learn, Random Forest Classifier |
| **Database** | SQLite |
| **Gmail API** | Google API, OAuth 2.0 |
| **Email Processing** | Python email library |
| **Visualizations** | Chart.js |

### Frontend Assets
- Bootstrap 5 CDN
- Font Awesome 6 CDN
- Google Fonts (Inter, Space Grotesk)
- Chart.js CDN

### Backend Dependencies
See `requirements.txt` for full dependency list.

---

## Project Structure

```
MailGuard/
├── app.py                  # Flask application entry point
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variable examples
├── database.py            # SQLite database operations
├── models/
│   ├── train.py           # Model training script
│   ├── phishing_model.pkl # Trained Random Forest model
│   ├── vectorizer.pkl     # TF-IDF vectorizer
│   └── scaler.pkl         # Model scaler
├── detection/
│   └── engine.py          # Phishing detection engine
├── gmail/
│   └── integration.py     # Gmail API integration
├── utils/
│   └── helpers.py         # Utility helpers
├── templates/
│   ├── index.html         # Landing page
│   ├── scanner.html       # Email scanner dashboard
│   ├── results.html       # Phishing detection results
│   └── analytics.html     # Analytics dashboard
└── static/
    ├── css/
    │   └── style.css      # Custom cybersecurity styling
    ├── js/
    │   └── main.js        # Client-side functionality
    └── images/
        └── favicon.ico    # Site favicon
├── uploads/               # Uploaded email files (temp)
└── README.md              # This file
```

---

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Google Cloud account (for Gmail integration)
- Modern web browser

### Step 1: Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-username/mailguard.git
cd mailguard

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Google Cloud Console Setup (for Gmail)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. **Enable the Gmail API**:
   - Navigate to APIs & Services > Library
   - Search for "Gmail API" and click Enable
4. **Create OAuth 2.0 Credentials**:
   - Navigate to APIs & Services > Credentials
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Desktop app" as the application type
   - Name it "MailGuard"
   - Click Create
5. **Configure OAuth Consent Screen**:
   - Select "External" user type
   - Add your email address as the developer contact
   - Add app name "MailGuard"
   - Save and continue
6. **Note your credentials**:
   - Client ID and Client Secret will be displayed
   - Save these for the .env file

### Step 3: Configuration

Create a `.env` file in the MailGuard directory:

```bash
cp .env.example .env
```

Edit `.env` with your values:

```
SECRET_KEY=your-secure-random-string-here
DEBUG=True

# Gmail API Credentials (from Google Cloud Console)
GOOGLE_CLIENT_ID=your-client-id-from-google-cloud
GOOGLE_CLIENT_SECRET=your-client-secret-from-google-cloud
GOOGLE_REDIRECT_URI=http://localhost:5000/callback
GOOGLE_SCOPES=https://www.googleapis.com/auth/gmail.readonly

# Database
DATABASE_PATH=database/mailguard.db

# Model Configuration
MODEL_ENABLED=True

# Security
MAX_UPLOAD_SIZE=10485760  # 10MB in bytes
```

### Step 4: Train the ML Model

```bash
python models/train.py
```

This will:
- Train a Random Forest classifier on labeled phishing data
- Save model artifacts to `models/` directory
- Generate evaluation metrics

### Step 5: Initialize the Database

```bash
python -c "from database import init_database; init_database()"
```

This creates the SQLite database with required tables.

### Step 6: Run the Application

```bash
python app.py
```

The website will be available at `http://localhost:5000`

---

## Usage

### Scanning Emails

1. **Paste Method**: Enter the sender email, subject, and body content, then click "Analyze Email"
2. **Upload Method**: Select a `.eml` file (max 10MB), click "Analyze Uploaded"
3. **Gmail Method**: Click "Connect Account", complete OAuth flow, select an email to scan

### Interpreting Results

- **Risk Score**: 0-100, higher = more suspicious
- **Risk Level**: Low (0-19), Moderate (20-39), High (40-69), Critical (70-100)
- **Indicators**: List of detected phishing markers
- **Authentication**: SPF, DKIM, DMARC results
- **Recommendations**: Security actions based on risk level

### Gmail Integration

- Uses read-only OAuth 2.0 permission
- Never stores your password
- Can be disconnected at any time
- Token revocation available via the disconnect feature

---

## Security Considerations

### What MailGuard Does NOT Do

- ❌ Never claims an email is "completely safe"
- ❌ Never stores Gmail passwords
- ❌ Never automatically opens suspicious links
- ❌ Never executes email attachments
- ❌ Never exposes API keys in frontend JavaScript
- ❌ Does not grant write access to Gmail

### What MailGuard DOES Do

- ✅ Analyzes emails for known phishing indicators
- ✅ Provides risk estimates based on ML + rule-based analysis
- ✅ Explains why an email was flagged
- ✅ Recommends security actions
- ✅ Uses environment variables for credentials
- ✅ Implements secure OAuth 2.0 authentication
- ✅ Validates and sanitizes all user inputs
- ✅ Limits file upload sizes and types

### OAuth 2.0 Token Management

- Tokens stored encrypted in SQLite database
- Automatic refresh when expired
- Manual revocation available via disconnect feature
- Tokens never leave the secure server environment

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page |
| `/scanner` | GET | Email scanner dashboard |
| `/results` | GET | Phishing detection results |
| `/analytics` | GET | Analytics dashboard |
| `/api/scan` | POST | Analyze email for phishing |
| `/api/gmail/connect` | POST | Connect Gmail via OAuth |
| `/api/gmail/disconnect` | POST | Disconnect Gmail account |
| `/api/gmail/emails` | GET | List recent Gmail emails |
| `/api/history` | GET | Get scan history |
| `/api/analytics` | GET | Get analytics data |

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Contact & Support

- **Project**: MailGuard - AI-Powered Email Phishing Detection
- **Purpose**: Educational and security research
- **Note**: This is a demo/prototype implementation for educational purposes

---

## Acknowledgments

- ML model trained on phishing email datasets
- Inspired by cybersecurity best practices
- Built with Flask, Scikit-learn, and Bootstrap 5