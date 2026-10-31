"""MailGuard - AI-Powered Email Phishing Detection Website"""

import os
import re
import sqlite3
import json
import base64
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from config import SECRET_KEY, DATABASE_PATH, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, GOOGLE_SCOPES, MODEL_ENABLED

# Create Flask app instance
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['DATABASE_PATH'] = DATABASE_PATH

# Import detection modules
from detection.engine import analyze_email
from gmail.integration import get_gmail_service, list_recent_emails, get_email_details
from utils.helpers import allowed_file, sanitize_input, format_risk_score

# Register blueprints or import routes
from routes import *

# Create database tables
def init_db():
    """Initialize the SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            sender_email TEXT,
            email_subject TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            classification TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            email_address TEXT,
            access_token TEXT,
            refresh_token TEXT,
            token_expiry TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Create tables on startup
with app.app_context():
    init_db()

# Home route
@app.route('/')
def index():
    """Landing page route."""
    return render_template('index.html')

# Scanner dashboard route
@app.route('/scanner')
def scanner():
    """Email scanner dashboard route."""
    return render_template('scanner.html')

# Results route
@app.route('/results')
def results():
    """Phishing detection results route."""
    scan_id = request.args.get('id')
    if scan_id:
        scan_result = get_scan_result(scan_id)
        return render_template('results.html', result=scan_result)
    return redirect(url_for('scanner'))

# Analytics route
@app.route('/analytics')
def analytics():
    """Analytics dashboard route."""
    return render_template('analytics.html')

# API: Scan email endpoint
@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Analyze email for phishing indicators."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        scan_method = data.get('method', 'paste')
        
        if scan_method == 'paste':
            sender = data.get('sender', '')
            subject = data.get('subject', '')
            body = data.get('body', '')
            result = analyze_email(sender, subject, body)
        
        elif scan_method == 'upload':
            filename = data.get('filename', '')
            content = data.get('content', '')
            result = analyze_email(filename, subject='', body=content)
        
        elif scan_method == 'gmail':
            email_id = data.get('email_id')
            if not email_id:
                return jsonify({'error': 'No email ID provided'}), 400
            result = analyze_gmail_email(email_id)
        
        else:
            return jsonify({'error': 'Invalid scan method'}), 400
        
        # Save scan to database
        save_scan_result(result)
        
        return jsonify({
            'success': True,
            'sender': result.get('sender', ''),
            'subject': result.get('subject', ''),
            'classification': result['classification'],
            'risk_score': result['risk_score'],
            'risk_level': result['risk_level'],
            'indicators': result['indicators'],
            'authentication': result['authentication'],
            'analysis': result['analysis']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API: Gmail connect endpoint
@app.route('/api/gmail/connect', methods=['POST'])
def gmail_connect():
    """Handle Gmail OAuth connection."""
    try:
        data = request.get_json()
        authorization_code = data.get('code')
        
        if not authorization_code:
            return jsonify({'error': 'No authorization code provided'}), 400
        
        # Exchange authorization code for tokens
        from google_auth_oauthlib.flow import Flow
        from googleapiclient.discovery import build
        import os
        
        flow = Flow.from_client_config(
            {
                "inst": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/auth2",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=GOOGLE_SCOPES
        )
        
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        flow.authorization_response = None  # Will be set by the flow
        
        # Exchange code for tokens
        flow.fetch_token(code=authorization_code)
        
        credentials = flow.credentials
        
        # Store user info in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE google_id = ?', (data.get('state'),))
        user = cursor.fetchone()
        
        if not user:
            cursor.execute(
                'INSERT INTO users (google_id, email_address, access_token, refresh_token, token_expiry) VALUES (?, ?, ?, ?, ?)',
                (data.get('state'), data.get('email'), 
                 credentials.token, credentials.refresh_token,
                 datetime.datetime.utcnow() + datetime.timedelta(seconds=credentials.expiry.expires_in if credentials.expiry else 3600))
            )
        else:
            cursor.execute(
                'UPDATE users SET access_token = ?, refresh_token = ?, token_expiry = ? WHERE google_id = ?',
                (credentials.token, credentials.refresh_token,
                 datetime.datetime.utcnow() + datetime.timedelta(seconds=3600), data.get('state'))
            )
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Gmail account connected successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API: Gmail disconnect endpoint
@app.route('/api/gmail/disconnect', methods=['POST'])
def gmail_disconnect():
    """Handle Gmail disconnection."""
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        session.pop('user_id', None)
        return jsonify({'success': True, 'message': 'Gmail account disconnected'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API: Get recent emails from Gmail
@app.route('/api/gmail/emails', methods=['GET'])
def gmail_emails():
    """Get recent emails from Gmail."""
    try:
        service = get_gmail_service()
        if not service:
            return jsonify({'error': 'Gmail not connected'}), 400
        
        emails = list_recent_emails(service, max_results=10)
        return jsonify({'success': True, 'emails': emails})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API: Get scan history
@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history from database."""
    try:
        limit = min(max(request.args.get('limit', default=50, type=int) or 50, 1), 1000)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_count = cursor.fetchone()[0]
        cursor.execute('SELECT id, sender_email, email_subject, risk_score, risk_level, classification, detected_at FROM scans ORDER BY detected_at DESC LIMIT ?', (limit,))
        scans = cursor.fetchall()
        conn.close()
        
        history = []
        for scan in scans:
            history.append({
                'id': scan[0],
                'sender_email': scan[1],
                'email_subject': scan[2],
                'risk_score': scan[3],
                'risk_level': scan[4],
                'classification': scan[5],
                'detected_at': scan[6]
            })
        
        return jsonify({'success': True, 'history': history, 'total_count': total_count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API: Get analytics
@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data from database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total emails scanned
        cursor.execute('SELECT COUNT(*) FROM scans')
        total = cursor.fetchone()[0]
        
        # Phishing emails (high + critical risk)
        cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_level IN ("High Risk", "Critical Risk")')
        phishing_count = cursor.fetchone()[0]
        
        # Low risk emails
        cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_level = "Low Risk"')
        low_risk = cursor.fetchone()[0]
        
        # High risk emails
        cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_level = "High Risk"')
        high_risk = cursor.fetchone()[0]
        
        # Phishing detection percentage
        phishing_percentage = (phishing_count / total * 100) if total > 0 else 0
        
        # Weekly activity (last 7 days)
        cursor.execute('''
            SELECT DATE(detected_at) as date, COUNT(*) as count 
            FROM scans 
            WHERE detected_at >= date('now', '-7 days')
            GROUP BY DATE(detected_at)
        ''')
        weekly_activity = cursor.fetchall()
        
        # Risk distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count 
            FROM scans 
            GROUP BY risk_level
        ''')
        risk_distribution = cursor.fetchall()
        
        conn.close()
        
        analytics = {
            'total_scanned': total,
            'potential_phishing': phishing_count,
            'low_risk': low_risk,
            'high_risk': high_risk,
            'phishing_percentage': round(phishing_percentage, 2),
            'weekly_activity': [{'date': str(row[0]), 'count': row[1]} for row in weekly_activity],
            'risk_distribution': [{'level': row[0], 'count': row[1]} for row in risk_distribution]
        }
        
        return jsonify({'success': True, 'analytics': analytics})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper: Save scan result to database
def save_scan_result(result):
    """Save scan result to SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (sender_email, email_subject, risk_score, risk_level, classification, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        result.get('sender', ''),
        result.get('subject', ''),
        result.get('risk_score', 0),
        result.get('risk_level', 'Low Risk'),
        result.get('classification', 'Low Risk'),
        request.remote_addr,
        request.user_agent.string if request.user_agent else ''
    ))
    conn.commit()
    conn.close()

# Helper: Get scan result from database
def get_scan_result(scan_id):
    """Get scan result from SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, sender_email, email_subject, risk_score, risk_level, classification, detected_at FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    conn.close()
    
    if scan:
        return {
            'id': scan[0],
            'sender_email': scan[1],
            'email_subject': scan[2],
            'risk_score': scan[3],
            'risk_level': scan[4],
            'classification': scan[5],
            'detected_at': scan[6]
        }
    return None

# Helper error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)