"""MailGuard Flask Routes"""

import os
import re
import sqlite3
import base64
from datetime import datetime
from flask import Blueprint, request, session, jsonify, render_template, redirect, url_for

from config import DATABASE_PATH, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
from detection.engine import analyze_email
from gmail.integration import get_gmail_service, list_recent_emails, get_email_details
from utils.helpers import allowed_file, sanitize_input, format_risk_score

routes_bp = Blueprint('routes', __name__)


@routes_bp.route('/')
def index():
    """Landing page route."""
    return render_template('index.html')


@routes_bp.route('/scanner')
def scanner():
    """Email scanner dashboard route."""
    return render_template('scanner.html')


@routes_bp.route('/results')
def results():
    """Phishing detection results route."""
    scan_id = request.args.get('id')
    if scan_id:
        from app import get_scan_result
        scan_result = get_scan_result(scan_id)
        return render_template('results.html', result=scan_result)
    return redirect(url_for('routes.scanner'))


@routes_bp.route('/analytics')
def analytics():
    """Analytics dashboard route."""
    from app import get_analytics
    analytics_data = get_analytics()
    return render_template('analytics.html', analytics=analytics_data)


@routes_bp.route('/api/scan', methods=['POST'])
def api_scan():
    """Analyze email for phishing indicators."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        scan_method = data.get('method', 'paste')
        
        if scan_method == 'paste':
            sender = sanitize_input(data.get('sender', ''))
            subject = sanitize_input(data.get('subject', ''))
            body = sanitize_input(data.get('body', ''))
            result = analyze_email(sender, subject, body)
        
        elif scan_method == 'upload':
            filename = data.get('filename', '')
            content = sanitize_input(data.get('content', ''))
            result = analyze_email(filename, subject='', body=content)
        
        elif scan_method == 'gmail':
            email_id = data.get('email_id')
            if not email_id:
                return jsonify({'error': 'No email ID provided'}), 400
            result = analyze_gmail_email(email_id)
        
        else:
            return jsonify({'error': 'Invalid scan method'}), 400
        
        # Save scan to database
        from app import save_scan_result
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


@routes_bp.route('/api/gmail/connect', methods=['POST'])
def gmail_connect():
    """Handle Gmail OAuth connection."""
    try:
        data = request.get_json()
        authorization_code = data.get('code')
        state = data.get('state')
        
        if not authorization_code:
            return jsonify({'error': 'No authorization code provided'}), 400
        
        from google_auth_oauthlib.flow import Flow
        from googleapiclient.discovery import build
        
        flow = Flow.from_client_config(
            {
                "inst": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/auth2",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=['https://www.googleapis.com/auth/gmail.readonly'],
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        
        flow.fetch_token(code=authorization_code)
        
        credentials = flow.credentials
        
        # Store user info in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE google_id = ?', (state,))
        user = cursor.fetchone()
        
        if not user:
            cursor.execute(
                'INSERT INTO users (google_id, email_address, access_token, refresh_token, token_expiry) VALUES (?, ?, ?, ?, ?)',
                (state, data.get('email'), 
                 credentials.token, credentials.refresh_token,
                 datetime.datetime.utcnow() + datetime.timedelta(seconds=3600))
            )
        else:
            cursor.execute(
                'UPDATE users SET access_token = ?, refresh_token = ?, token_expiry = ? WHERE google_id = ?',
                (credentials.token, credentials.refresh_token,
                 datetime.datetime.utcnow() + datetime.timedelta(seconds=3600), state)
            )
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Gmail account connected successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@routes_bp.route('/api/gmail/disconnect', methods=['POST'])
def gmail_disconnect():
    """Handle Gmail disconnection."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (session.get('user_id'),))
        conn.commit()
        conn.close()
        session.pop('user_id', None)
        return jsonify({'success': True, 'message': 'Gmail account disconnected'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@routes_bp.route('/api/gmail/emails', methods=['GET'])
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


@routes_bp.route('/api/history', methods=['GET'])
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


@routes_bp.route('/api/analytics', methods=['GET'])
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


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn