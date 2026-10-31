"""MailGuard Database Module"""

import sqlite3
from datetime import datetime
from config import DATABASE_PATH


def get_connection():
    """Get a database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize the database with required tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Create scans table
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
    
    # Create users table for Gmail OAuth
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
    
    # Create index for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_senders ON scans(sender_email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_detected_at ON scans(detected_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_level ON scans(risk_level)')
    
    conn.commit()
    conn.close()
    print("✓ Database initialized successfully")


def save_scan(result):
    """Save a scan result to the database."""
    conn = get_connection()
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
        '',  # ip_address - would be request.remote_addr in Flask
        ''   # user_agent - would be request.user_agent.string in Flask
    ))
    
    conn.commit()
    conn.close()


def get_recent_scans(limit=50):
    """Get recent scan records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, sender_email, email_subject, risk_score, risk_level, classification, detected_at
        FROM scans ORDER BY detected_at DESC LIMIT ?
    ''', (limit,))
    scans = cursor.fetchall()
    conn.close()
    
    return [dict(scan) for scan in scans]


def get_scan_statistics():
    """Get scan statistics for analytics."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total scans
    cursor.execute('SELECT COUNT(*) FROM scans')
    total = cursor.fetchone()[0]
    
    # Phishing (high + critical risk)
    cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_level IN ("High Risk", "Critical Risk")')
    phishing = cursor.fetchone()[0]
    
    # Low risk
    cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_level = "Low Risk"')
    low_risk = cursor.fetchone()[0]
    
    # High risk
    cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_level = "High Risk"')
    high_risk = cursor.fetchone()[0]
    
    # Phishing percentage
    phishing_pct = (phishing / total * 100) if total > 0 else 0
    
    conn.close()
    
    return {
        'total_scanned': total,
        'potential_phishing': phishing,
        'low_risk': low_risk,
        'high_risk': high_risk,
        'phishing_percentage': round(phishing_pct, 2)
    }


def get_weekly_activity():
    """Get weekly scanning activity."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DATE(detected_at) as date, COUNT(*) as count
        FROM scans
        WHERE detected_at >= date('now', '-7 days')
        GROUP BY DATE(detected_at)
    ''')
    activity = cursor.fetchall()
    conn.close()
    
    return [{'date': str(row[0]), 'count': row[1]} for row in activity]


def get_risk_distribution():
    """Get risk distribution."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT risk_level, COUNT(*) as count
        FROM scans
        GROUP BY risk_level
    ''')
    distribution = cursor.fetchall()
    conn.close()
    
    return [{'level': row[0], 'count': row[1]} for row in distribution]