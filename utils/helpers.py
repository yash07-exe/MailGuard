"""MailGuard Utility Helpers"""

import re
import os
import json
from datetime import datetime
from config import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE


def sanitize_input(user_input):
    """Sanitize user input to prevent XSS and injection attacks."""
    if not user_input:
        return ''
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>&"\']', '', user_input)
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)
    
    # HTML encode
    sanitized = sanitized.replace('&', '&')
    sanitized = sanitized.replace('<', '<')
    sanitized = sanitized.replace('>', '>')
    sanitized = sanitized.replace('"', '"')
    sanitized = sanitized.replace("'", "")
    
    return sanitized.strip()


def allowed_file(filename):
    """Check if uploaded file has an allowed extension."""
    if not filename:
        return False
    
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS


def format_risk_score(score):
    """Format risk score with appropriate styling class."""
    if score >= 70:
        return {
            'value': score,
            'level': 'Critical Risk',
            'class': 'critical'
        }
    elif score >= 40:
        return {
            'value': score,
            'level': 'High Risk',
            'class': 'high'
        }
    elif score >= 20:
        return {
            'value': score,
            'level': 'Moderate Risk',
            'class': 'moderate'
        }
    else:
        return {
            'value': score,
            'level': 'Low Risk',
            'class': 'low'
        }


def format_risk_level(risk_level):
    """Format risk level for display."""
    levels = {
        'Low Risk': ('low', 'Low'),
        'Moderate Risk': ('moderate', 'Moderate'),
        'High Risk': ('high', 'High'),
        'Critical Risk': ('critical', 'Critical')
    }
    
    if risk_level in levels:
        css_class, display = levels[risk_level]
        return {'css': css_class, 'display': display}
    
    return {'css': 'low', 'display': 'Low Risk'}


def extract_sender_email(sender_string):
    """Extract email address from sender string."""
    if not sender_string:
        return 'Unknown'
    
    # Extract email from "Name <email>" format or just "email"
    email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender_string)
    if email_match:
        return email_match.group(0)
    
    return sender_string


def extract_domain(email_address):
    """Extract domain from email address."""
    if not email_address or '@' not in email_address:
        return ''
    
    return email_address.split('@')[-1]


def check_punycode(domain):
    """Check if domain uses Punycode encoding."""
    if not domain:
        return False
    
    # Punycode domains start with "xn--"
    return domain.startswith('xn--') or 'xn--' in domain


def generate_security_summary(indicators):
    """Generate a security summary from detected indicators."""
    if not indicators:
        return {
            'total_indicators': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'summary': 'No significant threats detected'
        }
    
    risk_counts = {'high': 0, 'medium': 0, 'low': 0}
    categories = {}
    
    for indicator in indicators:
        risk = indicator.get('risk', 'low').lower()
        if risk in risk_counts:
            risk_counts[risk] += 1
        
        cat = indicator.get('type', 'other')
        categories[cat] = categories.get(cat, 0) + 1
    
    total = sum(risk_counts.values())
    
    # Generate summary text
    if risk_counts['high'] > 3:
        summary = f'⚠️ {risk_counts["high"]} high-risk indicators detected - strong phishing signals'
    elif risk_counts['high'] > 0:
        summary = f'⚠️ {risk_counts["high"]} high-risk indicator(s) detected'
    elif risk_counts['medium'] > 2:
        summary = f'ℹ️ {risk_counts["medium"]} moderate-risk indicator(s) detected'
    else:
        summary = '✓ No significant threats detected'
    
    return {
        'total_indicators': total,
        'high_risk': risk_counts['high'],
        'medium_risk': risk_counts['medium'],
        'low_risk': risk_counts['low'],
        'summary': summary,
        'categories': categories
    }