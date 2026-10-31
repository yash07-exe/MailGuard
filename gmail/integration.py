"""MailGuard Gmail API Integration"""

import os
import json
import sqlite3
import datetime
import base64
import email
import email.utils
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from werkzeug.utils import secure_filename


def get_credentials_from_db(user_id=None):
    """Retrieve Gmail credentials from SQLite database."""
    conn = sqlite3.connect('mailguard.db') if not hasattr(get_credentials_from_db, 'db_path') else sqlite3.connect(get_credentials_from_db.db_path)
    # Actually, use the configured database path
    from config import DATABASE_PATH
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute('SELECT google_id, email_address, access_token, refresh_token, token_expiry FROM users WHERE id = ?', (user_id,))
    else:
        # Get the current user from session
        cursor.execute('SELECT google_id, email_address, access_token, refresh_token, token_expiry FROM users LIMIT 1')
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return None
    
    google_id, email_address, access_token, refresh_token, token_expiry = user
    
    # Check if token is expired
    expiry = None
    if token_expiry:
        expiry = datetime.datetime.fromisoformat(token_expiry) if isinstance(token_expiry, str) else token_expiry
    
    now = datetime.datetime.utcnow()
    
    # If token is expired or about to expire, we need to refresh
    if expiry and expiry < now:
        # Try to refresh the token
        try:
            creds = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID'),
                client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET'),
                scopes=['https://www.googleapis.com/auth/gmail.readonly']
            )
            import google.auth
            creds.refresh(google.auth.requests.Request())
            
            # Update in database
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET access_token = ?, refresh_token = ?, token_expiry = ? WHERE id = ?',
                (creds.token, creds.refresh_token, datetime.datetime.utcnow().isoformat(), google_id)
            )
            conn.commit()
            conn.close()
        except Exception:
            return None
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token if refresh_token else '',
        'expiry': expiry.isoformat() if expiry else None,
        'email_address': email_address
    }


def get_gmail_service(user_id=None):
    """Get an authorized Gmail API service instance."""
    creds_data = get_credentials_from_db(user_id)
    
    if not creds_data or not creds_data.get('access_token'):
        return None
    
    try:
        creds = Credentials(
            token=creds_data['access_token'],
            refresh_token=creds_data.get('refresh_token', ''),
            token_uri='https://oauth2.googleapis.com/token',
            client_id=os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET'),
            scopes=['https://www.googleapis.com/auth/gmail.readonly']
        )
        
        if creds.expired and creds.refresh_token:
            import google.auth
            creds.refresh(google.auth.requests.Request())
        
        service = build('gmail', 'v1', credentials=creds)
        return service
    
    except Exception as e:
        print(f"Error creating Gmail service: {e}")
        return None


def list_recent_emails(service, max_results=10):
    """List recent emails from the user's Gmail account."""
    try:
        # Get recent messages
        results = service.users().messages().list(
            userId='me',
            maxResults=max_results,
            labelIds=['INBOX']
        ).execute()
        
        messages = results.get('messages', [])
        
        emails = []
        for msg in messages:
            # Get message details
            msg_details = service.users().messages().get(userId='me', id=msg['id']).execute()
            
            # Extract headers
            headers = {}
            if 'payload' in msg_details and 'headers' in msg_details['payload']:
                for header in msg_details['payload']['headers']:
                    headers[header['name'].lower()] = header['value']
            
            # Get snippet
            snippet = msg_details.get('snippet', '')
            
            # Get date
            date_str = headers.get('date', '')
            date_formatted = ''
            if date_str:
                try:
                    parsed_date = email.utils.parsedate_to_datetime(date_str)
                    date_formatted = parsed_date.strftime('%Y-%m-%d %H:%M')
                except:
                    date_formatted = date_str
            
            # Get from address
            from_addr = headers.get('from', '')
            
            emails.append({
                'id': msg['id'],
                'from': from_addr,
                'subject': subject or '',
                'snippet': snippet,
                'date': date_formatted,
                'label_ids': msg_details.get('labelIds', [])
            })
        
        return emails
    
    except Exception as e:
        print(f"Error listing emails: {e}")
        return []


def get_email_details(service, email_id):
    """Get detailed information about a specific Gmail email."""
    try:
        msg = service.users().messages().get(userId='me', id=email_id).execute()
        
        # Extract headers
        headers = {}
        if 'payload' in msg and 'headers' in msg['payload']:
            for header in msg['payload']['headers']:
                headers[header['name'].lower()] = header['value']
        
        # Extract body text
        body = ''
        body_html = ''
        
        if 'payload' in msg and 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                mime_type = part.get('mimeType', '')
                data = part.get('body', {}).get('data', '')
                
                if mime_type == 'text/plain' and data:
                    body = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                elif mime_type == 'text/html' and data:
                    body_html = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
        elif 'body' in msg and 'data' in msg['body']:
            data = msg['body'].get('data', '')
            if data:
                body = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
        
        # Clean up HTML tags from body if needed
        import re
        body_clean = re.sub(r'<.*?>', '', body_html) if body_html else body
        
        return {
            'id': msg.get('id'),
            'thread_id': msg.get('threadId'),
            'from': headers.get('from', ''),
            'to': headers.get('to', ''),
            'subject': headers.get('subject', ''),
            'date': headers.get('date', ''),
            'body': body_clean,
            'body_html': body_html,
            'labels': msg.get('labelIds', []),
            'snippet': msg.get('snippet', '')
        }
    
    except Exception as e:
        return None


def revoke_token(user_id=None):
    """Revoke a user's Gmail token."""
    creds_data = get_credentials_from_db(user_id)
    
    if not creds_data:
        return False
    
    try:
        from googleapiclient.discovery import build
        from google.oauth2.credentials import Credentials
        
        creds = Credentials(
            token=creds_data['access_token'],
            refresh_token=creds_data.get('refresh_token', ''),
            token_uri='https://oauth2.googleapis.com/token',
            client_id=os.getenv('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET'),
            scopes=['https://www.googleapis.com/auth/gmail.readonly']
        )
        
        # Revoke via OAuth2 revocation endpoint
        import urllib.request
        urllib.request.urlopen(
            'https://oauth2.googleapis.com/revoke?token=' + creds.token
        )
        
        # Remove from database
        from config import DATABASE_PATH
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE google_id = ?', (creds_data.get('google_id'),))
        conn.commit()
        conn.close()
        
        return True
    
    except Exception as e:
        print(f"Error revoking token: {e}")
        return False