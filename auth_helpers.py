import re
import time
import jwt as jwt_lib
from collections import defaultdict
from functools import wraps
from flask import current_app, request, jsonify
from db import get_db

# Rate limiting storage
request_counts = defaultdict(list)


def rate_limit(max_requests=10, window_seconds=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Skip rate limiting in test mode
            if current_app.config.get('TESTING', False):
                return f(*args, **kwargs)
            
            # Allow OPTIONS requests (CORS preflight) to pass through without rate limiting
            if request.method == 'OPTIONS':  # pragma: no cover -- Flask/CORS handles OPTIONS before view
                return f(*args, **kwargs)
            
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            now = time.time()
            request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < window_seconds]
            if len(request_counts[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            request_counts[client_ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator


def generate_download_token(file_id, user_id, expires_in_minutes=30):
    """Generate a temporary download token for GitHub Actions"""
    payload = {
        'file_id': file_id,
        'user_id': user_id,
        'exp': int(time.time()) + (expires_in_minutes * 60),
        'iat': int(time.time()),
        'purpose': 'download'
    }
    
    secret = current_app.config['JWT_SECRET_KEY']
    return jwt_lib.encode(payload, secret, algorithm='HS256')


def verify_download_token(token):
    """Verify and decode download token"""
    try:
        secret = current_app.config['JWT_SECRET_KEY']
        # Allow 60 seconds leeway for clock skew
        payload = jwt_lib.decode(token, secret, algorithms=['HS256'], leeway=60)
        
        # Check if token is for download purpose
        if payload.get('purpose') != 'download':
            return None
            
        return payload
    except jwt_lib.ExpiredSignatureError:
        print("DEBUG: Download token expired")
        return None
    except jwt_lib.InvalidTokenError as e:
        print(f"DEBUG: Invalid download token: {e}")
        return None


def validate_password_strength(password):
    """
    Validate password meets strong requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 12:
        return False, 'Password must be at least 12 characters long'
    
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number'
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, 'Password must contain at least one special character (!@#$%^&* etc.)'
    
    return True, None


def is_admin_user(email):
    """Check if user is admin"""
    conn = get_db()
    try:
        user = conn.execute(
            'SELECT is_admin FROM users WHERE email = ?', (email,)
        ).fetchone()
        if user:
            return bool(user['is_admin']) if user['is_admin'] is not None else False
        return False
    finally:
        conn.close()


def validate_invitation_token(token):
    """
    Validate invitation token:
    - Check JWT signature
    - Check expiration
    - Check if token has been used
    Returns (is_valid, email, error_message)
    """
    from datetime import datetime
    try:
        secret = current_app.config['JWT_SECRET_KEY']
        # Allow 60 seconds leeway for clock skew
        payload = jwt_lib.decode(token, secret, algorithms=['HS256'], leeway=60)
        
        if payload.get('purpose') != 'invitation':
            return False, None, 'Invalid token purpose'
        
        email = payload.get('email')
        if not email:
            return False, None, 'Invalid token: missing email'
        
        # Check database for token
        conn = get_db()
        try:
            token_record = conn.execute(
                '''SELECT email, expires_at, used_at FROM invitation_tokens 
                   WHERE token = ?''',
                (token,)
            ).fetchone()
            
            if not token_record:
                return False, None, 'Invalid or expired invitation token'
            
            # Check if already used
            if token_record['used_at']:
                return False, None, 'This invitation has already been used'
            
            # Check expiration
            expires_at = datetime.fromisoformat(token_record['expires_at'])
            if datetime.utcnow() > expires_at:
                return False, None, 'This invitation has expired'
            
            # Verify email matches
            if token_record['email'] != email:
                return False, None, 'Token email mismatch'
            
            return True, email, None
            
        finally:
            conn.close()
            
    except jwt_lib.ExpiredSignatureError:
        return False, None, 'Invitation token has expired'
    except jwt_lib.InvalidTokenError as e:
        return False, None, f'Invalid invitation token: {str(e)}'
    except Exception as e:
        return False, None, f'Error validating token: {str(e)}'
