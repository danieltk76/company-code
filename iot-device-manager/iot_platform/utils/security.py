"""
Security utilities for IoT Device Management Platform
Provides authentication, authorization, and cryptographic functions
"""

import secrets
import hashlib
import hmac
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User
from cryptography.fernet import Fernet


def generate_api_key():
    """Generate a secure API key for device authentication"""
    return secrets.token_urlsafe(32)


def validate_device_signature(device_id, payload, signature, device_key):
    """Validate HMAC signature from device"""
    try:
        expected_signature = hmac.new(
            device_key.encode(),
            f"{device_id}:{payload}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    except Exception:
        return False


def validate_command_permissions(user, device, command_type):
    """Validate user permissions for device commands"""
    if not user or not user.is_authenticated:
        return False
    
    # Device owner always has permissions
    if device.owner == user:
        return True
    
    # Staff users have elevated permissions
    if user.is_staff:
        return True
    
    # Check specific command permissions
    if command_type == 'FIRMWARE_UPDATE':
        return user.has_perm('devices.firmware_update')
    elif command_type == 'COMMAND':
        return user.has_perm('devices.send_commands')
    
    return False


def encrypt_sensitive_data(data):
    """Encrypt sensitive data using Fernet"""
    try:
        key = settings.ENCRYPTION_KEY.encode() if hasattr(settings, 'ENCRYPTION_KEY') else Fernet.generate_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode()
    except Exception:
        return data


def decrypt_sensitive_data(encrypted_data):
    """Decrypt sensitive data using Fernet"""
    try:
        key = settings.ENCRYPTION_KEY.encode() if hasattr(settings, 'ENCRYPTION_KEY') else Fernet.generate_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return encrypted_data


def generate_device_token(device_id, expires_hours=24):
    """Generate JWT token for device authentication"""
    payload = {
        'device_id': device_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=expires_hours)
    }
    
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def validate_device_token(token):
    """Validate device JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload.get('device_id')
    except jwt.InvalidTokenError:
        return None 