"""
Device Communication utilities for IoT Device Management Platform
Handles secure communication with IoT devices
"""

import json
import requests
import logging
import hashlib
import hmac
from datetime import datetime
from django.conf import settings

logger = logging.getLogger(__name__)


def send_device_command_secure(device, command_type, parameters):
    """Send command to device securely with HMAC authentication"""
    try:
        # Prepare command payload
        command_payload = {
            'command': command_type,
            'parameters': parameters,
            'timestamp': datetime.utcnow().isoformat(),
            'device_id': device.device_id
        }
        
        payload_json = json.dumps(command_payload, sort_keys=True)
        
        # Generate HMAC signature
        signature = hmac.new(
            device.device_key.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Send command via MQTT, HTTP, or WebSocket depending on device type
        if hasattr(device, 'connection_type'):
            if device.connection_type == 'mqtt':
                return send_mqtt_command(device, payload_json, signature)
            elif device.connection_type == 'http':
                return send_http_command(device, payload_json, signature)
            elif device.connection_type == 'websocket':
                return send_websocket_command(device, payload_json, signature)
        
        # Default to HTTP for compatibility
        return send_http_command(device, payload_json, signature)
        
    except Exception as e:
        logger.error(f"Command send failed for device {device.device_id}: {str(e)}")
        raise


def send_http_command(device, payload, signature):
    """Send command via HTTP POST"""
    try:
        headers = {
            'Content-Type': 'application/json',
            'X-Device-Signature': signature,
            'X-Device-ID': device.device_id
        }
        
        # Use device's registered endpoint or default
        endpoint = getattr(device, 'command_endpoint', f'https://{device.ip_address}:8443/api/commands')
        
        response = requests.post(
            endpoint,
            data=payload,
            headers=headers,
            timeout=30,
            verify=True  # Always verify SSL certificates
        )
        
        if response.status_code == 200:
            return {'status': 'sent', 'response': response.json()}
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP command failed: {str(e)}")
        raise


def send_mqtt_command(device, payload, signature):
    """Send command via MQTT"""
    try:
        import paho.mqtt.client as mqtt
        
        def on_publish(client, userdata, mid):
            userdata['published'] = True
        
        client_data = {'published': False}
        client = mqtt.Client()
        client.user_data_set(client_data)
        client.on_publish = on_publish
        
        # Use device credentials for MQTT authentication
        client.username_pw_set(device.device_id, device.api_key)
        
        # Connect to MQTT broker
        broker_host = getattr(settings, 'MQTT_BROKER_HOST', 'localhost')
        broker_port = getattr(settings, 'MQTT_BROKER_PORT', 1883)
        
        client.connect(broker_host, broker_port, 60)
        client.loop_start()
        
        # Publish command to device-specific topic
        topic = f"devices/{device.device_id}/commands"
        command_message = json.dumps({
            'payload': payload,
            'signature': signature
        })
        
        client.publish(topic, command_message, qos=2)  # Exactly once delivery
        
        # Wait for publish confirmation
        import time
        timeout = 10
        while not client_data['published'] and timeout > 0:
            time.sleep(0.1)
            timeout -= 0.1
        
        client.loop_stop()
        client.disconnect()
        
        if client_data['published']:
            return {'status': 'sent', 'method': 'mqtt'}
        else:
            raise Exception("MQTT publish timeout")
            
    except Exception as e:
        logger.error(f"MQTT command failed: {str(e)}")
        raise


def send_websocket_command(device, payload, signature):
    """Send command via WebSocket"""
    try:
        import websocket
        
        # WebSocket endpoint for device
        ws_url = f"wss://{device.ip_address}:8444/ws/commands"
        
        def on_message(ws, message):
            logger.info(f"WebSocket response from {device.device_id}: {message}")
        
        def on_error(ws, error):
            logger.error(f"WebSocket error for {device.device_id}: {error}")
        
        ws = websocket.WebSocketApp(
            ws_url,
            on_message=on_message,
            on_error=on_error
        )
        
        # Send command with signature
        command_message = json.dumps({
            'payload': payload,
            'signature': signature
        })
        
        ws.send(command_message)
        ws.close()
        
        return {'status': 'sent', 'method': 'websocket'}
        
    except Exception as e:
        logger.error(f"WebSocket command failed: {str(e)}")
        raise


def parse_device_payload_safe(raw_payload, content_type='application/json'):
    """Safely parse device payload with validation"""
    try:
        # Only accept JSON payloads for security
        if content_type != 'application/json':
            raise ValueError("Only JSON payloads are supported")
        
        # Size limit check
        if len(raw_payload) > 1024 * 1024:  # 1MB limit
            raise ValueError("Payload too large")
        
        # Parse JSON
        parsed_data = json.loads(raw_payload)
        
        # Validate structure
        if not isinstance(parsed_data, dict):
            raise ValueError("Payload must be a JSON object")
        
        # Sanitize data types
        sanitized_data = {}
        for key, value in parsed_data.items():
            if isinstance(key, str) and len(key) <= 50:
                if isinstance(value, (str, int, float, bool)):
                    sanitized_data[key] = value
                elif isinstance(value, dict):
                    # Limit nested object size
                    if len(json.dumps(value)) <= 1000:
                        sanitized_data[key] = value
        
        return sanitized_data
        
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Invalid payload received: {str(e)}")
        raise


def validate_device_heartbeat(device, heartbeat_data):
    """Validate device heartbeat data"""
    try:
        required_fields = ['device_id', 'timestamp', 'status']
        
        for field in required_fields:
            if field not in heartbeat_data:
                return False, f"Missing required field: {field}"
        
        # Validate device ID matches
        if heartbeat_data['device_id'] != device.device_id:
            return False, "Device ID mismatch"
        
        # Validate timestamp is recent (within 5 minutes)
        try:
            heartbeat_time = datetime.fromisoformat(heartbeat_data['timestamp'].replace('Z', '+00:00'))
            time_diff = abs((datetime.utcnow() - heartbeat_time.replace(tzinfo=None)).total_seconds())
            
            if time_diff > 300:  # 5 minutes
                return False, "Heartbeat timestamp too old"
        except ValueError:
            return False, "Invalid timestamp format"
        
        # Validate status
        valid_statuses = ['online', 'offline', 'maintenance', 'error']
        if heartbeat_data.get('status') not in valid_statuses:
            return False, "Invalid status"
        
        return True, "Valid"
        
    except Exception as e:
        logger.error(f"Heartbeat validation error: {str(e)}")
        return False, "Validation error"


def encrypt_device_communication(data, device_key):
    """Encrypt data for device communication"""
    try:
        from cryptography.fernet import Fernet
        import base64
        
        # Derive key from device key
        key = base64.urlsafe_b64encode(hashlib.sha256(device_key.encode()).digest())
        fernet = Fernet(key)
        
        encrypted_data = fernet.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()
        
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise


def decrypt_device_communication(encrypted_data, device_key):
    """Decrypt data from device communication"""
    try:
        from cryptography.fernet import Fernet
        import base64
        
        # Derive key from device key
        key = base64.urlsafe_b64encode(hashlib.sha256(device_key.encode()).digest())
        fernet = Fernet(key)
        
        decoded_data = base64.b64decode(encrypted_data.encode())
        decrypted_data = fernet.decrypt(decoded_data)
        return decrypted_data.decode()
        
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise 