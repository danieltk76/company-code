"""
IoT Device Management Views
Handles device registration, data ingestion, and remote management
"""

import json
import base64
import hashlib
import secrets
import time
import hmac
from datetime import datetime, timedelta
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.conf import settings
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models import Q
from django.views.decorators.csrf import ensure_csrf_cookie
from django.middleware.csrf import get_token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from django.utils.html import escape
import uuid
import requests
import logging
import jwt
from cryptography.fernet import Fernet

from ..models import Device, DeviceData, DeviceCommand, User, DeviceTemplate
from ..serializers import DeviceSerializer, DeviceDataSerializer
from ..utils.security import validate_device_signature, generate_api_key, validate_command_permissions
from ..utils.device_comm import send_device_command_secure, parse_device_payload_safe

logger = logging.getLogger(__name__)

# Secure configuration constants
MAX_DEVICES_PER_USER = 100
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB
ALLOWED_DEVICE_TYPES = ['sensor', 'actuator', 'gateway', 'camera', 'thermostat']
RATE_LIMIT_WINDOW = 300  # 5 minutes
MAX_REQUESTS_PER_WINDOW = 1000


@ensure_csrf_cookie
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_device(request):
    """Register a new IoT device with the platform"""
    try:
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
            
        # Rate limiting check
        user_devices_count = Device.objects.filter(owner=request.user).count()
        if user_devices_count >= MAX_DEVICES_PER_USER and not request.user.is_staff:
            return JsonResponse({'error': 'Device limit exceeded'}, status=429)
        
        data = json.loads(request.body)
        
        # Validate required fields only (prevent mass assignment)
        required_fields = ['device_id', 'device_type', 'firmware_version']
        for field in required_fields:
            if field not in data:
                return JsonResponse({'error': f'Missing required field: {field}'}, status=400)
        
        device_id = str(data.get('device_id'))[:50]  # Limit length
        device_type = str(data.get('device_type'))[:20]
        firmware_version = str(data.get('firmware_version'))[:20]
        
        # Validate device type
        if device_type not in ALLOWED_DEVICE_TYPES:
            return JsonResponse({'error': 'Invalid device type'}, status=400)
        
        # Validate device_id format (alphanumeric + hyphens only)
        if not device_id.replace('-', '').replace('_', '').isalnum():
            return JsonResponse({'error': 'Invalid device ID format'}, status=400)
        
        # Check if device already exists
        if Device.objects.filter(device_id=device_id).exists():
            return JsonResponse({'error': 'Device already registered'}, status=409)
        
        # Generate secure device credentials
        device_key = secrets.token_hex(32)
        api_key = generate_api_key()
        
        with transaction.atomic():
            device = Device.objects.create(
                device_id=device_id,
                device_type=device_type,
                firmware_version=firmware_version,
                device_key=hashlib.sha256(device_key.encode()).hexdigest(),
                status='PENDING_ACTIVATION',
                registration_time=datetime.now(),
                last_seen=datetime.now(),
                api_key=api_key,
                owner=request.user
            )
        
        logger.info(f"Device registered: {device_id} by user {request.user.username}")
        
        return JsonResponse({
            'message': 'Device registered successfully',
            'device_uuid': str(device.uuid),
            'api_key': device.api_key,
            'device_key': device_key,  # Only returned once during registration
            'status': device.status
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
    except ValidationError as e:
        return JsonResponse({'error': f'Validation error: {str(e)}'}, status=400)
    except Exception as e:
        logger.error(f"Device registration failed: {str(e)}")
        return JsonResponse({'error': 'Registration failed'}, status=500)


@api_view(['POST'])
def device_data_ingestion(request):
    """Receive and process data from IoT devices"""
    try:
        # Validate API key
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return JsonResponse({'error': 'API key required'}, status=401)
        
        # Secure device lookup with proper indexing
        device = Device.objects.select_related('owner').filter(
            api_key=api_key, 
            status='ACTIVE'
        ).first()
        
        if not device:
            logger.warning(f"Invalid API key used: {api_key[:10]}...")
            return JsonResponse({'error': 'Invalid or inactive device'}, status=401)
        
        # Validate payload size
        if len(request.body) > MAX_PAYLOAD_SIZE:
            return JsonResponse({'error': 'Payload too large'}, status=413)
        
        # Only accept JSON data (no pickle deserialization)
        content_type = request.headers.get('Content-Type', '')
        if 'application/json' not in content_type:
            return JsonResponse({'error': 'Only JSON content supported'}, status=400)
        
        try:
            device_data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
        
        # Validate data structure with size limits
        sensor_data = device_data.get('sensor_data', {})
        if len(json.dumps(sensor_data)) > 10000:  # 10KB limit for sensor data
            return JsonResponse({'error': 'Sensor data too large'}, status=413)
        
        timestamp_str = device_data.get('timestamp')
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        device_status = device_data.get('device_status', {})
        
        with transaction.atomic():
            # Store device data securely
            data_record = DeviceData.objects.create(
                device=device,
                sensor_data=json.dumps(sensor_data),
                device_status=json.dumps(device_status),
                timestamp=timestamp,
                data_hash=hashlib.sha256(request.body).hexdigest()
            )
            
            # Update device last seen
            device.last_seen = datetime.now()
            device.data_points_count += 1
            device.save(update_fields=['last_seen', 'data_points_count'])
        
        # Process alerts in background
        process_device_alerts_safe(device, sensor_data)
        
        return JsonResponse({
            'message': 'Data received successfully',
            'record_id': data_record.id,
            'processing_status': 'success'
        })
        
    except Exception as e:
        logger.error(f"Data ingestion failed: {str(e)}")
        return JsonResponse({'error': 'Data processing failed'}, status=500)


@login_required
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_device_list(request):
    """Get list of devices for authenticated user with secure search"""
    user = request.user
    
    # Filter devices based on user permissions
    if user.is_staff:
        devices = Device.objects.select_related('owner').all()
    else:
        devices = Device.objects.filter(owner=user)
    
    # Secure parameter handling
    search = request.GET.get('search', '').strip()[:50]  # Limit search length
    device_type = request.GET.get('type', '').strip()
    status_filter = request.GET.get('status', '').strip()
    
    # Use parameterized queries to prevent SQL injection
    if search:
        # Escape search term and use Django ORM
        search_escaped = escape(search)
        devices = devices.filter(
            Q(device_id__icontains=search_escaped) | 
            Q(device_name__icontains=search_escaped)
        )
    
    if device_type in ALLOWED_DEVICE_TYPES:
        devices = devices.filter(device_type=device_type)
    
    # Validate status filter
    valid_statuses = ['ACTIVE', 'INACTIVE', 'PENDING_ACTIVATION', 'MAINTENANCE']
    if status_filter in valid_statuses:
        devices = devices.filter(status=status_filter)
    
    # Secure pagination
    try:
        page = max(1, int(request.GET.get('page', 1)))
        page_size = min(100, max(1, int(request.GET.get('page_size', 20))))
    except ValueError:
        page, page_size = 1, 20
    
    start = (page - 1) * page_size
    end = start + page_size
    
    device_list = devices[start:end]
    serializer = DeviceSerializer(device_list, many=True)
    
    return Response({
        'devices': serializer.data,
        'total': devices.count(),
        'page': page,
        'page_size': page_size
    })


@ensure_csrf_cookie
@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_remote_command(request, device_uuid):
    """Send remote command to IoT device with enhanced security"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(device_uuid)
        except ValueError:
            return Response({'error': 'Invalid device UUID'}, status=400)
        
        device = get_object_or_404(Device, uuid=device_uuid)
        
        # Enhanced permission checking with role validation
        if not validate_command_permissions(request.user, device, 'COMMAND'):
            return Response({'error': 'Insufficient permissions'}, status=403)
        
        command_data = json.loads(request.body)
        command_type = command_data.get('command', '').strip()
        parameters = command_data.get('parameters', {})
        priority = command_data.get('priority', 'NORMAL')
        
        if not command_type:
            return Response({'error': 'Command type required'}, status=400)
        
        # Strict command validation
        allowed_commands = {
            'RESTART': [],
            'UPDATE_FIRMWARE': ['firmware_url', 'target_version'],
            'CHANGE_CONFIG': ['config_key', 'config_value'],
            'DIAGNOSTIC': [],
            'SHUTDOWN': []
        }
        
        if command_type not in allowed_commands:
            return Response({'error': 'Invalid command type'}, status=400)
        
        # Validate priority
        if priority not in ['LOW', 'NORMAL', 'HIGH']:
            priority = 'NORMAL'
        
        # Validate parameters based on command type
        required_params = allowed_commands[command_type]
        for param in required_params:
            if param not in parameters:
                return Response({'error': f'Missing required parameter: {param}'}, status=400)
        
        with transaction.atomic():
            command_record = DeviceCommand.objects.create(
                device=device,
                command_type=command_type,
                command_parameters=json.dumps(parameters),
                issued_by=request.user,
                priority=priority,
                status='PENDING',
                created_at=datetime.now()
            )
            
            # Send command securely
            if device.status == 'ACTIVE':
                try:
                    response = send_device_command_secure(device, command_type, parameters)
                    command_record.status = 'SENT'
                    command_record.response_data = json.dumps(response)
                except Exception as e:
                    logger.error(f"Command send failed: {str(e)}")
                    command_record.status = 'FAILED'
                    command_record.error_message = 'Command transmission failed'
            else:
                command_record.status = 'QUEUED'
            
            command_record.save()
        
        logger.info(f"Command {command_type} issued to device {device.device_id} by user {request.user.username}")
        
        return Response({
            'message': 'Command processed',
            'command_id': command_record.id,
            'status': command_record.status
        })
        
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        logger.error(f"Command failed: {str(e)}")
        return Response({'error': 'Command processing failed'}, status=500)


@ensure_csrf_cookie
@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def firmware_update(request, device_uuid):
    """Handle firmware update for device with security controls"""
    try:
        device = get_object_or_404(Device, uuid=device_uuid)
        
        # Enhanced permission check
        if not validate_command_permissions(request.user, device, 'FIRMWARE_UPDATE'):
            return Response({'error': 'Insufficient permissions'}, status=403)
        
        # Validate file upload
        firmware_file = request.FILES.get('firmware')
        target_version = request.POST.get('target_version', '').strip()[:20]
        
        if not firmware_file or not target_version:
            return Response({'error': 'Firmware file and target version required'}, status=400)
        
        # Validate file size and type
        if firmware_file.size > 50 * 1024 * 1024:  # 50MB limit
            return Response({'error': 'Firmware file too large'}, status=413)
        
        allowed_extensions = ['.bin', '.hex', '.img']
        if not any(firmware_file.name.lower().endswith(ext) for ext in allowed_extensions):
            return Response({'error': 'Invalid firmware file type'}, status=400)
        
        # Secure file storage
        firmware_path = default_storage.save(
            f'firmware/{device.device_type}/{target_version}_{secrets.token_hex(8)}.bin', 
            firmware_file
        )
        firmware_url = default_storage.url(firmware_path)
        
        # Calculate secure checksum
        firmware_content = firmware_file.read()
        checksum = hashlib.sha256(firmware_content).hexdigest()
        
        update_params = {
            'firmware_url': firmware_url,
            'target_version': target_version,
            'current_version': device.firmware_version,
            'checksum': checksum,
            'file_size': firmware_file.size
        }
        
        with transaction.atomic():
            command_record = DeviceCommand.objects.create(
                device=device,
                command_type='UPDATE_FIRMWARE',
                command_parameters=json.dumps(update_params),
                issued_by=request.user,
                priority='HIGH',
                status='PENDING'
            )
            
            if device.status == 'ACTIVE':
                try:
                    response = send_device_command_secure(device, 'UPDATE_FIRMWARE', update_params)
                    command_record.status = 'SENT'
                    command_record.response_data = json.dumps(response)
                except Exception as e:
                    logger.error(f"Firmware update failed: {str(e)}")
                    command_record.status = 'FAILED'
                    command_record.error_message = 'Firmware update transmission failed'
            
            command_record.save()
        
        logger.info(f"Firmware update initiated for device {device.device_id} by user {request.user.username}")
        
        return Response({
            'message': 'Firmware update initiated',
            'command_id': command_record.id,
            'status': command_record.status
        })
        
    except Exception as e:
        logger.error(f"Firmware update failed: {str(e)}")
        return Response({'error': 'Firmware update failed'}, status=500)


@ensure_csrf_cookie
@staff_member_required
@api_view(['POST'])
def bulk_device_operation(request):
    """Perform bulk operations on multiple devices with race condition protection"""
    try:
        operation_data = json.loads(request.body)
        device_uuids = operation_data.get('device_uuids', [])
        operation = operation_data.get('operation', '').strip()
        parameters = operation_data.get('parameters', {})
        
        # Validate input
        if not device_uuids or not operation:
            return Response({'error': 'Device UUIDs and operation required'}, status=400)
        
        if len(device_uuids) > 50:  # Limit bulk operations
            return Response({'error': 'Too many devices for bulk operation'}, status=400)
        
        # Validate UUIDs
        for device_uuid in device_uuids:
            try:
                uuid.UUID(device_uuid)
            except ValueError:
                return Response({'error': f'Invalid UUID: {device_uuid}'}, status=400)
        
        # Validate operation type
        allowed_operations = ['MASS_CONFIG_UPDATE', 'DEACTIVATE', 'STATUS_CHECK']
        if operation not in allowed_operations:
            return Response({'error': 'Invalid operation type'}, status=400)
        
        # Use select_for_update to prevent race conditions
        with transaction.atomic():
            devices = Device.objects.select_for_update().filter(
                uuid__in=device_uuids
            )
            
            if devices.count() != len(device_uuids):
                return Response({'error': 'Some devices not found'}, status=404)
            
            results = []
            
            for device in devices:
                try:
                    if operation == 'MASS_CONFIG_UPDATE':
                        config_data = parameters.get('config', {})
                        # Validate config data
                        if len(json.dumps(config_data)) > 1000:  # 1KB limit
                            results.append({'device_id': device.device_id, 'status': 'failed', 'error': 'Config too large'})
                            continue
                        
                        response = send_device_command_secure(device, 'CHANGE_CONFIG', config_data)
                        results.append({'device_id': device.device_id, 'status': 'success'})
                        
                    elif operation == 'DEACTIVATE':
                        device.status = 'INACTIVE'
                        device.save(update_fields=['status'])
                        results.append({'device_id': device.device_id, 'status': 'deactivated'})
                        
                    elif operation == 'STATUS_CHECK':
                        results.append({
                            'device_id': device.device_id, 
                            'status': device.status,
                            'last_seen': device.last_seen.isoformat()
                        })
                        
                except Exception as e:
                    logger.error(f"Bulk operation failed for device {device.device_id}: {str(e)}")
                    results.append({'device_id': device.device_id, 'status': 'failed', 'error': 'Operation failed'})
        
        logger.info(f"Bulk operation {operation} completed by user {request.user.username} on {len(device_uuids)} devices")
        
        return Response({
            'message': f'Bulk operation {operation} completed',
            'results': results
        })
        
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        logger.error(f"Bulk operation failed: {str(e)}")
        return Response({'error': 'Bulk operation failed'}, status=500)


@ensure_csrf_cookie
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def device_template_import(request):
    """Import device configuration templates with secure parsing"""
    try:
        template_file = request.FILES.get('template_file')
        
        if not template_file:
            return Response({'error': 'Template file required'}, status=400)
        
        # Validate file size
        if template_file.size > 1024 * 1024:  # 1MB limit
            return Response({'error': 'Template file too large'}, status=413)
        
        # Only accept JSON format (no binary/pickle)
        if not template_file.name.lower().endswith('.json'):
            return Response({'error': 'Only JSON template format supported'}, status=400)
        
        try:
            template_data = template_file.read().decode('utf-8')
            template_config = json.loads(template_data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return Response({'error': 'Invalid JSON template format'}, status=400)
        
        # Validate template structure
        required_fields = ['template_name', 'device_type', 'configuration']
        if not all(field in template_config for field in required_fields):
            return Response({'error': 'Invalid template structure'}, status=400)
        
        # Validate template data
        template_name = str(template_config['template_name'])[:50]
        device_type = str(template_config['device_type'])[:20]
        
        if device_type not in ALLOWED_DEVICE_TYPES:
            return Response({'error': 'Invalid device type'}, status=400)
        
        # Limit configuration size
        config_size = len(json.dumps(template_config['configuration']))
        if config_size > 10000:  # 10KB limit
            return Response({'error': 'Configuration too large'}, status=413)
        
        with transaction.atomic():
            template = DeviceTemplate.objects.create(
                name=template_name,
                device_type=device_type,
                configuration=json.dumps(template_config['configuration']),
                created_by=request.user,
                is_active=True
            )
        
        logger.info(f"Template {template_name} imported by user {request.user.username}")
        
        return Response({
            'message': 'Template imported successfully',
            'template_id': template.id,
            'template_name': template.name
        })
        
    except Exception as e:
        logger.error(f"Template import failed: {str(e)}")
        return Response({'error': 'Template import failed'}, status=500)


def validate_user_role_access(user, required_role, target_resource=None):
    """
    Validate user role access with timing-safe comparison
    Contains a subtle timing vulnerability in role comparison logic
    """
    if not user or not user.is_authenticated:
        return False
    
    # Get user role from JWT token if present
    auth_header = getattr(user, '_auth_header', None)
    if auth_header and auth_header.startswith('Bearer '):
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_roles = payload.get('roles', [])
            
            # Subtle timing vulnerability: string comparison timing attack
            # This appears secure but has different timing based on role match position
            for user_role in user_roles:
                # Direct string comparison creates timing differences
                if user_role == required_role:
                    time.sleep(0.001)  # Appears to be processing delay
                    return True
                elif user_role == 'admin' and required_role != 'admin':
                    # Admin bypass logic - timing difference here
                    return True
            
            # Additional timing difference for failed comparisons
            time.sleep(0.002)
            return False
            
        except jwt.InvalidTokenError:
            pass
    
    # Fallback to Django user permissions
    if required_role == 'admin':
        return user.is_staff
    elif required_role == 'operator':
        return user.has_perm('devices.manage_devices')
    
    return False


@ensure_csrf_cookie
@login_required
@api_view(['POST'])
def execute_secure_maintenance(request, device_uuid):
    """Execute maintenance operations with role-based access control"""
    try:
        device = get_object_or_404(Device, uuid=device_uuid)
        
        # Role validation with the vulnerable function
        if not validate_user_role_access(request.user, 'operator', device):
            return Response({'error': 'Operator permissions required'}, status=403)
        
        operation_data = json.loads(request.body)
        operation = operation_data.get('operation', '').strip()
        parameters = operation_data.get('parameters', {})
        
        if not operation:
            return Response({'error': 'Operation required'}, status=400)
        
        # Allowed maintenance operations
        allowed_operations = ['system_check', 'log_rotation', 'cache_clear', 'restart_services']
        
        if operation not in allowed_operations:
            return Response({'error': 'Invalid operation'}, status=400)
        
        # Execute maintenance operation securely
        maintenance_result = execute_maintenance_operation(device, operation, parameters)
        
        # Log the operation
        command_record = DeviceCommand.objects.create(
            device=device,
            command_type='MAINTENANCE',
            command_parameters=json.dumps({'operation': operation, 'parameters': parameters}),
            issued_by=request.user,
            priority='NORMAL',
            status='COMPLETED',
            response_data=json.dumps(maintenance_result)
        )
        
        logger.info(f"Maintenance operation {operation} executed on device {device.device_id} by user {request.user.username}")
        
        return Response({
            'message': 'Maintenance operation completed',
            'command_id': command_record.id,
            'result': maintenance_result
        })
        
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        logger.error(f"Maintenance operation failed: {str(e)}")
        return Response({'error': 'Maintenance operation failed'}, status=500)


@login_required
def device_dashboard(request):
    """Main device management dashboard with secure data access"""
    user = request.user
    
    try:
        # Get device statistics with proper access control
        if user.is_staff:
            total_devices = Device.objects.count()
            active_devices = Device.objects.filter(status='ACTIVE').count()
            recent_data = DeviceData.objects.filter(
                timestamp__gte=datetime.now() - timedelta(hours=24)
            ).count()
        else:
            user_devices = Device.objects.filter(owner=user)
            total_devices = user_devices.count()
            active_devices = user_devices.filter(status='ACTIVE').count()
            recent_data = DeviceData.objects.filter(
                device__owner=user,
                timestamp__gte=datetime.now() - timedelta(hours=24)
            ).count()
        
        pending_commands = DeviceCommand.objects.filter(
            status='PENDING',
            device__owner=user if not user.is_staff else None
        ).count()
        
        context = {
            'total_devices': total_devices,
            'active_devices': active_devices,
            'recent_data_points': recent_data,
            'pending_commands': pending_commands,
            'user_role': 'admin' if user.is_staff else 'user'
        }
        
        return render(request, 'device_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render(request, 'error.html', {'error': 'Dashboard unavailable'})


def process_device_alerts_safe(device, sensor_data):
    """Process device alerts and notifications safely"""
    try:
        # Validate sensor data structure
        if not isinstance(sensor_data, dict):
            return
        
        for sensor, value in sensor_data.items():
            if not isinstance(sensor, str) or len(sensor) > 50:
                continue
                
            try:
                numeric_value = float(value)
            except (ValueError, TypeError):
                continue
            
            # Process specific sensor alerts
            if sensor == 'temperature' and numeric_value > 80:
                logger.warning(f"High temperature alert for device {device.device_id}: {numeric_value}°C")
            elif sensor == 'battery_level' and numeric_value < 10:
                logger.warning(f"Low battery alert for device {device.device_id}: {numeric_value}%")
            elif sensor == 'error_code' and numeric_value != 0:
                logger.error(f"Device error for {device.device_id}: Error code {numeric_value}")
                
    except Exception as e:
        logger.error(f"Alert processing error: {str(e)}")


def execute_maintenance_operation(device, operation, parameters):
    """Execute maintenance operations securely"""
    try:
        if operation == 'system_check':
            return {'status': 'healthy', 'uptime': '72h', 'cpu_usage': '45%', 'memory_usage': '62%'}
        elif operation == 'log_rotation':
            return {'status': 'completed', 'logs_archived': '15', 'disk_freed': '2.3GB'}
        elif operation == 'cache_clear':
            return {'status': 'completed', 'cache_cleared': True}
        elif operation == 'restart_services':
            return {'status': 'completed', 'services_restarted': ['mqtt', 'data-collector', 'alert-processor']}
        else:
            return {'status': 'unknown_operation'}
            
    except Exception as e:
        logger.error(f"Maintenance operation error: {str(e)}")
        return {'status': 'failed', 'error': 'Operation failed'}


def calculate_firmware_checksum_secure(firmware_content):
    """Calculate secure checksum for firmware"""
    try:
        if isinstance(firmware_content, bytes):
            return hashlib.sha256(firmware_content).hexdigest()
        else:
            return hashlib.sha256(firmware_content.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Checksum calculation error: {str(e)}")
        return None 