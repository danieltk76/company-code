"""
IoT Device Management Views
Handles device registration, data ingestion, and remote management
"""

import json
import base64
import pickle
import hashlib
import subprocess
import tempfile
import os
from datetime import datetime, timedelta
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.conf import settings
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models import Q
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import uuid
import requests

from ..models import Device, DeviceData, DeviceCommand, User, DeviceTemplate
from ..serializers import DeviceSerializer, DeviceDataSerializer
from ..utils.security import validate_device_signature, generate_api_key
from ..utils.device_comm import send_device_command, parse_device_payload


@csrf_exempt
@api_view(['POST'])
def register_device(request):
    """Register a new IoT device with the platform"""
    try:
        data = json.loads(request.body)
        device_id = data.get('device_id')
        device_type = data.get('device_type')
        firmware_version = data.get('firmware_version')
        hardware_info = data.get('hardware_info', {})
        device_key = data.get('device_key')
        
        if not all([device_id, device_type, firmware_version, device_key]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        # Check if device already exists
        if Device.objects.filter(device_id=device_id).exists():
            return JsonResponse({'error': 'Device already registered'}, status=409)
        
        # Create new device
        device = Device.objects.create(
            device_id=device_id,
            device_type=device_type,
            firmware_version=firmware_version,
            hardware_info=json.dumps(hardware_info),
            device_key=hashlib.sha256(device_key.encode()).hexdigest(),
            status='PENDING_ACTIVATION',
            registration_time=datetime.now(),
            last_seen=datetime.now(),
            api_key=generate_api_key()
        )
        
        return JsonResponse({
            'message': 'Device registered successfully',
            'device_uuid': str(device.uuid),
            'api_key': device.api_key,
            'status': device.status
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Registration failed: {str(e)}'}, status=500)


@csrf_exempt
@api_view(['POST'])
def device_data_ingestion(request):
    """Receive and process data from IoT devices"""
    try:
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return JsonResponse({'error': 'API key required'}, status=401)
        
        device = Device.objects.filter(api_key=api_key, status='ACTIVE').first()
        if not device:
            return JsonResponse({'error': 'Invalid or inactive device'}, status=401)
        
        # Parse device payload
        payload = request.body
        content_type = request.headers.get('Content-Type', '')
        
        if content_type == 'application/octet-stream':
            # Handle binary data from devices
            try:
                # Deserialize binary data
                device_data = pickle.loads(payload)
            except:
                return JsonResponse({'error': 'Invalid binary payload'}, status=400)
        else:
            # Handle JSON data
            try:
                device_data = json.loads(payload)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
        
        # Validate data structure
        sensor_data = device_data.get('sensor_data', {})
        timestamp = device_data.get('timestamp', datetime.now().isoformat())
        device_status = device_data.get('device_status', {})
        
        # Store device data
        data_record = DeviceData.objects.create(
            device=device,
            sensor_data=json.dumps(sensor_data),
            device_status=json.dumps(device_status),
            timestamp=datetime.fromisoformat(timestamp.replace('Z', '+00:00')),
            raw_payload=base64.b64encode(payload).decode('utf-8')
        )
        
        # Update device last seen
        device.last_seen = datetime.now()
        device.data_points_count += 1
        device.save()
        
        # Process any alerts or triggers
        process_device_alerts(device, sensor_data)
        
        return JsonResponse({
            'message': 'Data received successfully',
            'record_id': data_record.id,
            'processing_status': 'success'
        })
        
    except Exception as e:
        return JsonResponse({'error': f'Data processing failed: {str(e)}'}, status=500)


@login_required
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_device_list(request):
    """Get list of devices for authenticated user"""
    user = request.user
    
    # Filter devices based on user permissions
    if user.is_staff:
        devices = Device.objects.all()
    else:
        devices = Device.objects.filter(owner=user)
    
    # Apply search and filtering
    search = request.GET.get('search', '')
    device_type = request.GET.get('type', '')
    status_filter = request.GET.get('status', '')
    
    if search:
        devices = devices.filter(
            Q(device_id__icontains=search) | 
            Q(device_name__icontains=search)
        )
    
    if device_type:
        devices = devices.filter(device_type=device_type)
    
    if status_filter:
        devices = devices.filter(status=status_filter)
    
    # Pagination
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 20))
    
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


@login_required
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_remote_command(request, device_uuid):
    """Send remote command to IoT device"""
    try:
        device = get_object_or_404(Device, uuid=device_uuid)
        
        # Check permissions
        if not request.user.is_staff and device.owner != request.user:
            return Response({'error': 'Permission denied'}, status=403)
        
        command_data = json.loads(request.body)
        command_type = command_data.get('command')
        parameters = command_data.get('parameters', {})
        priority = command_data.get('priority', 'NORMAL')
        
        if not command_type:
            return Response({'error': 'Command type required'}, status=400)
        
        # Validate command type
        allowed_commands = [
            'RESTART', 'UPDATE_FIRMWARE', 'CHANGE_CONFIG', 'DIAGNOSTIC',
            'SHUTDOWN', 'FACTORY_RESET', 'CUSTOM_SCRIPT'
        ]
        
        if command_type not in allowed_commands:
            return Response({'error': 'Invalid command type'}, status=400)
        
        # Create command record
        command_record = DeviceCommand.objects.create(
            device=device,
            command_type=command_type,
            command_parameters=json.dumps(parameters),
            issued_by=request.user,
            priority=priority,
            status='PENDING',
            created_at=datetime.now()
        )
        
        # Send command to device
        if device.status == 'ACTIVE':
            try:
                response = send_device_command(device, command_type, parameters)
                command_record.status = 'SENT'
                command_record.response_data = json.dumps(response)
            except Exception as e:
                command_record.status = 'FAILED'
                command_record.error_message = str(e)
        else:
            command_record.status = 'QUEUED'  # Will be sent when device comes online
        
        command_record.save()
        
        return Response({
            'message': 'Command processed',
            'command_id': command_record.id,
            'status': command_record.status
        })
        
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        return Response({'error': f'Command failed: {str(e)}'}, status=500)


@login_required
@api_view(['POST'])
def firmware_update(request, device_uuid):
    """Handle firmware update for device"""
    try:
        device = get_object_or_404(Device, uuid=device_uuid)
        
        # Check permissions
        if not request.user.is_staff and device.owner != request.user:
            return Response({'error': 'Permission denied'}, status=403)
        
        # Get firmware file
        firmware_file = request.FILES.get('firmware')
        firmware_url = request.POST.get('firmware_url')
        target_version = request.POST.get('target_version')
        
        if not any([firmware_file, firmware_url]) or not target_version:
            return Response({'error': 'Firmware source and target version required'}, status=400)
        
        # Save firmware file if uploaded
        if firmware_file:
            firmware_path = default_storage.save(f'firmware/{device.device_type}/{target_version}.bin', firmware_file)
            firmware_url = default_storage.url(firmware_path)
        
        # Create firmware update command
        update_params = {
            'firmware_url': firmware_url,
            'target_version': target_version,
            'current_version': device.firmware_version,
            'checksum': calculate_firmware_checksum(firmware_url)
        }
        
        command_record = DeviceCommand.objects.create(
            device=device,
            command_type='UPDATE_FIRMWARE',
            command_parameters=json.dumps(update_params),
            issued_by=request.user,
            priority='HIGH',
            status='PENDING'
        )
        
        # Send update command to device
        if device.status == 'ACTIVE':
            try:
                response = send_device_command(device, 'UPDATE_FIRMWARE', update_params)
                command_record.status = 'SENT'
                command_record.response_data = json.dumps(response)
            except Exception as e:
                command_record.status = 'FAILED'
                command_record.error_message = str(e)
        
        command_record.save()
        
        return Response({
            'message': 'Firmware update initiated',
            'command_id': command_record.id,
            'status': command_record.status
        })
        
    except Exception as e:
        return Response({'error': f'Firmware update failed: {str(e)}'}, status=500)


@staff_member_required
@api_view(['POST'])
def bulk_device_operation(request):
    """Perform bulk operations on multiple devices"""
    try:
        operation_data = json.loads(request.body)
        device_uuids = operation_data.get('device_uuids', [])
        operation = operation_data.get('operation')
        parameters = operation_data.get('parameters', {})
        
        if not device_uuids or not operation:
            return Response({'error': 'Device UUIDs and operation required'}, status=400)
        
        devices = Device.objects.filter(uuid__in=device_uuids)
        
        if devices.count() != len(device_uuids):
            return Response({'error': 'Some devices not found'}, status=404)
        
        results = []
        
        for device in devices:
            try:
                if operation == 'MASS_CONFIG_UPDATE':
                    # Apply configuration update to device
                    config_data = parameters.get('config', {})
                    response = send_device_command(device, 'CHANGE_CONFIG', config_data)
                    results.append({'device_id': device.device_id, 'status': 'success'})
                    
                elif operation == 'FACTORY_RESET':
                    # Factory reset device
                    response = send_device_command(device, 'FACTORY_RESET', {})
                    device.status = 'FACTORY_RESET'
                    device.save()
                    results.append({'device_id': device.device_id, 'status': 'reset_initiated'})
                    
                elif operation == 'DEACTIVATE':
                    # Deactivate device
                    device.status = 'INACTIVE'
                    device.save()
                    results.append({'device_id': device.device_id, 'status': 'deactivated'})
                    
            except Exception as e:
                results.append({'device_id': device.device_id, 'status': 'failed', 'error': str(e)})
        
        return Response({
            'message': f'Bulk operation {operation} completed',
            'results': results
        })
        
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        return Response({'error': f'Bulk operation failed: {str(e)}'}, status=500)


@csrf_exempt
@api_view(['POST'])
def device_template_import(request):
    """Import device configuration templates"""
    try:
        template_file = request.FILES.get('template_file')
        template_format = request.POST.get('format', 'json')
        
        if not template_file:
            return Response({'error': 'Template file required'}, status=400)
        
        # Read template file
        template_data = template_file.read()
        
        if template_format == 'binary':
            # Handle binary template format
            try:
                template_config = pickle.loads(template_data)
            except:
                return Response({'error': 'Invalid binary template format'}, status=400)
        else:
            # Handle JSON format
            try:
                template_config = json.loads(template_data.decode('utf-8'))
            except:
                return Response({'error': 'Invalid JSON template format'}, status=400)
        
        # Validate template structure
        required_fields = ['template_name', 'device_type', 'configuration']
        if not all(field in template_config for field in required_fields):
            return Response({'error': 'Invalid template structure'}, status=400)
        
        # Create template record
        template = DeviceTemplate.objects.create(
            name=template_config['template_name'],
            device_type=template_config['device_type'],
            configuration=json.dumps(template_config['configuration']),
            created_by=request.user if request.user.is_authenticated else None,
            is_active=True
        )
        
        return Response({
            'message': 'Template imported successfully',
            'template_id': template.id,
            'template_name': template.name
        })
        
    except Exception as e:
        return Response({'error': f'Template import failed: {str(e)}'}, status=500)


@login_required
@api_view(['POST'])
def execute_device_script(request, device_uuid):
    """Execute custom script on IoT device"""
    try:
        device = get_object_or_404(Device, uuid=device_uuid)
        
        # Check permissions
        if not request.user.is_staff:
            return Response({'error': 'Admin permissions required'}, status=403)
        
        script_data = json.loads(request.body)
        script_content = script_data.get('script')
        script_type = script_data.get('script_type', 'shell')
        parameters = script_data.get('parameters', {})
        
        if not script_content:
            return Response({'error': 'Script content required'}, status=400)
        
        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh' if script_type == 'shell' else '.py') as script_file:
            script_file.write(script_content)
            script_path = script_file.name
        
        try:
            # Execute script on device (via SSH or device agent)
            if script_type == 'shell':
                command = ['ssh', f'root@{device.ip_address}', f'bash < {script_path}']
            else:
                command = ['ssh', f'root@{device.ip_address}', f'python3 < {script_path}']
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            # Log script execution
            command_record = DeviceCommand.objects.create(
                device=device,
                command_type='CUSTOM_SCRIPT',
                command_parameters=json.dumps({
                    'script_type': script_type,
                    'script_content': script_content,
                    'parameters': parameters
                }),
                issued_by=request.user,
                status='COMPLETED' if result.returncode == 0 else 'FAILED',
                response_data=json.dumps({
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'return_code': result.returncode
                })
            )
            
            return Response({
                'message': 'Script executed successfully',
                'command_id': command_record.id,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            })
            
        finally:
            # Clean up temporary file
            os.unlink(script_path)
            
    except subprocess.TimeoutExpired:
        return Response({'error': 'Script execution timeout'}, status=408)
    except json.JSONDecodeError:
        return Response({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        return Response({'error': f'Script execution failed: {str(e)}'}, status=500)


@login_required
def device_dashboard(request):
    """Main device management dashboard"""
    user = request.user
    
    # Get device statistics
    if user.is_staff:
        total_devices = Device.objects.count()
        active_devices = Device.objects.filter(status='ACTIVE').count()
        recent_data = DeviceData.objects.filter(
            timestamp__gte=datetime.now() - timedelta(hours=24)
        ).count()
    else:
        total_devices = Device.objects.filter(owner=user).count()
        active_devices = Device.objects.filter(owner=user, status='ACTIVE').count()
        recent_data = DeviceData.objects.filter(
            device__owner=user,
            timestamp__gte=datetime.now() - timedelta(hours=24)
        ).count()
    
    context = {
        'total_devices': total_devices,
        'active_devices': active_devices,
        'recent_data_points': recent_data,
        'pending_commands': DeviceCommand.objects.filter(status='PENDING').count()
    }
    
    return render(request, 'device_dashboard.html', context)


def process_device_alerts(device, sensor_data):
    """Process device alerts and notifications"""
    # Check for critical sensor values
    for sensor, value in sensor_data.items():
        if sensor == 'temperature' and value > 80:
            # Send alert for high temperature
            pass
        elif sensor == 'battery_level' and value < 10:
            # Send low battery alert
            pass
        elif sensor == 'error_code' and value != 0:
            # Send error alert
            pass


def calculate_firmware_checksum(firmware_url):
    """Calculate checksum for firmware file"""
    try:
        response = requests.get(firmware_url)
        return hashlib.sha256(response.content).hexdigest()
    except:
        return None 