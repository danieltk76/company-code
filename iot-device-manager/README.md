# IoT Device Management Platform

Enterprise-grade IoT device lifecycle management system built with Django. Provides comprehensive device registration, data ingestion, remote management, and monitoring capabilities.

## Features

### Device Lifecycle Management
- Automated device registration and provisioning
- Real-time device status monitoring
- Firmware update management
- Remote device configuration
- Device health diagnostics

### Data Processing
- High-throughput sensor data ingestion
- Real-time data processing pipelines  
- Time-series data storage with InfluxDB
- Custom data validation and transformation
- Alert and notification system

### Remote Operations
- Remote command execution
- Custom script deployment
- Bulk device operations
- Firmware over-the-air (FOTA) updates
- Factory reset capabilities

### Security & Access Control
- API key-based device authentication
- Role-based user permissions
- Audit logging for all operations
- Encrypted communication channels
- Device signature validation

## Architecture

The platform is built using a microservices architecture:

- **Django REST Framework**: Core API services
- **Celery**: Asynchronous task processing
- **Redis**: Caching and message broker
- **PostgreSQL**: Relational data storage
- **InfluxDB**: Time-series sensor data
- **MQTT**: Device communication protocol

## Quick Start

### Prerequisites
- Python 3.9+
- PostgreSQL 13+
- Redis 6+
- InfluxDB 2.0+

### Installation

```bash
git clone https://github.com/enterprise/iot-device-manager.git
cd iot-device-manager
```

### Setup Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Database Setup

```bash
python manage.py migrate
python manage.py createsuperuser
```

### Environment Configuration

Create `.env` file:

```env
SECRET_KEY=your-django-secret-key
DEBUG=False
DATABASE_URL=postgres://user:password@localhost:5432/iot_platform
REDIS_URL=redis://localhost:6379/0
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=your-influxdb-token
INFLUXDB_ORG=your-organization
INFLUXDB_BUCKET=device_data

# Device communication
MQTT_BROKER_HOST=localhost
MQTT_BROKER_PORT=1883
MQTT_USERNAME=mqtt_user
MQTT_PASSWORD=mqtt_password

# External services
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AWS_STORAGE_BUCKET_NAME=iot-firmware-storage
```

### Start Services

```bash
# Start Django development server
python manage.py runserver

# Start Celery worker (in separate terminal)
celery -A iot_platform worker -l info

# Start Celery beat scheduler (in separate terminal)  
celery -A iot_platform beat -l info
```

## API Documentation

### Device Registration

```http
POST /api/v1/devices/register
Content-Type: application/json

{
  "device_id": "sensor-001",
  "device_type": "temperature_sensor", 
  "firmware_version": "1.2.3",
  "hardware_info": {
    "model": "TempSense Pro",
    "serial": "TS2024001"
  },
  "device_key": "device-secret-key"
}
```

### Data Ingestion

```http
POST /api/v1/devices/data
X-API-Key: device-api-key
Content-Type: application/json

{
  "sensor_data": {
    "temperature": 23.5,
    "humidity": 65.2,
    "pressure": 1013.25
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "device_status": {
    "battery_level": 87,
    "signal_strength": -45,
    "memory_usage": 34
  }
}
```

### Remote Commands

```http
POST /api/v1/devices/{device_uuid}/commands
Authorization: Bearer your-jwt-token
Content-Type: application/json

{
  "command": "UPDATE_FIRMWARE",
  "parameters": {
    "firmware_url": "https://storage.example.com/firmware-v1.3.0.bin",
    "target_version": "1.3.0"
  },
  "priority": "HIGH"
}
```

## Device Types Supported

### Environmental Sensors
- Temperature/Humidity sensors
- Air quality monitors
- Weather stations
- Soil moisture sensors

### Industrial IoT
- Machine monitoring sensors
- Vibration analyzers
- Power meters
- Flow sensors

### Smart City
- Traffic counters
- Noise level monitors
- Parking sensors
- Street lighting controllers

### Agricultural IoT
- Crop monitoring systems
- Irrigation controllers
- Livestock trackers
- Greenhouse automation

## Data Processing Pipeline

1. **Ingestion**: Devices send data via REST API or MQTT
2. **Validation**: Data validation and sanitization
3. **Processing**: Real-time processing with Celery workers
4. **Storage**: Time-series data stored in InfluxDB
5. **Analysis**: Automated analysis and alert generation
6. **Visualization**: Dashboard and reporting system

## Remote Management

### Supported Commands
- **RESTART**: Reboot device
- **UPDATE_FIRMWARE**: Over-the-air firmware updates
- **CHANGE_CONFIG**: Update device configuration
- **DIAGNOSTIC**: Run diagnostic tests
- **SHUTDOWN**: Safe device shutdown
- **FACTORY_RESET**: Reset to factory defaults
- **CUSTOM_SCRIPT**: Execute custom scripts

### Bulk Operations
- Mass configuration updates
- Fleet-wide firmware deployment
- Batch device provisioning
- Coordinated maintenance operations

## Monitoring & Alerts

### Device Health Monitoring
- Real-time connectivity status
- Battery level tracking
- Performance metrics
- Error rate monitoring

### Alert Types
- Device offline alerts
- Sensor threshold violations
- Battery low warnings
- Firmware update failures
- Security incident notifications

## Security Features

### Authentication & Authorization
- Multi-factor authentication for users
- API key management for devices
- Role-based access control
- Session management

### Data Security
- Encrypted data transmission
- Secure firmware distribution
- Device identity verification
- Audit trail logging

### Network Security
- VPN support for device communication
- Certificate-based device authentication
- Network segmentation recommendations
- Intrusion detection integration

## Deployment

### Docker Deployment

```bash
# Build containers
docker-compose build

# Start services
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate
```

### Production Deployment

```bash
# Install production server
pip install gunicorn

# Start with Gunicorn
gunicorn iot_platform.wsgi:application --bind 0.0.0.0:8000

# Use nginx as reverse proxy
# Configure SSL certificates
# Set up monitoring with Prometheus/Grafana
```

## Testing

```bash
# Run unit tests
python manage.py test

# Run with coverage
pip install coverage
coverage run --source='.' manage.py test
coverage report
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For technical support:
- Check the documentation wiki
- Submit issues on GitHub
- Contact the development team

## License

Copyright (c) 2024 Enterprise IoT Solutions. All rights reserved. 