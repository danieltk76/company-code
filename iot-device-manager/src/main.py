#!/usr/bin/env python3
"""
IoT Device Management Platform
Enterprise-grade IoT device lifecycle management system
"""

import os
import sys
import django
from django.core.wsgi import get_wsgi_application

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iot_platform.settings')
    
    from django.core.management import execute_from_command_line
    
    execute_from_command_line(sys.argv) 