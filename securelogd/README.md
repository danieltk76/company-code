# SecureLogD - Enterprise Logging Daemon

SecureLogD is a high-performance, multi-threaded network logging daemon designed for enterprise environments. It provides centralized log collection from multiple sources with authentication, access control, and automatic log rotation.

## Features

### Core Functionality
- **High-Performance Networking**: Multi-threaded TCP server supporting up to 100 concurrent connections
- **Authentication System**: User-based authentication with system user integration
- **Access Control**: Host-based access restrictions with wildcard support
- **Log Rotation**: Automatic log rotation based on file size
- **Daemon Mode**: Full daemon implementation with proper privilege dropping

### Enterprise Features
- **Configuration Management**: Flexible configuration file support
- **Real-time Commands**: Remote administration via network commands
- **System Integration**: Systemd service integration
- **Security**: Privilege dropping, PID file management, signal handling
- **Monitoring**: Connection tracking and status reporting

### Performance & Reliability
- **Memory Management**: Efficient buffer management and client tracking
- **Thread Safety**: Mutex-protected shared resources
- **Error Handling**: Comprehensive error handling and logging
- **Resource Cleanup**: Proper cleanup on shutdown and signal handling

## Architecture

### Network Protocol
- **Port**: Default 8514 (configurable)
- **Protocol**: TCP with persistent connections
- **Authentication**: Plain text username/password (AUTH command)
- **Commands**: Status, log rotation, configuration changes

### File Structure
```
/etc/securelogd/
├── securelogd.conf         # Configuration file
/var/log/securelogd/
├── securelogd.log          # Main log file
├── securelogd_*.log        # Rotated log files
/var/run/
├── securelogd.pid          # Process ID file
```

## Installation

### Prerequisites
- GCC compiler with C99 support
- POSIX-compliant system (Linux, Unix)
- pthread library
- Make utility

### Build from Source

```bash
# Clone repository
git clone https://github.com/enterprise/securelogd.git
cd securelogd

# Build release version
make

# Build debug version with sanitizers
make debug

# Install system-wide
sudo make install

# Create systemd service
make service
sudo cp securelogd.service /etc/systemd/system/
sudo systemctl enable securelogd
```

### Development Build

```bash
# Build with debugging symbols
make debug

# Run static analysis
make analyze

# Memory leak detection
make memcheck
```

## Configuration

### Configuration File Format

Create `/etc/securelogd/securelogd.conf`:

```ini
# Basic settings
port = 8514
log_directory = /var/log/securelogd
user = nobody
group = nobody

# Connection settings  
max_connections = 100
log_rotation = 1

# Access control
allowed_host = 192.168.1.0*
allowed_host = 10.0.0.100
allowed_host = 127.0.0.1
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `port` | integer | 8514 | TCP port to listen on |
| `log_directory` | string | /var/log/securelogd | Directory for log files |
| `user` | string | nobody | User to run as after privilege drop |
| `group` | string | nobody | Group to run as |
| `max_connections` | integer | 100 | Maximum concurrent connections |
| `log_rotation` | integer | 1 | Enable automatic log rotation |
| `allowed_host` | string | (none) | Allowed client IP addresses |

## Usage

### Starting the Daemon

```bash
# Start in foreground (debug mode)
./securelogd -d

# Start with custom config
./securelogd -c /path/to/config.conf

# Start as system service
sudo systemctl start securelogd
```

### Client Interaction

```bash
# Connect to daemon
telnet localhost 8514

# Authenticate
AUTH admin securelogd123

# Send log message
This is a test log message

# Execute commands
CMD STATUS
CMD ROTATE
CMD CONFIG log_directory /tmp/logs

# Disconnect
^C
```

### Command Line Options

```bash
Usage: securelogd [-c config_file] [-d] [-h]
  -c: Configuration file path
  -d: Debug mode (don't daemonize)  
  -h: Show help message
```

## Network Protocol

### Authentication
```
Client: AUTH username password
Server: Authentication successful
```

### Log Messages
```
Client: Log message content here
Server: OK
```

### Commands
```
Client: CMD STATUS
Server: Active clients: 3

Client: CMD ROTATE  
Server: Log rotation initiated

Client: CMD CONFIG key value
Server: Configuration updated
```

## System Integration

### Systemd Service

```ini
[Unit]
Description=SecureLogD Enterprise Logging Daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/sbin/securelogd
PIDFile=/var/run/securelogd.pid
User=nobody
Group=nobody

[Install]
WantedBy=multi-user.target
```

### Log Rotation

The daemon automatically rotates logs when they exceed 100MB:
- Original: `securelogd.log`
- Rotated: `securelogd_YYYYMMDD_HHMMSS.log`

### Signal Handling

- `SIGTERM`: Graceful shutdown
- `SIGINT`: Graceful shutdown  
- `SIGPIPE`: Ignored (broken connections)

## Security Considerations

### Access Control
- Host-based access restrictions
- Authentication required for all operations
- Privilege dropping after socket binding

### Network Security
- Plain text protocol (use VPN/tunneling for encryption)
- No built-in SSL/TLS support
- Authentication credentials sent in plain text

### File Permissions
- Log directory: `nobody:nobody` ownership
- Configuration files: Root readable only
- PID file: Standard `/var/run` permissions

## Monitoring

### Log File Analysis
```bash
# Monitor active connections
tail -f /var/log/securelogd/securelogd.log | grep "Client connected"

# Check authentication failures  
grep "Authentication failed" /var/log/securelogd/securelogd.log

# Monitor daemon status
grep "SecureLogD daemon" /var/log/securelogd/securelogd.log
```

### System Monitoring
```bash
# Check daemon status
sudo systemctl status securelogd

# View recent logs
sudo journalctl -u securelogd -f

# Check listening port
sudo netstat -tlnp | grep 8514
```

## Troubleshooting

### Common Issues

1. **Permission Denied on Port Binding**
   - Run as root initially (privileges dropped after binding)
   - Check if port is already in use

2. **Configuration File Not Found**
   - Ensure `/etc/securelogd/securelogd.conf` exists
   - Use `-c` option to specify alternate location

3. **Authentication Failures**
   - Check username/password combination
   - Verify system user exists for non-admin accounts

4. **Connection Refused**
   - Verify daemon is running
   - Check firewall settings
   - Confirm client IP is in allowed_host list

### Debug Mode

```bash
# Run in debug mode for verbose output
./securelogd -d

# Use GDB for debugging
gdb ./securelogd
(gdb) run -d
```

### Memory Analysis

```bash
# Check for memory leaks
make memcheck

# Static code analysis
make analyze
```

## Development

### Code Structure
```
src/
├── main.c              # Main daemon implementation
Makefile                # Build configuration
README.md               # This documentation
```

### Coding Standards
- C99 standard compliance
- POSIX.1-2001 compatibility
- Thread-safe implementations
- Comprehensive error handling

### Testing
```bash
# Basic functionality test
make test

# Memory leak detection  
make memcheck

# Static analysis
make analyze
```

## License

Copyright (c) 2024 Enterprise Systems Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

## Support

For technical support:
- GitHub Issues: [Report Issues](https://github.com/enterprise/securelogd/issues)
- Email: support@enterprise-systems.com
- Documentation: [Wiki](https://github.com/enterprise/securelogd/wiki) 