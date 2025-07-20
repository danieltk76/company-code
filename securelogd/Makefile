# SecureLogD - Enterprise Logging Daemon
# Makefile for building the daemon

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -O2
LDFLAGS = -lpthread

# Debug build flags
DEBUG_CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -g -DDEBUG -fsanitize=address
DEBUG_LDFLAGS = -lpthread -fsanitize=address

# Directories
SRCDIR = src
BUILDDIR = build
INSTALLDIR = /usr/local/sbin

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)
TARGET = securelogd

# Default target
all: $(TARGET)

# Build release version
$(TARGET): $(BUILDDIR) $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Build debug version
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: LDFLAGS = $(DEBUG_LDFLAGS)
debug: $(TARGET)

# Create build directory
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Compile object files
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install the daemon
install: $(TARGET)
	sudo cp $(TARGET) $(INSTALLDIR)/
	sudo chmod 755 $(INSTALLDIR)/$(TARGET)
	sudo mkdir -p /etc/securelogd
	sudo mkdir -p /var/log/securelogd
	sudo chown nobody:nobody /var/log/securelogd
	@echo "Installation complete"

# Uninstall the daemon
uninstall:
	sudo rm -f $(INSTALLDIR)/$(TARGET)
	sudo rm -rf /etc/securelogd
	sudo rm -rf /var/log/securelogd
	sudo rm -f /var/run/securelogd.pid
	@echo "Uninstallation complete"

# Create systemd service file
service:
	@echo "[Unit]" > securelogd.service
	@echo "Description=SecureLogD Enterprise Logging Daemon" >> securelogd.service
	@echo "After=network.target" >> securelogd.service
	@echo "" >> securelogd.service
	@echo "[Service]" >> securelogd.service
	@echo "Type=forking" >> securelogd.service
	@echo "ExecStart=$(INSTALLDIR)/$(TARGET)" >> securelogd.service
	@echo "ExecReload=/bin/kill -HUP \$$MAINPID" >> securelogd.service
	@echo "PIDFile=/var/run/securelogd.pid" >> securelogd.service
	@echo "User=nobody" >> securelogd.service
	@echo "Group=nobody" >> securelogd.service
	@echo "" >> securelogd.service
	@echo "[Install]" >> securelogd.service
	@echo "WantedBy=multi-user.target" >> securelogd.service
	@echo "Systemd service file created: securelogd.service"

# Clean build files
clean:
	rm -rf $(BUILDDIR)
	rm -f $(TARGET)
	rm -f securelogd.service
	@echo "Clean complete"

# Static analysis with cppcheck
analyze:
	cppcheck --enable=all --std=c99 $(SRCDIR)/

# Memory leak detection with valgrind
memcheck: debug
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) -d

# Run tests
test: $(TARGET)
	@echo "Running basic functionality tests..."
	./$(TARGET) -h
	@echo "Test complete"

# Create distribution package
dist: clean
	tar -czf securelogd-1.0.tar.gz --exclude='.git' --exclude='*.tar.gz' .
	@echo "Distribution package created: securelogd-1.0.tar.gz"

.PHONY: all debug install uninstall service clean analyze memcheck test dist 