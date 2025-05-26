#!/bin/bash

# Fix permissions for mounted files
chmod 666 /home/tgproxy/config.py
chmod +x /home/tgproxy/manage_users.py
chmod +x /home/tgproxy/monitor.py
chmod +x /home/tgproxy/analyze_logs.py

# Start the main application
exec python3 mtprotoproxy.py 