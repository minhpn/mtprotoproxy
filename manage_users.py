#!/usr/bin/env python3
import os
import re
import secrets
import argparse
from datetime import datetime

CONFIG_FILE = "config.py"

def generate_secret():
    """Generate a 32-character hex secret"""
    return secrets.token_hex(16)

def read_config():
    """Read and parse the config file"""
    with open(CONFIG_FILE, 'r') as f:
        content = f.read()
    return content

def write_config(content):
    """Write content back to config file"""
    with open(CONFIG_FILE, 'w') as f:
        f.write(content)

def add_user(username):
    """Add a new user to the config"""
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        print(f"Error: Username '{username}' contains invalid characters. Use only letters, numbers, underscore, and dash.")
        return False
    
    content = read_config()
    
    # Check if user already exists
    if f'"{username}":' in content:
        print(f"Error: User '{username}' already exists!")
        return False
    
    # Generate new secret
    secret = generate_secret()
    
    # Find the USERS section and add the new user
    users_pattern = r'(USERS = \{[^}]*)'
    match = re.search(users_pattern, content, re.DOTALL)
    
    if not match:
        print("Error: Could not find USERS section in config.py")
        return False
    
    users_section = match.group(1)
    
    # Add new user entry
    new_entry = f'    "{username}": "{secret}",'
    
    # Insert before the closing brace
    updated_content = content.replace(users_section, users_section + '\n' + new_entry)
    
    # Write back to file
    write_config(updated_content)
    
    print(f"✅ User '{username}' added successfully!")
    print(f"Secret: {secret}")
    print(f"Connection string: tg://{username}@your-server-ip:443?secret={secret}")
    
    return True

def list_users():
    """List all users in the config"""
    content = read_config()
    
    # Extract USERS section
    users_pattern = r'USERS = \{([^}]*)\}'
    match = re.search(users_pattern, content, re.DOTALL)
    
    if not match:
        print("Error: Could not find USERS section in config.py")
        return
    
    users_content = match.group(1)
    
    # Parse user entries
    user_pattern = r'"([^"]+)":\s*"([^"]+)"'
    users = re.findall(user_pattern, users_content)
    
    if not users:
        print("No users found in config.")
        return
    
    print(f"\n📋 Current users ({len(users)} total):")
    print("-" * 60)
    for username, secret in users:
        print(f"User: {username}")
        print(f"Secret: {secret}")
        print(f"Connection: tg://{username}@your-server-ip:443?secret={secret}")
        print("-" * 60)

def remove_user(username):
    """Remove a user from the config"""
    content = read_config()
    
    # Check if user exists
    user_pattern = f'\\s*"{re.escape(username)}":\\s*"[^"]+",?\\n?'
    
    if not re.search(user_pattern, content):
        print(f"Error: User '{username}' not found!")
        return False
    
    # Remove the user entry
    updated_content = re.sub(user_pattern, '', content)
    
    # Clean up any double newlines
    updated_content = re.sub(r'\n\n+', '\n', updated_content)
    
    write_config(updated_content)
    print(f"✅ User '{username}' removed successfully!")
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Manage MTProto proxy users')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add user command
    add_parser = subparsers.add_parser('add', help='Add a new user')
    add_parser.add_argument('username', help='Username to add')
    
    # List users command
    list_parser = subparsers.add_parser('list', help='List all users')
    
    # Remove user command
    remove_parser = subparsers.add_parser('remove', help='Remove a user')
    remove_parser.add_argument('username', help='Username to remove')
    
    args = parser.parse_args()
    
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: {CONFIG_FILE} not found!")
        return
    
    if args.command == 'add':
        add_user(args.username)
    elif args.command == 'list':
        list_users()
    elif args.command == 'remove':
        remove_user(args.username)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 