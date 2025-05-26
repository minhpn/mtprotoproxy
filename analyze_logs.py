#!/usr/bin/env python3
import re
import json
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse

class MTProxyLogAnalyzer:
    def __init__(self):
        self.user_connections = defaultdict(list)
        self.ip_to_user = {}
        self.connection_patterns = defaultdict(lambda: defaultdict(int))
        
    def get_docker_logs(self, container_name="mtprotoproxy", lines=1000):
        """Get logs from Docker container"""
        try:
            cmd = f"docker logs --tail {lines} {container_name}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.stdout.split('\n')
        except Exception as e:
            print(f"Error getting Docker logs: {e}")
            return []
    
    def get_docker_compose_logs(self, service_name="mtprotoproxy", lines=1000):
        """Get logs from Docker Compose service"""
        try:
            cmd = f"docker-compose logs --tail {lines} {service_name}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.stdout.split('\n')
        except Exception as e:
            print(f"Error getting Docker Compose logs: {e}")
            return []
    
    def parse_logs(self, log_lines):
        """Parse MTProxy logs to extract connection information"""
        connection_patterns = [
            # Common MTProxy log patterns
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+).*?user.*?([a-f0-9]{32})',
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+).*?secret.*?([a-f0-9]{32})',
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+).*?connected.*?([a-f0-9]{32})',
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(\d+\.\d+\.\d+\.\d+).*?auth.*?([a-f0-9]{32})',
        ]
        
        # Load user secrets from config
        user_secrets = self.load_user_secrets()
        secret_to_user = {secret: user for user, secret in user_secrets.items()}
        
        for line in log_lines:
            if not line.strip():
                continue
                
            for pattern in connection_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    timestamp_str, ip, secret = match.groups()
                    
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    except:
                        timestamp = datetime.now()
                    
                    # Map secret to username
                    username = secret_to_user.get(secret, f"unknown_{secret[:8]}")
                    
                    connection_info = {
                        'timestamp': timestamp,
                        'ip': ip,
                        'secret': secret,
                        'username': username,
                        'raw_log': line.strip()
                    }
                    
                    self.user_connections[username].append(connection_info)
                    self.ip_to_user[ip] = username
                    
                    # Track patterns
                    hour = timestamp.hour
                    self.connection_patterns[username][hour] += 1
                    
                    break
    
    def load_user_secrets(self):
        """Load user secrets from config.py"""
        try:
            with open('config.py', 'r') as f:
                content = f.read()
            
            # Extract USERS section
            users_pattern = r'USERS = \{([^}]*)\}'
            match = re.search(users_pattern, content, re.DOTALL)
            
            if not match:
                return {}
            
            users_content = match.group(1)
            
            # Parse user entries
            user_pattern = r'"([^"]+)":\s*"([^"]+)"'
            users = re.findall(user_pattern, users_content)
            
            return dict(users)
        except Exception as e:
            print(f"Error loading user secrets: {e}")
            return {}
    
    def analyze_sharing_behavior(self):
        """Analyze potential account sharing"""
        sharing_analysis = {}
        
        for username, connections in self.user_connections.items():
            if len(connections) < 2:
                continue
            
            # Get unique IPs for this user
            user_ips = set(conn['ip'] for conn in connections)
            
            # Analyze time patterns
            connection_times = [conn['timestamp'] for conn in connections]
            connection_times.sort()
            
            # Check for simultaneous connections from different IPs
            simultaneous_ips = []
            for i, conn1 in enumerate(connections):
                for conn2 in connections[i+1:]:
                    time_diff = abs((conn1['timestamp'] - conn2['timestamp']).total_seconds())
                    if time_diff < 300 and conn1['ip'] != conn2['ip']:  # Within 5 minutes
                        simultaneous_ips.append((conn1['ip'], conn2['ip'], time_diff))
            
            # Calculate connection frequency
            if len(connection_times) > 1:
                total_time = (connection_times[-1] - connection_times[0]).total_seconds()
                avg_interval = total_time / len(connection_times) if total_time > 0 else 0
            else:
                avg_interval = 0
            
            sharing_analysis[username] = {
                'total_connections': len(connections),
                'unique_ips': len(user_ips),
                'ips': list(user_ips),
                'simultaneous_different_ips': len(simultaneous_ips),
                'avg_connection_interval': avg_interval,
                'suspicious_score': self.calculate_suspicious_score(
                    len(user_ips), len(simultaneous_ips), len(connections)
                ),
                'first_seen': min(connection_times) if connection_times else None,
                'last_seen': max(connection_times) if connection_times else None
            }
        
        return sharing_analysis
    
    def calculate_suspicious_score(self, unique_ips, simultaneous_ips, total_connections):
        """Calculate a suspicious score for account sharing"""
        score = 0
        
        # Multiple IPs increase suspicion
        if unique_ips > 1:
            score += unique_ips * 10
        
        # Simultaneous connections from different IPs are very suspicious
        score += simultaneous_ips * 50
        
        # High frequency connections might indicate sharing
        if total_connections > 20:
            score += (total_connections - 20) * 2
        
        return min(score, 100)  # Cap at 100
    
    def print_analysis(self, sharing_analysis):
        """Print detailed analysis"""
        print(f"\n📊 MTProxy Log Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        if not sharing_analysis:
            print("No connection data found in logs.")
            return
        
        # Sort by suspicious score
        sorted_users = sorted(sharing_analysis.items(), 
                            key=lambda x: x[1]['suspicious_score'], reverse=True)
        
        for username, data in sorted_users:
            print(f"\n👤 User: {username}")
            print(f"   📈 Total connections: {data['total_connections']}")
            print(f"   🌐 Unique IPs: {data['unique_ips']}")
            print(f"   ⚠️  Suspicious score: {data['suspicious_score']}/100")
            
            if data['suspicious_score'] > 30:
                print(f"   🚨 HIGH RISK - Potential account sharing!")
            elif data['suspicious_score'] > 10:
                print(f"   ⚠️  MEDIUM RISK - Monitor closely")
            else:
                print(f"   ✅ LOW RISK - Normal usage")
            
            if data['unique_ips'] > 1:
                print(f"   📍 IPs used: {', '.join(data['ips'][:5])}")
                if len(data['ips']) > 5:
                    print(f"      ... and {len(data['ips']) - 5} more")
            
            if data['simultaneous_different_ips'] > 0:
                print(f"   🔄 Simultaneous connections from different IPs: {data['simultaneous_different_ips']}")
            
            if data['first_seen'] and data['last_seen']:
                print(f"   🕐 First seen: {data['first_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   🕐 Last seen: {data['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            print("-" * 60)
        
        # Summary statistics
        total_users = len(sharing_analysis)
        high_risk = sum(1 for data in sharing_analysis.values() if data['suspicious_score'] > 30)
        medium_risk = sum(1 for data in sharing_analysis.values() if 10 < data['suspicious_score'] <= 30)
        
        print(f"\n📋 Summary:")
        print(f"   Total users analyzed: {total_users}")
        print(f"   🚨 High risk users: {high_risk}")
        print(f"   ⚠️  Medium risk users: {medium_risk}")
        print(f"   ✅ Low risk users: {total_users - high_risk - medium_risk}")
    
    def export_analysis(self, sharing_analysis, filename=None):
        """Export analysis to JSON"""
        if not filename:
            filename = f"mtproxy_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert datetime objects to strings for JSON serialization
        export_data = {}
        for username, data in sharing_analysis.items():
            export_data[username] = data.copy()
            if data['first_seen']:
                export_data[username]['first_seen'] = data['first_seen'].isoformat()
            if data['last_seen']:
                export_data[username]['last_seen'] = data['last_seen'].isoformat()
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"📄 Analysis exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Analyze MTProxy logs for user behavior')
    parser.add_argument('--lines', '-l', type=int, default=1000,
                       help='Number of log lines to analyze (default: 1000)')
    parser.add_argument('--container', '-c', type=str, default='mtprotoproxy',
                       help='Docker container name (default: mtprotoproxy)')
    parser.add_argument('--compose', action='store_true',
                       help='Use docker-compose logs instead of docker logs')
    parser.add_argument('--export', '-e', type=str, nargs='?', const='auto',
                       help='Export analysis to JSON file')
    
    args = parser.parse_args()
    
    analyzer = MTProxyLogAnalyzer()
    
    # Get logs
    if args.compose:
        log_lines = analyzer.get_docker_compose_logs(args.container, args.lines)
    else:
        log_lines = analyzer.get_docker_logs(args.container, args.lines)
    
    if not log_lines:
        print("No logs found. Make sure the container is running and accessible.")
        return
    
    # Parse and analyze
    analyzer.parse_logs(log_lines)
    sharing_analysis = analyzer.analyze_sharing_behavior()
    
    # Print results
    analyzer.print_analysis(sharing_analysis)
    
    # Export if requested
    if args.export:
        filename = None if args.export == 'auto' else args.export
        analyzer.export_analysis(sharing_analysis, filename)

if __name__ == "__main__":
    main() 