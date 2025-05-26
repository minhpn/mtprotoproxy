#!/usr/bin/env python3
import subprocess
import re
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse

class MTProxyMonitor:
    def __init__(self):
        self.connection_history = defaultdict(list)
        self.user_ips = defaultdict(set)
        self.suspicious_activity = []
        
    def get_active_connections(self):
        """Get active connections on port 443"""
        try:
            # Get connections on port 443
            result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True)
            connections = []
            
            for line in result.stdout.split('\n'):
                if ':443' in line and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[3]
                        foreign_addr = parts[4]
                        foreign_ip = foreign_addr.split(':')[0]
                        connections.append({
                            'local': local_addr,
                            'remote': foreign_addr,
                            'remote_ip': foreign_ip,
                            'timestamp': datetime.now()
                        })
            
            return connections
        except Exception as e:
            print(f"Error getting connections: {e}")
            return []
    
    def get_process_connections(self):
        """Get connections specifically for the MTProxy process"""
        try:
            # Find MTProxy process
            ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            mtproxy_pid = None
            
            for line in ps_result.stdout.split('\n'):
                if 'mtprotoproxy.py' in line or 'python3' in line and 'mtprotoproxy' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        mtproxy_pid = parts[1]
                        break
            
            if not mtproxy_pid:
                return []
            
            # Get connections for this process
            lsof_result = subprocess.run(['lsof', '-p', mtproxy_pid, '-i', 'TCP:443'], 
                                       capture_output=True, text=True)
            
            connections = []
            for line in lsof_result.stdout.split('\n')[1:]:  # Skip header
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        connection_info = parts[8]  # Format: ip:port->ip:port
                        if '->' in connection_info:
                            local, remote = connection_info.split('->')
                            remote_ip = remote.split(':')[0]
                            connections.append({
                                'local': local,
                                'remote': remote,
                                'remote_ip': remote_ip,
                                'timestamp': datetime.now()
                            })
            
            return connections
        except Exception as e:
            print(f"Error getting process connections: {e}")
            return []
    
    def analyze_user_behavior(self, connections):
        """Analyze connections for suspicious behavior"""
        current_time = datetime.now()
        
        # Group connections by IP
        ip_connections = defaultdict(int)
        for conn in connections:
            ip_connections[conn['remote_ip']] += 1
            self.user_ips[conn['remote_ip']].add(current_time.strftime('%Y-%m-%d %H:%M'))
        
        # Detect suspicious activity
        for ip, count in ip_connections.items():
            # Multiple simultaneous connections from same IP
            if count > 3:
                self.suspicious_activity.append({
                    'type': 'multiple_connections',
                    'ip': ip,
                    'count': count,
                    'timestamp': current_time
                })
            
            # Check for connections from multiple locations (simplified)
            unique_times = len(self.user_ips[ip])
            if unique_times > 10:  # More than 10 different connection times
                self.suspicious_activity.append({
                    'type': 'frequent_connections',
                    'ip': ip,
                    'connection_times': unique_times,
                    'timestamp': current_time
                })
    
    def get_connection_stats(self):
        """Get current connection statistics"""
        connections = self.get_active_connections()
        process_connections = self.get_process_connections()
        
        # Use process connections if available, otherwise fall back to netstat
        active_connections = process_connections if process_connections else connections
        
        self.analyze_user_behavior(active_connections)
        
        # Count unique IPs
        unique_ips = set(conn['remote_ip'] for conn in active_connections)
        
        # Group by IP
        ip_counts = Counter(conn['remote_ip'] for conn in active_connections)
        
        return {
            'total_connections': len(active_connections),
            'unique_users': len(unique_ips),
            'connections_by_ip': dict(ip_counts),
            'active_connections': active_connections,
            'timestamp': datetime.now()
        }
    
    def print_stats(self, stats):
        """Print formatted statistics"""
        print(f"\n🔍 MTProxy Monitor - {stats['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        print(f"📊 Total active connections: {stats['total_connections']}")
        print(f"👥 Unique users (IPs): {stats['unique_users']}")
        
        if stats['connections_by_ip']:
            print(f"\n📋 Connections by IP:")
            for ip, count in sorted(stats['connections_by_ip'].items(), key=lambda x: x[1], reverse=True):
                status = "⚠️ " if count > 2 else "✅ "
                print(f"  {status}{ip}: {count} connection(s)")
        
        # Show suspicious activity
        recent_suspicious = [s for s in self.suspicious_activity 
                           if s['timestamp'] > datetime.now() - timedelta(minutes=5)]
        
        if recent_suspicious:
            print(f"\n⚠️  Suspicious Activity (last 5 minutes):")
            for activity in recent_suspicious[-5:]:  # Show last 5
                if activity['type'] == 'multiple_connections':
                    print(f"  🚨 {activity['ip']}: {activity['count']} simultaneous connections")
                elif activity['type'] == 'frequent_connections':
                    print(f"  🔄 {activity['ip']}: {activity['connection_times']} different connection times")
    
    def monitor_continuous(self, interval=30):
        """Monitor continuously with specified interval"""
        print(f"🚀 Starting continuous monitoring (interval: {interval}s)")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                stats = self.get_connection_stats()
                self.print_stats(stats)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped")
    
    def export_logs(self, filename=None):
        """Export monitoring data to JSON"""
        if not filename:
            filename = f"mtproxy_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        data = {
            'user_ips': {ip: list(times) for ip, times in self.user_ips.items()},
            'suspicious_activity': self.suspicious_activity,
            'export_time': datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"📄 Monitoring data exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Monitor MTProxy connections')
    parser.add_argument('--continuous', '-c', action='store_true', 
                       help='Run continuous monitoring')
    parser.add_argument('--interval', '-i', type=int, default=30,
                       help='Monitoring interval in seconds (default: 30)')
    parser.add_argument('--export', '-e', type=str, nargs='?', const='auto',
                       help='Export monitoring data to JSON file')
    
    args = parser.parse_args()
    
    monitor = MTProxyMonitor()
    
    if args.continuous:
        monitor.monitor_continuous(args.interval)
    elif args.export:
        filename = None if args.export == 'auto' else args.export
        monitor.export_logs(filename)
    else:
        # Single check
        stats = monitor.get_connection_stats()
        monitor.print_stats(stats)

if __name__ == "__main__":
    main() 