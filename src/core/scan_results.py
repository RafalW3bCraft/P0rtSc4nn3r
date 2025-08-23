"""
Scan Results Management for P0rt$c4nn3r
Handle storage, display, and export of scan results
"""

import json
import csv
import time
from datetime import datetime

class ScanResults:
    """Manage scan results and history"""
    
    def __init__(self):
        self.scan_history = []
        
    def add_scan_result(self, target, results, scan_type):
        """Add scan result to history"""
        scan_data = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'results': results,
            'total_open_ports': len(results)
        }
        self.scan_history.append(scan_data)
        
    def display_history(self):
        """Display scan history"""
        if not self.scan_history:
            print("\n[i] No scan history available.")
            return
            
        print(f"\n╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      SCAN HISTORY                           ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")
        
        for i, scan in enumerate(self.scan_history[-10:], 1):  # Show last 10 scans
            timestamp = datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n[{i}] {scan['scan_type']} - {scan['target']}")
            print(f"    Time: {timestamp}")
            print(f"    Open Ports: {scan['total_open_ports']}")
            
            if scan['results']:
                ports_preview = [str(result['port']) for result in scan['results'][:5]]
                if len(scan['results']) > 5:
                    ports_preview.append("...")
                print(f"    Ports: {', '.join(ports_preview)}")
                
        input(f"\nPress Enter to continue...")
        
    def export_json(self, filename):
        """Export results to JSON format"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
            return True
        except Exception as e:
            print(f"[✗] Error exporting JSON: {e}")
            return False
            
    def export_csv(self, filename):
        """Export results to CSV format"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Target', 'Scan Type', 'Port', 'Service', 'Status'])
                
                for scan in self.scan_history:
                    for result in scan['results']:
                        writer.writerow([
                            scan['timestamp'],
                            scan['target'],
                            scan['scan_type'],
                            result['port'],
                            result['service'],
                            result['status']
                        ])
            return True
        except Exception as e:
            print(f"[✗] Error exporting CSV: {e}")
            return False
            
    def export_txt(self, filename):
        """Export results to text format"""
        try:
            with open(filename, 'w') as f:
                f.write("P0rt$c4nn3r Scan Results\n")
                f.write("Created by RafalW3bCraft\n")
                f.write("=" * 50 + "\n\n")
                
                for scan in self.scan_history:
                    timestamp = datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"Scan: {scan['scan_type']}\n")
                    f.write(f"Target: {scan['target']}\n")
                    f.write(f"Time: {timestamp}\n")
                    f.write(f"Open Ports Found: {scan['total_open_ports']}\n")
                    f.write("-" * 30 + "\n")
                    
                    if scan['results']:
                        f.write(f"{'PORT':<10}{'SERVICE':<20}{'STATUS'}\n")
                        f.write("-" * 40 + "\n")
                        for result in scan['results']:
                            f.write(f"{result['port']:<10}{result['service']:<20}{result['status']}\n")
                    f.write("\n" + "=" * 50 + "\n\n")
                    
            return True
        except Exception as e:
            print(f"[✗] Error exporting TXT: {e}")
            return False
            
    def clear_history(self):
        """Clear all scan history"""
        self.scan_history = []
