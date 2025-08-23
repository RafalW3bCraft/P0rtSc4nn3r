"""
Scanner Engine for P0rt$c4nn3r
Multi-threaded port scanning with progress tracking
"""

import socket
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from database.port_database import PortDatabase
from database.enhanced_port_database import EnhancedPortDatabase
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.banner_grabber import BannerGrabber

class ScannerEngine:
    """Main scanning engine with threading support"""
    
    def __init__(self):
        self.port_db = PortDatabase()
        self.enhanced_port_db = EnhancedPortDatabase()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.banner_grabber = BannerGrabber()
        self.results = []
        self.progress = 0
        self.total_ports = 0
        self.start_time = 0
        self.lock = threading.Lock()
        self.enable_enhanced_scanning = True
        self.enable_vulnerability_scanning = True
        
    def validate_target(self, target):
        """Validate target hostname or IP address"""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
            
    def scan_target(self, target, port_range, scan_type="custom", threads=50, timeout=1.0):
        """Main scanning method with enhanced capabilities"""
        try:
            # Resolve target to IP
            ip_address = socket.gethostbyname(target)
            
            # Determine ports to scan based on scan type
            if scan_type == "quick":
                ports_to_scan = self.enhanced_port_db.get_top_ports(1000)
            elif scan_type == "full":
                ports_to_scan = list(range(port_range[0], port_range[1] + 1))
            elif scan_type == "common":
                ports_to_scan = self.enhanced_port_db.get_common_ports()
            else:  # custom
                ports_to_scan = list(range(port_range[0], port_range[1] + 1))
                
            self.total_ports = len(ports_to_scan)
            self.progress = 0
            self.results = []
            self.start_time = time.time()
            
            print(f"\n[i] Scanning {len(ports_to_scan)} ports on {target} ({ip_address})")
            print(f"[i] Using {threads} threads with {timeout}s timeout")
            if self.enable_enhanced_scanning:
                print("[i] Enhanced scanning enabled (banner grabbing + vulnerability detection)")
            
            # Start progress display thread
            progress_thread = threading.Thread(target=self._display_progress, daemon=True)
            progress_thread.start()
            
            # Execute threaded scan
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, ip_address, port, timeout): port 
                    for port in ports_to_scan
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open = future.result()
                        if is_open:
                            # Get comprehensive port information
                            port_info = self.enhanced_port_db.get_port_info(port)
                            protocols = self.enhanced_port_db.get_protocol_support(port)
                            scan_commands = self.enhanced_port_db.get_scan_commands(port)
                            
                            with self.lock:
                                self.results.append({
                                    'port': port,
                                    'service': port_info['service'],
                                    'description': port_info['description'],
                                    'protocols': protocols,
                                    'status': port_info['status'],
                                    'category': port_info['category'],
                                    'scan_commands': scan_commands,
                                    'state': 'open'
                                })
                    except Exception as e:
                        pass  # Skip failed scans
                    finally:
                        with self.lock:
                            self.progress += 1
                            
            # Final progress update
            self._display_final_progress()
            
            # Enhanced post-processing if enabled
            if self.enable_enhanced_scanning and self.results:
                print("\n[i] Performing enhanced service detection...")
                self.results = self._enhance_scan_results(target, timeout)
                
            if self.enable_vulnerability_scanning and self.results:
                print("[i] Performing vulnerability analysis...")
                self.results = self._perform_vulnerability_scan(target, timeout)
            
            # Sort results by port number
            self.results.sort(key=lambda x: x['port'])
            
            return self.results
            
        except socket.gaierror:
            print(f"[✗] Error: Could not resolve hostname '{target}'")
            return None
        except Exception as e:
            print(f"[✗] Scan error: {e}")
            return None
            
    def scan_specific_ports(self, target, ports, threads=20, timeout=1.0):
        """Scan specific list of ports"""
        try:
            ip_address = socket.gethostbyname(target)
            
            self.total_ports = len(ports)
            self.progress = 0
            self.results = []
            self.start_time = time.time()
            
            print(f"\n[i] Scanning {len(ports)} specific ports on {target} ({ip_address})")
            
            # Start progress display
            progress_thread = threading.Thread(target=self._display_progress, daemon=True)
            progress_thread.start()
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, ip_address, port, timeout): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open = future.result()
                        if is_open:
                            # Get comprehensive port information
                            port_info = self.enhanced_port_db.get_port_info(port)
                            protocols = self.enhanced_port_db.get_protocol_support(port)
                            scan_commands = self.enhanced_port_db.get_scan_commands(port)
                            
                            with self.lock:
                                self.results.append({
                                    'port': port,
                                    'service': port_info['service'],
                                    'description': port_info['description'],
                                    'protocols': protocols,
                                    'status': port_info['status'],
                                    'category': port_info['category'],
                                    'scan_commands': scan_commands,
                                    'state': 'open'
                                })
                    except Exception:
                        pass
                    finally:
                        with self.lock:
                            self.progress += 1
                            
            self._display_final_progress()
            self.results.sort(key=lambda x: x['port'])
            return self.results
            
        except Exception as e:
            print(f"[✗] Scan error: {e}")
            return None
            
    def _scan_port(self, ip_address, port, timeout):
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception:
            return False
            
    def _display_progress(self):
        """Display real-time progress"""
        while self.progress < self.total_ports:
            with self.lock:
                current_progress = self.progress
                
            if current_progress > 0:
                elapsed = time.time() - self.start_time
                rate = current_progress / elapsed if elapsed > 0 else 0
                eta = (self.total_ports - current_progress) / rate if rate > 0 else 0
                
                percentage = (current_progress / self.total_ports) * 100
                bar_length = 40
                filled_length = int(bar_length * current_progress // self.total_ports)
                bar = '█' * filled_length + '-' * (bar_length - filled_length)
                
                sys.stdout.write(f'\r[{bar}] {percentage:.1f}% ({current_progress}/{self.total_ports}) ETA: {eta:.0f}s')
                sys.stdout.flush()
                
            time.sleep(0.1)
            
    def _display_final_progress(self):
        """Display final progress"""
        elapsed = time.time() - self.start_time
        rate = self.total_ports / elapsed if elapsed > 0 else 0
        
        sys.stdout.write(f'\r[{"█" * 40}] 100.0% ({self.total_ports}/{self.total_ports}) Completed in {elapsed:.1f}s ({rate:.0f} ports/s)\n')
        sys.stdout.flush()
        
    def _enhance_scan_results(self, target, timeout):
        """Enhance scan results with banner grabbing"""
        enhanced_results = []
        
        for result in self.results:
            port = result['port']
            service = result['service']
            
            # Grab banner for enhanced service detection
            banner_info = self.banner_grabber.grab_banner(target, port, timeout)
            
            # Create enhanced result
            enhanced_result = result.copy()
            enhanced_result.update({
                'banner_info': banner_info,
                'detected_service': banner_info.get('detected_service', service),
                'version': banner_info.get('version', 'unknown'),
                'ssl_enabled': banner_info.get('ssl_enabled', False),
                'banner': banner_info.get('banner', '')
            })
            
            enhanced_results.append(enhanced_result)
            
        return enhanced_results
        
    def _perform_vulnerability_scan(self, target, timeout):
        """Perform vulnerability scanning on open ports"""
        vuln_results = []
        
        for result in self.results:
            port = result['port']
            service = result.get('detected_service', result['service'])
            
            # Scan for vulnerabilities
            vuln_info = self.vulnerability_scanner.scan_vulnerabilities(target, port, service, timeout)
            
            # Add vulnerability information to result
            enhanced_result = result.copy()
            enhanced_result.update({
                'vulnerabilities': vuln_info.get('vulnerabilities', []),
                'vulnerability_count': len(vuln_info.get('vulnerabilities', [])),
                'has_vulnerabilities': len(vuln_info.get('vulnerabilities', [])) > 0
            })
            
            vuln_results.append(enhanced_result)
            
        return vuln_results
        
    def get_vulnerability_summary(self):
        """Get vulnerability summary for scan results"""
        if not hasattr(self, 'results') or not self.results:
            return None
            
        return self.vulnerability_scanner.get_vulnerability_summary(self.results)
        
    def display_enhanced_results(self, show_vulnerabilities=True, show_banners=True):
        """Display enhanced scan results with formatting"""
        if not self.results:
            print("[i] No open ports found.")
            return
            
        print(f"\n{'='*80}")
        print(f"ENHANCED SCAN RESULTS")
        print(f"{'='*80}")
        
        for result in self.results:
            port = result['port']
            service = result.get('detected_service', result['service'])
            version = result.get('version', 'unknown')
            description = result.get('description', '')
            ssl_enabled = result.get('ssl_enabled', False)
            
            # Port header
            ssl_indicator = " (SSL/TLS)" if ssl_enabled else ""
            print(f"\n[PORT {port}] {service.upper()}{ssl_indicator}")
            print(f"  Service: {service} {version}")
            print(f"  Description: {description}")
            print(f"  Protocols: {', '.join(result.get('protocols', ['TCP']))}")
            print(f"  Category: {result.get('category', 'Unknown')}")
            
            # Banner information
            if show_banners and result.get('banner'):
                banner = result['banner'][:100] + "..." if len(result['banner']) > 100 else result['banner']
                print(f"  Banner: {banner}")
                
            # Vulnerability information
            if show_vulnerabilities and result.get('vulnerabilities'):
                vuln_count = len(result['vulnerabilities'])
                print(f"  ⚠ Vulnerabilities: {vuln_count} found")
                
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'unknown').upper()
                    severity_indicator = {
                        'HIGH': '🔴',
                        'MEDIUM': '🟡', 
                        'LOW': '🟢'
                    }.get(severity, '⚪')
                    
                    print(f"    {severity_indicator} [{severity}] {vuln.get('description', 'Unknown vulnerability')}")
                    if vuln.get('recommendation'):
                        print(f"      → {vuln['recommendation']}")
                        
            # Scan commands
            scan_commands = result.get('scan_commands', [])
            if scan_commands:
                print(f"  Scan Commands:")
                for cmd in scan_commands[:3]:  # Show first 3 commands
                    print(f"    • {cmd}")
                    
        # Summary
        total_ports = len(self.results)
        vuln_summary = self.get_vulnerability_summary()
        
        print(f"\n{'='*80}")
        print(f"SCAN SUMMARY")
        print(f"{'='*80}")
        print(f"Total open ports: {total_ports}")
        
        if vuln_summary:
            print(f"Total vulnerabilities: {vuln_summary['total_vulnerabilities']}")
            print(f"  High severity: {vuln_summary['high_severity']}")
            print(f"  Medium severity: {vuln_summary['medium_severity']}")
            print(f"  Low severity: {vuln_summary['low_severity']}")
            
        print(f"{'='*80}")
        
    def set_enhanced_scanning(self, enabled=True):
        """Enable or disable enhanced scanning features"""
        self.enable_enhanced_scanning = enabled
        
    def set_vulnerability_scanning(self, enabled=True):
        """Enable or disable vulnerability scanning"""
        self.enable_vulnerability_scanning = enabled
