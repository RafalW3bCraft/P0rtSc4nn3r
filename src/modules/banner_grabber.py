"""
Banner Grabber for P0rt$c4nn3r
Enhanced service detection through banner grabbing
"""

import socket
import ssl
import re
import time

class BannerGrabber:
    """Enhanced banner grabbing for accurate service detection"""
    
    def __init__(self):
        self.service_signatures = self._build_service_signatures()
        
    def grab_banner(self, target, port, timeout=3.0):
        """Grab banner and attempt service identification"""
        try:
            # Try different connection methods based on port
            banner = None
            service_info = {}
            
            # Try standard TCP connection first
            banner = self._grab_tcp_banner(target, port, timeout)
            
            # Try SSL/TLS if standard fails and port commonly uses SSL
            if not banner and port in [443, 993, 995, 465, 636, 8443]:
                banner = self._grab_ssl_banner(target, port, timeout)
                service_info['ssl_enabled'] = True
                
            if banner:
                # Analyze banner for service identification
                detected_service = self._identify_service(banner, port)
                service_info.update({
                    'banner': banner,
                    'detected_service': detected_service['service'],
                    'version': detected_service['version'],
                    'additional_info': detected_service['additional_info']
                })
                
            return service_info
            
        except Exception as e:
            return {'error': str(e)}
            
    def _grab_tcp_banner(self, target, port, timeout):
        """Grab banner using standard TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send appropriate probe based on port
            probe = self._get_port_probe(port)
            if probe:
                sock.send(probe.encode('utf-8', errors='ignore'))
                time.sleep(0.5)  # Wait for response
                
            # Receive banner
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
            
    def _grab_ssl_banner(self, target, port, timeout):
        """Grab banner using SSL/TLS connection"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ssl_sock = context.wrap_socket(sock)
            ssl_sock.connect((target, port))
            
            # Send appropriate probe
            probe = self._get_port_probe(port)
            if probe:
                ssl_sock.send(probe.encode('utf-8', errors='ignore'))
                time.sleep(0.5)
                
            banner = ssl_sock.recv(2048).decode('utf-8', errors='ignore').strip()
            ssl_sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
            
    def _get_port_probe(self, port):
        """Get appropriate probe string for specific ports"""
        probes = {
            21: "USER anonymous\r\n",
            22: "",  # SSH sends banner immediately
            23: "",  # Telnet sends banner immediately  
            25: "EHLO banner-grabber\r\n",
            53: "",  # DNS typically doesn't respond to TCP probes
            80: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: P0rtSc4nn3r\r\nConnection: close\r\n\r\n",
            110: "USER test\r\n",
            119: "HELP\r\n",
            143: "A001 CAPABILITY\r\n",
            443: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: P0rtSc4nn3r\r\nConnection: close\r\n\r\n",
            993: "A001 CAPABILITY\r\n",
            995: "USER test\r\n",
            1433: "",  # SQL Server
            3306: "",  # MySQL
            5432: "",  # PostgreSQL
            6379: "INFO\r\n",  # Redis
            8080: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: P0rtSc4nn3r\r\nConnection: close\r\n\r\n",
            8443: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: P0rtSc4nn3r\r\nConnection: close\r\n\r\n",
            9200: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: P0rtSc4nn3r\r\nConnection: close\r\n\r\n",  # Elasticsearch
            27017: "",  # MongoDB
        }
        return probes.get(port, "")
        
    def _identify_service(self, banner, port):
        """Identify service based on banner analysis"""
        banner_lower = banner.lower()
        result = {
            'service': 'unknown',
            'version': 'unknown',
            'additional_info': []
        }
        
        # Check against service signatures
        for signature in self.service_signatures:
            if re.search(signature['pattern'], banner_lower):
                result['service'] = signature['service']
                
                # Extract version if pattern includes version group
                version_match = re.search(signature.get('version_pattern', ''), banner)
                if version_match:
                    result['version'] = version_match.group(1)
                    
                result['additional_info'] = signature.get('additional_info', [])
                break
                
        # Port-specific fallback identification
        if result['service'] == 'unknown':
            result['service'] = self._get_default_service_by_port(port)
            
        return result
        
    def _get_default_service_by_port(self, port):
        """Get default service name based on port number"""
        default_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 3306: 'mysql', 5432: 'postgresql',
            6379: 'redis', 8080: 'http-alt', 27017: 'mongodb'
        }
        return default_services.get(port, f'port-{port}')
        
    def _build_service_signatures(self):
        """Build comprehensive service signature database"""
        return [
            # Web servers
            {
                'pattern': r'apache[\/\s]([0-9\.]+)',
                'version_pattern': r'apache[\/\s]([0-9\.]+)',
                'service': 'apache',
                'additional_info': ['web_server']
            },
            {
                'pattern': r'nginx[\/\s]([0-9\.]+)',
                'version_pattern': r'nginx[\/\s]([0-9\.]+)',
                'service': 'nginx',
                'additional_info': ['web_server']
            },
            {
                'pattern': r'microsoft-iis[\/\s]([0-9\.]+)',
                'version_pattern': r'microsoft-iis[\/\s]([0-9\.]+)',
                'service': 'iis',
                'additional_info': ['web_server', 'microsoft']
            },
            
            # SSH servers
            {
                'pattern': r'openssh[_\s]([0-9\.]+)',
                'version_pattern': r'openssh[_\s]([0-9\.]+)',
                'service': 'openssh',
                'additional_info': ['ssh_server']
            },
            {
                'pattern': r'ssh-[0-9\.]+',
                'service': 'ssh',
                'additional_info': ['ssh_server']
            },
            
            # FTP servers
            {
                'pattern': r'vsftpd ([0-9\.]+)',
                'version_pattern': r'vsftpd ([0-9\.]+)',
                'service': 'vsftpd',
                'additional_info': ['ftp_server']
            },
            {
                'pattern': r'proftpd ([0-9\.]+)',
                'version_pattern': r'proftpd ([0-9\.]+)',
                'service': 'proftpd',
                'additional_info': ['ftp_server']
            },
            {
                'pattern': r'filezilla server',
                'service': 'filezilla',
                'additional_info': ['ftp_server']
            },
            
            # Mail servers
            {
                'pattern': r'postfix',
                'service': 'postfix',
                'additional_info': ['mail_server', 'smtp']
            },
            {
                'pattern': r'sendmail ([0-9\.]+)',
                'version_pattern': r'sendmail ([0-9\.]+)',
                'service': 'sendmail',
                'additional_info': ['mail_server', 'smtp']
            },
            {
                'pattern': r'exim ([0-9\.]+)',
                'version_pattern': r'exim ([0-9\.]+)',
                'service': 'exim',
                'additional_info': ['mail_server', 'smtp']
            },
            
            # Database servers
            {
                'pattern': r'mysql.*([0-9\.]+)',
                'version_pattern': r'mysql.*([0-9\.]+)',
                'service': 'mysql',
                'additional_info': ['database']
            },
            {
                'pattern': r'postgresql ([0-9\.]+)',
                'version_pattern': r'postgresql ([0-9\.]+)',
                'service': 'postgresql',
                'additional_info': ['database']
            },
            {
                'pattern': r'redis_version:([0-9\.]+)',
                'version_pattern': r'redis_version:([0-9\.]+)',
                'service': 'redis',
                'additional_info': ['database', 'cache']
            },
            {
                'pattern': r'mongodb ([0-9\.]+)',
                'version_pattern': r'mongodb ([0-9\.]+)',
                'service': 'mongodb',
                'additional_info': ['database', 'nosql']
            },
            
            # Application servers
            {
                'pattern': r'apache tomcat[\/\s]([0-9\.]+)',
                'version_pattern': r'apache tomcat[\/\s]([0-9\.]+)',
                'service': 'tomcat',
                'additional_info': ['application_server', 'java']
            },
            {
                'pattern': r'jetty[\/\s]([0-9\.]+)',
                'version_pattern': r'jetty[\/\s]([0-9\.]+)',
                'service': 'jetty',
                'additional_info': ['application_server', 'java']
            },
            
            # Elasticsearch
            {
                'pattern': r'"number" : "([0-9\.]+)".*elasticsearch',
                'version_pattern': r'"number" : "([0-9\.]+)"',
                'service': 'elasticsearch',
                'additional_info': ['search_engine', 'analytics']
            },
            
            # Docker
            {
                'pattern': r'"apiversion":"([0-9\.]+)"',
                'version_pattern': r'"apiversion":"([0-9\.]+)"',
                'service': 'docker',
                'additional_info': ['container_platform']
            },
        ]
        
    def enhance_scan_results(self, scan_results, target, timeout=3.0):
        """Enhance scan results with banner grabbing information"""
        enhanced_results = []
        
        for result in scan_results:
            port = result['port']
            service = result['service']
            
            # Grab banner for this port
            banner_info = self.grab_banner(target, port, timeout)
            
            # Enhance the result
            enhanced_result = result.copy()
            enhanced_result.update({
                'banner_info': banner_info,
                'enhanced_service': banner_info.get('detected_service', service),
                'version': banner_info.get('version', 'unknown'),
                'ssl_enabled': banner_info.get('ssl_enabled', False)
            })
            
            enhanced_results.append(enhanced_result)
            
        return enhanced_results