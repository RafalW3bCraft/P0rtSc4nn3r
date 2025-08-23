"""
Enhanced Port Database for P0rt$c4nn3r
Comprehensive port database with detailed service information, protocol support,
IANA status, descriptions, and scanning commands based on official sources.
"""

class EnhancedPortDatabase:
    """Enhanced database with comprehensive port information"""
    
    def __init__(self):
        self.port_data = self._build_enhanced_database()
        
    def get_port_info(self, port):
        """Get comprehensive port information"""
        return self.port_data.get(port, {
            'service': 'Unknown',
            'description': 'Unknown service',
            'tcp': False,
            'udp': False,
            'sctp': False,
            'dccp': False,
            'status': 'Unassigned',
            'category': 'Unknown',
            'scan_commands': [
                f'nmap -p {port} <target>',
                f'nc -v <target> {port}'
            ]
        })
        
    def get_service_name(self, port):
        """Get service name for backward compatibility"""
        return self.port_data.get(port, {}).get('service', 'Unknown')
        
    def get_scan_commands(self, port):
        """Get scanning commands for specific port"""
        port_info = self.get_port_info(port)
        return port_info.get('scan_commands', [])
        
    def get_protocol_support(self, port):
        """Get protocol support information"""
        port_info = self.get_port_info(port)
        protocols = []
        if port_info.get('tcp'): protocols.append('TCP')
        if port_info.get('udp'): protocols.append('UDP')
        if port_info.get('sctp'): protocols.append('SCTP')
        if port_info.get('dccp'): protocols.append('DCCP')
        return protocols if protocols else ['Unknown']
        
    def _build_enhanced_database(self):
        """Build comprehensive enhanced port database based on official IANA assignments and Wikipedia data"""
        # Start with well-known ports data
        enhanced_db = {}
        
        # Critical well-known ports with comprehensive data
        critical_ports = {
            1: {
                'service': 'tcpmux',
                'description': 'TCP Port Service Multiplexer (TCPMUX)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'System',
                'scan_commands': ['nmap -p 1 <target>', 'telnet <target> 1', 'nc -v <target> 1']
            },
            7: {
                'service': 'echo',
                'description': 'Echo Protocol - returns received data',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Network Testing',
                'scan_commands': ['nmap -p 7 <target>', 'echo "test" | nc <target> 7', 'nmap -sU -p 7 <target>']
            },
            9: {
                'service': 'discard',
                'description': 'Discard Protocol (null service) - discards received data',
                'tcp': True, 'udp': True, 'sctp': True, 'dccp': True,
                'status': 'Official', 'category': 'Network Testing',
                'scan_commands': ['nmap -p 9 <target>', 'echo "test" | nc <target> 9', 'nmap -sU -p 9 <target>']
            },
            11: {
                'service': 'systat',
                'description': 'Active Users (systat service) - system status',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'System Information',
                'scan_commands': ['nmap -p 11 <target>', 'nc -v <target> 11', 'systat <target>']
            },
            13: {
                'service': 'daytime',
                'description': 'Daytime Protocol - returns human-readable time',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Time Services',
                'scan_commands': ['nmap -p 13 <target>', 'nc <target> 13', 'nmap -sU -p 13 <target>']
            },
            17: {
                'service': 'qotd',
                'description': 'Quote of the Day Protocol',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Information',
                'scan_commands': ['nmap -p 17 <target>', 'nc <target> 17', 'telnet <target> 17']
            },
            19: {
                'service': 'chargen',
                'description': 'Character Generator Protocol (CHARGEN)',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Network Testing',
                'scan_commands': ['nmap -p 19 <target>', 'nc <target> 19', 'telnet <target> 19']
            },
            20: {
                'service': 'ftp-data',
                'description': 'File Transfer Protocol (FTP) data transfer',
                'tcp': True, 'udp': False, 'sctp': True, 'dccp': False,
                'status': 'Official', 'category': 'File Transfer',
                'scan_commands': ['nmap -p 20 <target>', 'ftp <target>', 'nc -v <target> 20', 'nmap -sS -sV -p 20 <target>']
            },
            21: {
                'service': 'ftp',
                'description': 'File Transfer Protocol (FTP) control (command)',
                'tcp': True, 'udp': False, 'sctp': True, 'dccp': False,
                'status': 'Official', 'category': 'File Transfer',
                'scan_commands': ['nmap -p 21 <target>', 'ftp <target>', 'nmap --script ftp-anon -p 21 <target>', 'hydra -l admin -P passwords.txt ftp://<target>']
            },
            22: {
                'service': 'ssh',
                'description': 'Secure Shell (SSH) - secure remote login and file transfer',
                'tcp': True, 'udp': False, 'sctp': True, 'dccp': False,
                'status': 'Official', 'category': 'Remote Access',
                'scan_commands': ['nmap -p 22 <target>', 'ssh <target>', 'nmap --script ssh-hostkey -p 22 <target>', 'ssh-keyscan <target>']
            },
            23: {
                'service': 'telnet',
                'description': 'Telnet protocol - unencrypted text communications',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Remote Access',
                'scan_commands': ['nmap -p 23 <target>', 'telnet <target>', 'nmap --script telnet-brute -p 23 <target>']
            },
            25: {
                'service': 'smtp',
                'description': 'Simple Mail Transfer Protocol (SMTP) - email routing',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 25 <target>', 'telnet <target> 25', 'nmap --script smtp-commands -p 25 <target>', 'nmap --script smtp-enum-users -p 25 <target>']
            },
            53: {
                'service': 'dns',
                'description': 'Domain Name System (DNS) - name resolution',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Name Services',
                'scan_commands': ['nmap -p 53 <target>', 'nslookup google.com <target>', 'dig @<target> google.com', 'nmap --script dns-zone-transfer -p 53 <target>', 'dnsrecon -d <target>']
            },
            67: {
                'service': 'dhcp-server',
                'description': 'Dynamic Host Configuration Protocol (DHCP) Server',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Network Configuration',
                'scan_commands': ['nmap -sU -p 67 <target>', 'nmap --script dhcp-discover -p 67 <target>']
            },
            68: {
                'service': 'dhcp-client',
                'description': 'Dynamic Host Configuration Protocol (DHCP) Client',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Network Configuration',
                'scan_commands': ['nmap -sU -p 68 <target>']
            },
            69: {
                'service': 'tftp',
                'description': 'Trivial File Transfer Protocol (TFTP)',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'File Transfer',
                'scan_commands': ['nmap -sU -p 69 <target>', 'tftp <target>', 'nmap --script tftp-enum -p 69 <target>']
            },
            79: {
                'service': 'finger',
                'description': 'Finger Protocol - user information lookup',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Information',
                'scan_commands': ['nmap -p 79 <target>', 'finger @<target>', 'nmap --script finger -p 79 <target>']
            },
            80: {
                'service': 'http',
                'description': 'Hypertext Transfer Protocol (HTTP) - web traffic',
                'tcp': True, 'udp': False, 'sctp': True, 'dccp': False,
                'status': 'Official', 'category': 'Web Services',
                'scan_commands': ['nmap -p 80 <target>', 'curl http://<target>', 'nmap --script http-enum -p 80 <target>', 'nikto -h <target>', 'dirb http://<target>']
            },
            88: {
                'service': 'kerberos',
                'description': 'Kerberos authentication protocol',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Authentication',
                'scan_commands': ['nmap -p 88 <target>', 'nmap -sU -p 88 <target>', 'kerbrute userenum -d <target> users.txt']
            },
            110: {
                'service': 'pop3',
                'description': 'Post Office Protocol v3 (POP3) - email retrieval',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 110 <target>', 'telnet <target> 110', 'nmap --script pop3-capabilities -p 110 <target>']
            },
            111: {
                'service': 'rpcbind',
                'description': 'ONC RPC (Remote Procedure Call) portmapper',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'RPC Services',
                'scan_commands': ['nmap -p 111 <target>', 'rpcinfo -p <target>', 'nmap --script rpc-grind -p 111 <target>', 'nmap -sU -p 111 <target>']
            },
            113: {
                'service': 'ident',
                'description': 'Ident Protocol - user identification',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Authentication',
                'scan_commands': ['nmap -p 113 <target>', 'nc -v <target> 113', 'ident-user-enum <target>']
            },
            119: {
                'service': 'nntp',
                'description': 'Network News Transfer Protocol (NNTP)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'News',
                'scan_commands': ['nmap -p 119 <target>', 'telnet <target> 119', 'nc -v <target> 119']
            },
            123: {
                'service': 'ntp',
                'description': 'Network Time Protocol (NTP) - time synchronization',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Time Services',
                'scan_commands': ['nmap -sU -p 123 <target>', 'ntpdate -q <target>', 'nmap --script ntp-info -p 123 <target>']
            },
            135: {
                'service': 'msrpc',
                'description': 'Microsoft RPC (Remote Procedure Call)',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'RPC Services',
                'scan_commands': ['nmap -p 135 <target>', 'rpcinfo -p <target>', 'nmap --script msrpc-enum -p 135 <target>', 'rpcclient -U "" <target>']
            },
            137: {
                'service': 'netbios-ns',
                'description': 'NetBIOS Name Service',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Name Services',
                'scan_commands': ['nmap -sU -p 137 <target>', 'nbtscan <target>', 'nmap --script nbstat -p 137 <target>']
            },
            138: {
                'service': 'netbios-dgm',
                'description': 'NetBIOS Datagram Service',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'File Sharing',
                'scan_commands': ['nmap -sU -p 138 <target>']
            },
            139: {
                'service': 'netbios-ssn',
                'description': 'NetBIOS Session Service',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'File Sharing',
                'scan_commands': ['nmap -p 139 <target>', 'smbclient -L <target>', 'enum4linux <target>', 'nmap --script smb-enum-shares -p 139 <target>']
            },
            143: {
                'service': 'imap',
                'description': 'Internet Message Access Protocol (IMAP) - email access',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 143 <target>', 'telnet <target> 143', 'nmap --script imap-capabilities -p 143 <target>']
            },
            161: {
                'service': 'snmp',
                'description': 'Simple Network Management Protocol (SNMP)',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Network Management',
                'scan_commands': ['nmap -sU -p 161 <target>', 'snmpwalk -v2c -c public <target>', 'nmap --script snmp-info -p 161 <target>', 'onesixtyone <target>']
            },
            162: {
                'service': 'snmptrap',
                'description': 'Simple Network Management Protocol (SNMP) Trap',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Network Management',
                'scan_commands': ['nmap -sU -p 162 <target>']
            },
            179: {
                'service': 'bgp',
                'description': 'Border Gateway Protocol (BGP)',
                'tcp': True, 'udp': False, 'sctp': True, 'dccp': False,
                'status': 'Official', 'category': 'Routing',
                'scan_commands': ['nmap -p 179 <target>', 'nc -v <target> 179']
            },
            389: {
                'service': 'ldap',
                'description': 'Lightweight Directory Access Protocol (LDAP)',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Directory Services',
                'scan_commands': ['nmap -p 389 <target>', 'ldapsearch -h <target>', 'nmap --script ldap-rootdse -p 389 <target>', 'ldapwhoami -H ldap://<target>']
            },
            443: {
                'service': 'https',
                'description': 'HTTP Secure (HTTPS) - encrypted web traffic',
                'tcp': True, 'udp': False, 'sctp': True, 'dccp': False,
                'status': 'Official', 'category': 'Web Services',
                'scan_commands': ['nmap -p 443 <target>', 'curl https://<target>', 'openssl s_client -connect <target>:443', 'nmap --script ssl-enum-ciphers -p 443 <target>', 'sslscan <target>:443']
            },
            445: {
                'service': 'microsoft-ds',
                'description': 'Microsoft Directory Services (SMB over TCP)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'File Sharing',
                'scan_commands': ['nmap -p 445 <target>', 'smbclient -L <target>', 'enum4linux <target>', 'nmap --script smb-enum-shares -p 445 <target>', 'nmap --script smb-vuln-* -p 445 <target>']
            },
            465: {
                'service': 'smtps',
                'description': 'Simple Mail Transfer Protocol Secure (SMTPS)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 465 <target>', 'openssl s_client -connect <target>:465', 'nmap --script smtp-commands -p 465 <target>']
            },
            587: {
                'service': 'submission',
                'description': 'Message Submission Protocol (SMTP Submission)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 587 <target>', 'telnet <target> 587', 'nmap --script smtp-commands -p 587 <target>']
            },
            631: {
                'service': 'ipp',
                'description': 'Internet Printing Protocol (IPP)',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Printing',
                'scan_commands': ['nmap -p 631 <target>', 'curl http://<target>:631', 'nmap --script cups-info -p 631 <target>']
            },
            636: {
                'service': 'ldaps',
                'description': 'Lightweight Directory Access Protocol Secure (LDAPS)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Directory Services',
                'scan_commands': ['nmap -p 636 <target>', 'openssl s_client -connect <target>:636', 'ldapsearch -H ldaps://<target>']
            },
            873: {
                'service': 'rsync',
                'description': 'rsync file synchronization protocol',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'File Transfer',
                'scan_commands': ['nmap -p 873 <target>', 'rsync <target>::', 'nc -v <target> 873']
            },
            993: {
                'service': 'imaps',
                'description': 'Internet Message Access Protocol Secure (IMAPS)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 993 <target>', 'openssl s_client -connect <target>:993', 'nmap --script imap-capabilities -p 993 <target>']
            },
            995: {
                'service': 'pop3s',
                'description': 'Post Office Protocol 3 Secure (POP3S)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Mail',
                'scan_commands': ['nmap -p 995 <target>', 'openssl s_client -connect <target>:995', 'nmap --script pop3-capabilities -p 995 <target>']
            },
            
            # Registered ports (1024-49151) - Selection of important ones
            1080: {
                'service': 'socks',
                'description': 'SOCKS proxy server',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Proxy',
                'scan_commands': ['nmap -p 1080 <target>', 'nc -v <target> 1080', 'proxychains curl http://google.com']
            },
            1194: {
                'service': 'openvpn',
                'description': 'OpenVPN',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'VPN',
                'scan_commands': ['nmap -p 1194 <target>', 'nmap -sU -p 1194 <target>']
            },
            1433: {
                'service': 'ms-sql-s',
                'description': 'Microsoft SQL Server',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Database',
                'scan_commands': ['nmap -p 1433 <target>', 'nmap --script ms-sql-info -p 1433 <target>', 'sqlcmd -S <target> -U sa']
            },
            1521: {
                'service': 'oracle',
                'description': 'Oracle Database',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Database',
                'scan_commands': ['nmap -p 1521 <target>', 'nmap --script oracle-sid-brute -p 1521 <target>', 'tnscmd10g version -h <target>']
            },
            1723: {
                'service': 'pptp',
                'description': 'Point-to-Point Tunneling Protocol (PPTP)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'VPN',
                'scan_commands': ['nmap -p 1723 <target>', 'nc -v <target> 1723']
            },
            2049: {
                'service': 'nfs',
                'description': 'Network File System (NFS)',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'File Sharing',
                'scan_commands': ['nmap -p 2049 <target>', 'showmount -e <target>', 'nmap --script nfs-ls -p 2049 <target>']
            },
            2222: {
                'service': 'ssh-alt',
                'description': 'SSH Alternative Port',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Remote Access',
                'scan_commands': ['nmap -p 2222 <target>', 'ssh -p 2222 <target>', 'nc -v <target> 2222']
            },
            3128: {
                'service': 'squid-http',
                'description': 'Squid Web Proxy Cache',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Proxy',
                'scan_commands': ['nmap -p 3128 <target>', 'curl --proxy <target>:3128 http://google.com', 'nc -v <target> 3128']
            },
            3306: {
                'service': 'mysql',
                'description': 'MySQL Database',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Database',
                'scan_commands': ['nmap -p 3306 <target>', 'mysql -h <target> -u root', 'nmap --script mysql-info -p 3306 <target>', 'nmap --script mysql-enum -p 3306 <target>']
            },
            3389: {
                'service': 'ms-wbt-server',
                'description': 'Microsoft Terminal Server (RDP)',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Remote Access',
                'scan_commands': ['nmap -p 3389 <target>', 'rdesktop <target>', 'nmap --script rdp-enum-encryption -p 3389 <target>', 'ncrack -vv --user administrator -P passwords.txt rdp://<target>']
            },
            5432: {
                'service': 'postgresql',
                'description': 'PostgreSQL Database',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Database',
                'scan_commands': ['nmap -p 5432 <target>', 'psql -h <target> -U postgres', 'nmap --script pgsql-brute -p 5432 <target>']
            },
            5900: {
                'service': 'vnc',
                'description': 'Virtual Network Computing (VNC)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Remote Access',
                'scan_commands': ['nmap -p 5900 <target>', 'vncviewer <target>', 'nmap --script vnc-info -p 5900 <target>', 'nmap --script vnc-brute -p 5900 <target>']
            },
            6379: {
                'service': 'redis',
                'description': 'Redis Database',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Database',
                'scan_commands': ['nmap -p 6379 <target>', 'redis-cli -h <target>', 'nmap --script redis-info -p 6379 <target>']
            },
            8080: {
                'service': 'http-proxy',
                'description': 'HTTP Proxy / Alternative HTTP',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Web Services',
                'scan_commands': ['nmap -p 8080 <target>', 'curl http://<target>:8080', 'nmap --script http-enum -p 8080 <target>', 'nikto -h <target>:8080']
            },
            8443: {
                'service': 'https-alt',
                'description': 'HTTPS Alternative',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Web Services',
                'scan_commands': ['nmap -p 8443 <target>', 'curl https://<target>:8443', 'openssl s_client -connect <target>:8443']
            },
            9050: {
                'service': 'tor-socks',
                'description': 'Tor SOCKS proxy',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Proxy',
                'scan_commands': ['nmap -p 9050 <target>', 'nc -v <target> 9050']
            },
            27017: {
                'service': 'mongodb',
                'description': 'MongoDB Database',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Database',
                'scan_commands': ['nmap -p 27017 <target>', 'mongo <target>:27017', 'nmap --script mongodb-info -p 27017 <target>']
            },
            # Modern web services and APIs
            3000: {
                'service': 'node-js',
                'description': 'Node.js development server / NTOP',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Web Services',
                'scan_commands': ['nmap -p 3000 <target>', 'curl http://<target>:3000', 'nc -v <target> 3000']
            },
            4000: {
                'service': 'dev-server',
                'description': 'Development server (React, Vue, Angular)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Web Services',
                'scan_commands': ['nmap -p 4000 <target>', 'curl http://<target>:4000']
            },
            5000: {
                'service': 'flask-dev',
                'description': 'Flask development server / UPnP',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Web Services',
                'scan_commands': ['nmap -p 5000 <target>', 'curl http://<target>:5000', 'nmap -sU -p 5000 <target>']
            },
            # Container and orchestration platforms
            2375: {
                'service': 'docker',
                'description': 'Docker daemon API (unencrypted)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Container Services',
                'scan_commands': ['nmap -p 2375 <target>', 'curl http://<target>:2375/version', 'docker -H tcp://<target>:2375 version']
            },
            2376: {
                'service': 'docker-ssl',
                'description': 'Docker daemon API (TLS encrypted)',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Container Services',
                'scan_commands': ['nmap -p 2376 <target>', 'curl https://<target>:2376/version', 'openssl s_client -connect <target>:2376']
            },
            2379: {
                'service': 'etcd-client',
                'description': 'etcd client communication',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Container Services',
                'scan_commands': ['nmap -p 2379 <target>', 'curl http://<target>:2379/version']
            },
            2380: {
                'service': 'etcd-peer',
                'description': 'etcd server-to-server communication',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Container Services',
                'scan_commands': ['nmap -p 2380 <target>']
            },
            6443: {
                'service': 'kubernetes-api',
                'description': 'Kubernetes API server',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Container Services',
                'scan_commands': ['nmap -p 6443 <target>', 'curl -k https://<target>:6443/version', 'kubectl cluster-info']
            },
            10250: {
                'service': 'kubelet',
                'description': 'Kubernetes kubelet API',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Container Services',
                'scan_commands': ['nmap -p 10250 <target>', 'curl -k https://<target>:10250/healthz']
            },
            # Message queues and streaming
            5672: {
                'service': 'rabbitmq',
                'description': 'RabbitMQ AMQP',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'Message Queue',
                'scan_commands': ['nmap -p 5672 <target>', 'nmap --script amqp-info -p 5672 <target>']
            },
            15672: {
                'service': 'rabbitmq-mgmt',
                'description': 'RabbitMQ Management HTTP API',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Message Queue',
                'scan_commands': ['nmap -p 15672 <target>', 'curl http://<target>:15672']
            },
            9092: {
                'service': 'kafka',
                'description': 'Apache Kafka',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Message Queue',
                'scan_commands': ['nmap -p 9092 <target>', 'nc -v <target> 9092']
            },
            # Monitoring and metrics
            3001: {
                'service': 'grafana',
                'description': 'Grafana / Nessus Scanner',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Monitoring',
                'scan_commands': ['nmap -p 3001 <target>', 'curl http://<target>:3001']
            },
            9090: {
                'service': 'prometheus',
                'description': 'Prometheus metrics server',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Monitoring',
                'scan_commands': ['nmap -p 9090 <target>', 'curl http://<target>:9090/metrics']
            },
            9093: {
                'service': 'alertmanager',
                'description': 'Prometheus Alertmanager',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Monitoring',
                'scan_commands': ['nmap -p 9093 <target>', 'curl http://<target>:9093']
            },
            # Search and analytics
            9200: {
                'service': 'elasticsearch',
                'description': 'Elasticsearch HTTP',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Search/Analytics',
                'scan_commands': ['nmap -p 9200 <target>', 'curl http://<target>:9200', 'nmap --script elasticsearch-info -p 9200 <target>']
            },
            9300: {
                'service': 'elasticsearch-transport',
                'description': 'Elasticsearch Transport',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Search/Analytics',
                'scan_commands': ['nmap -p 9300 <target>']
            },
            5601: {
                'service': 'kibana',
                'description': 'Kibana web interface',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Search/Analytics',
                'scan_commands': ['nmap -p 5601 <target>', 'curl http://<target>:5601']
            },
            # Modern communication
            9443: {
                'service': 'websocket-secure',
                'description': 'WebSocket Secure',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Communication',
                'scan_commands': ['nmap -p 9443 <target>', 'openssl s_client -connect <target>:9443']
            },
            # Gaming and media
            25565: {
                'service': 'minecraft',
                'description': 'Minecraft server',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Gaming',
                'scan_commands': ['nmap -p 25565 <target>', 'nc -v <target> 25565']
            },
            27015: {
                'service': 'steam-source',
                'description': 'Steam Source Dedicated Server',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Gaming',
                'scan_commands': ['nmap -p 27015 <target>', 'nmap -sU -p 27015 <target>']
            },
            # Cloud services
            50070: {
                'service': 'hadoop-namenode',
                'description': 'Hadoop NameNode HTTP',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Big Data',
                'scan_commands': ['nmap -p 50070 <target>', 'curl http://<target>:50070']
            },
            8020: {
                'service': 'hadoop-namenode-ipc',
                'description': 'Hadoop NameNode IPC',
                'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Big Data',
                'scan_commands': ['nmap -p 8020 <target>']
            },
            # Databases and caches
            11211: {
                'service': 'memcached',
                'description': 'Memcached',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Unofficial', 'category': 'Database',
                'scan_commands': ['nmap -p 11211 <target>', 'echo "stats" | nc <target> 11211', 'nmap --script memcached-info -p 11211 <target>']
            },
            # Security and VPN
            1194: {
                'service': 'openvpn',
                'description': 'OpenVPN',
                'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'VPN',
                'scan_commands': ['nmap -p 1194 <target>', 'nmap -sU -p 1194 <target>', 'nmap --script openvpn-info -p 1194 <target>']
            },
            4500: {
                'service': 'ipsec-nat-t',
                'description': 'IPSec NAT-Traversal',
                'tcp': False, 'udp': True, 'sctp': False, 'dccp': False,
                'status': 'Official', 'category': 'VPN',
                'scan_commands': ['nmap -sU -p 4500 <target>', 'ike-scan <target>']
            }
        }
        
        # Add the critical ports to the enhanced database
        enhanced_db.update(critical_ports)
        
        # Generate remaining ports with generic information
        for port in range(1, 65536):
            if port not in enhanced_db:
                if port < 1024:
                    # Well-known ports
                    enhanced_db[port] = {
                        'service': f'well-known-{port}',
                        'description': f'Well-known port {port} (see IANA registry)',
                        'tcp': True, 'udp': True, 'sctp': False, 'dccp': False,
                        'status': 'Reserved', 'category': 'Well-Known',
                        'scan_commands': [f'nmap -p {port} <target>', f'nc -v <target> {port}']
                    }
                elif port < 49152:
                    # Registered ports
                    enhanced_db[port] = {
                        'service': f'registered-{port}',
                        'description': f'Registered port {port}',
                        'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                        'status': 'Registered', 'category': 'Registered',
                        'scan_commands': [f'nmap -p {port} <target>', f'nc -v <target> {port}']
                    }
                else:
                    # Dynamic/Private ports
                    enhanced_db[port] = {
                        'service': f'dynamic-{port}',
                        'description': f'Dynamic/Private port {port}',
                        'tcp': True, 'udp': False, 'sctp': False, 'dccp': False,
                        'status': 'Dynamic', 'category': 'Dynamic/Private',
                        'scan_commands': [f'nmap -p {port} <target>', f'nc -v <target> {port}']
                    }
        
        return enhanced_db
        
    def get_common_ports(self):
        """Get list of most common ports for scanning"""
        return [
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 139, 
            143, 161, 162, 179, 389, 443, 445, 465, 587, 631, 636, 
            873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2222, 3128, 
            3306, 3389, 5432, 5900, 6379, 8080, 8443, 9050, 27017
        ]
        
    def get_top_ports(self, count=1000):
        """Get top N most commonly scanned ports"""
        # Extended top ports list based on nmap's frequency data
        top_ports = [
            # Most critical ports first
            80, 443, 22, 21, 25, 53, 110, 993, 995, 143, 587, 465, 23, 135, 139, 445,
            3389, 1433, 3306, 5432, 1521, 27017, 6379, 5900, 8080, 8443, 111, 2049,
            873, 631, 636, 389, 161, 162, 179, 123, 1080, 1194, 1723, 9050,
            # Additional well-known ports
            1, 7, 9, 11, 13, 17, 19, 20, 67, 68, 69, 79, 88, 113, 119, 137, 138, 2222, 3128
        ]
        
        # Extend with sequential ports if more are needed
        if count > len(top_ports):
            additional_ports = []
            for port in range(1024, 1024 + (count - len(top_ports))):
                if port not in top_ports:
                    additional_ports.append(port)
            top_ports.extend(additional_ports)
        
        return top_ports[:count]