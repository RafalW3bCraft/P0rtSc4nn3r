"""
Enhanced Display System for P0rt$c4nn3r
Provides comprehensive port information display with detailed service data,
protocol support, scanning commands, and IANA status information.
"""

from colorama import Fore, Style, init
from database.enhanced_port_database import EnhancedPortDatabase

# Initialize colorama
init(autoreset=True)

class EnhancedDisplay:
    """Enhanced display system with comprehensive port information"""
    
    def __init__(self):
        self.port_db = EnhancedPortDatabase()
        
    def display_comprehensive_results(self, results, target, show_commands=True):
        """Display comprehensive scan results with detailed port information"""
        if not results:
            print(f"\n{Fore.CYAN}[i]{Style.RESET_ALL} No open ports found on {target}")
            return
            
        # Header
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                 COMPREHENSIVE SCAN RESULTS                  ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
        print(f"{Fore.CYAN}Open Ports Found:{Style.RESET_ALL} {len(results)}")
        
        # Summary by category
        self._display_category_summary(results)
        
        # Detailed port information
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}DETAILED PORT ANALYSIS{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        
        for i, port_info in enumerate(results, 1):
            port = port_info['port']
            # Use the comprehensive information from scan results
            enhanced_info = port_info if 'description' in port_info else self.port_db.get_port_info(port)
            
            self._display_port_details(i, port, enhanced_info, show_commands)
            
        # Security recommendations
        self._display_security_recommendations(results)
        
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
    def _display_category_summary(self, results):
        """Display summary of ports grouped by category"""
        categories = {}
        
        for port_info in results:
            port = port_info['port']
            # Use category from scan results if available, otherwise fetch from database
            category = port_info.get('category', 'Unknown') if 'category' in port_info else self.port_db.get_port_info(port).get('category', 'Unknown')
            
            if category not in categories:
                categories[category] = []
            categories[category].append(port)
            
        print(f"\n{Fore.CYAN}SERVICES BY CATEGORY:{Style.RESET_ALL}")
        print("-" * 40)
        
        for category, ports in sorted(categories.items()):
            ports_str = ', '.join(map(str, sorted(ports)))
            print(f"{Fore.GREEN}{category}:{Style.RESET_ALL} {ports_str}")
            
    def _display_port_details(self, index, port, enhanced_info, show_commands=True):
        """Display detailed information for a single port"""
        print(f"\n{Fore.CYAN}[{index}] PORT {port}{Style.RESET_ALL}")
        print("─" * 60)
        
        # Basic information
        service = enhanced_info.get('service', 'Unknown')
        description = enhanced_info.get('description', 'No description available')
        status = enhanced_info.get('status', 'Unknown')
        category = enhanced_info.get('category', 'Unknown')
        
        print(f"{Fore.GREEN}Service:{Style.RESET_ALL} {service}")
        print(f"{Fore.GREEN}Description:{Style.RESET_ALL} {description}")
        print(f"{Fore.GREEN}Category:{Style.RESET_ALL} {category}")
        print(f"{Fore.GREEN}IANA Status:{Style.RESET_ALL} {status}")
        
        # Protocol support
        protocols = enhanced_info.get('protocols', self.port_db.get_protocol_support(port))
        protocols_str = ', '.join(protocols)
        print(f"{Fore.GREEN}Protocols:{Style.RESET_ALL} {protocols_str}")
        
        # Security assessment
        security_risk = self._assess_security_risk(port, enhanced_info)
        risk_color = self._get_risk_color(security_risk)
        print(f"{Fore.GREEN}Security Risk:{Style.RESET_ALL} {risk_color}{security_risk}{Style.RESET_ALL}")
        
        # Scanning commands
        if show_commands:
            scan_commands = enhanced_info.get('scan_commands', [])
            if scan_commands:
                print(f"{Fore.GREEN}Scanning Commands:{Style.RESET_ALL}")
                for i, cmd in enumerate(scan_commands[:3], 1):  # Show top 3 commands
                    print(f"  {Fore.YELLOW}{i}.{Style.RESET_ALL} {cmd}")
                    
    def _assess_security_risk(self, port, enhanced_info):
        """Assess security risk level for a port"""
        high_risk_ports = [21, 23, 25, 53, 69, 79, 110, 111, 135, 139, 445, 512, 513, 514]
        medium_risk_ports = [22, 80, 443, 993, 995, 143, 587, 636]
        
        category = enhanced_info.get('category', '').lower()
        
        if port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        elif 'authentication' in category or 'remote access' in category:
            return "HIGH"
        elif 'database' in category:
            return "HIGH"
        elif 'web services' in category:
            return "MEDIUM"
        else:
            return "LOW"
            
    def _get_risk_color(self, risk_level):
        """Get color based on risk level"""
        if risk_level == "HIGH":
            return Fore.RED
        elif risk_level == "MEDIUM":
            return Fore.YELLOW
        else:
            return Fore.GREEN
            
    def _display_security_recommendations(self, results):
        """Display security recommendations based on found ports"""
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SECURITY RECOMMENDATIONS{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        
        recommendations = set()
        high_risk_found = False
        
        for port_info in results:
            port = port_info['port']
            enhanced_info = self.port_db.get_port_info(port)
            risk = self._assess_security_risk(port, enhanced_info)
            
            if risk == "HIGH":
                high_risk_found = True
                
            # Add specific recommendations based on port
            if port == 21:
                recommendations.add("• Consider using SFTP (port 22) instead of FTP for secure file transfer")
            elif port == 23:
                recommendations.add("• Replace Telnet with SSH (port 22) for secure remote access")
            elif port == 80:
                recommendations.add("• Implement HTTPS (port 443) to encrypt web traffic")
            elif port in [135, 139, 445]:
                recommendations.add("• Secure Windows file sharing services or disable if not needed")
            elif port in [1433, 3306, 5432]:
                recommendations.add("• Ensure database is not exposed to public internet")
            elif port == 3389:
                recommendations.add("• Use VPN or restrict RDP access to specific IP ranges")
            elif port in [5900, 5901, 5902]:
                recommendations.add("• Secure VNC connections with authentication and encryption")
                
        # General recommendations
        if high_risk_found:
            recommendations.add("• Implement network segmentation and access controls")
            recommendations.add("• Use firewalls to restrict access to necessary services only")
            recommendations.add("• Regularly update and patch all discovered services")
            recommendations.add("• Monitor these ports for suspicious activity")
            
        recommendations.add("• Perform regular security audits and vulnerability assessments")
        recommendations.add("• Follow principle of least privilege for all services")
        
        for rec in sorted(recommendations):
            print(f"{Fore.CYAN}{rec}{Style.RESET_ALL}")
            
    def display_simple_results(self, results, target):
        """Display simple results (backward compatibility)"""
        if not results:
            print(f"\n{Fore.CYAN}[i]{Style.RESET_ALL} No open ports found on {target}")
            return
            
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    SCAN RESULTS                             ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
        print(f"{Fore.CYAN}Open Ports Found:{Style.RESET_ALL} {len(results)}")
        print(f"\n{Fore.YELLOW}{'PORT':<10}{'SERVICE':<20}{'STATUS':<10}{'CATEGORY'}{Style.RESET_ALL}")
        print("-" * 60)
        
        for port_info in results:
            port = port_info['port']
            status = port_info['status']
            enhanced_info = self.port_db.get_port_info(port)
            
            service = enhanced_info.get('service', 'Unknown')
            category = enhanced_info.get('category', 'Unknown')
            
            status_color = Fore.GREEN if status == 'open' else Fore.RED
            print(f"{port:<10}{service:<20}{status_color}{status:<10}{Style.RESET_ALL}{category}")
            
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
    def display_port_analysis_menu(self, results, target):
        """Display interactive port analysis menu"""
        while True:
            print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
            print(f"║                    PORT ANALYSIS MENU                       ║")
            print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}[1]{Style.RESET_ALL} Show Comprehensive Analysis")
            print(f"{Fore.GREEN}[2]{Style.RESET_ALL} Show Simple Summary")
            print(f"{Fore.GREEN}[3]{Style.RESET_ALL} Show Scanning Commands")
            print(f"{Fore.GREEN}[4]{Style.RESET_ALL} Show Security Assessment")
            print(f"{Fore.GREEN}[5]{Style.RESET_ALL} Search Specific Port")
            print(f"{Fore.GREEN}[6]{Style.RESET_ALL} Export Analysis Report")
            print(f"{Fore.GREEN}[7]{Style.RESET_ALL} Back to Main Menu")
            
            try:
                choice = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Select option (1-7): ").strip()
            except (EOFError, KeyboardInterrupt):
                break
                
            if choice == "1":
                self.display_comprehensive_results(results, target, show_commands=True)
            elif choice == "2":
                self.display_simple_results(results, target)
            elif choice == "3":
                self._display_scanning_commands_only(results)
            elif choice == "4":
                self._display_security_assessment_only(results, target)
            elif choice == "5":
                self._search_specific_port(results)
            elif choice == "6":
                self._export_analysis_report(results, target)
            elif choice == "7":
                break
            else:
                print(f"{Fore.RED}[✗]{Style.RESET_ALL} Invalid option. Please select 1-7.")
                
    def _display_scanning_commands_only(self, results):
        """Display only scanning commands for all ports"""
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   SCANNING COMMANDS                         ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        for port_info in results:
            port = port_info['port']
            enhanced_info = self.port_db.get_port_info(port)
            service = enhanced_info.get('service', 'Unknown')
            scan_commands = enhanced_info.get('scan_commands', [])
            
            print(f"\n{Fore.CYAN}Port {port} ({service}):{Style.RESET_ALL}")
            if scan_commands:
                for i, cmd in enumerate(scan_commands, 1):
                    print(f"  {Fore.YELLOW}{i}.{Style.RESET_ALL} {cmd}")
            else:
                print(f"  {Fore.RED}No specific scanning commands available{Style.RESET_ALL}")
                
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
    def _display_security_assessment_only(self, results, target):
        """Display only security assessment"""
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                  SECURITY ASSESSMENT                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
        
        risk_summary = {"HIGH": [], "MEDIUM": [], "LOW": []}
        
        for port_info in results:
            port = port_info['port']
            enhanced_info = self.port_db.get_port_info(port)
            risk = self._assess_security_risk(port, enhanced_info)
            risk_summary[risk].append(port)
            
        print(f"\n{Fore.CYAN}RISK SUMMARY:{Style.RESET_ALL}")
        for risk_level, ports in risk_summary.items():
            if ports:
                color = self._get_risk_color(risk_level)
                ports_str = ', '.join(map(str, sorted(ports)))
                print(f"{color}{risk_level} RISK:{Style.RESET_ALL} {ports_str}")
                
        self._display_security_recommendations(results)
        
    def _search_specific_port(self, results):
        """Search for specific port in results"""
        try:
            search_port = int(input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Enter port number to search: "))
        except (ValueError, EOFError, KeyboardInterrupt):
            return
            
        found_port = None
        for port_info in results:
            if port_info['port'] == search_port:
                found_port = port_info
                break
                
        if found_port:
            enhanced_info = self.port_db.get_port_info(search_port)
            print(f"\n{Fore.GREEN}Port {search_port} found in results:{Style.RESET_ALL}")
            self._display_port_details(1, search_port, enhanced_info, show_commands=True)
        else:
            print(f"\n{Fore.RED}[✗]{Style.RESET_ALL} Port {search_port} not found in current scan results")
            
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
    def _export_analysis_report(self, results, target):
        """Export detailed analysis report"""
        try:
            filename = input(f"\n{Fore.YELLOW}[?]{Style.RESET_ALL} Enter filename (or press Enter for default): ").strip()
            if not filename:
                filename = f"port_analysis_{target.replace('.', '_')}.txt"
                
            with open(filename, 'w') as f:
                f.write("P0rt$c4nn3r - Comprehensive Port Analysis Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"Target: {target}\n")
                f.write(f"Timestamp: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Open Ports: {len(results)}\n\n")
                
                # Category summary
                categories = {}
                for port_info in results:
                    port = port_info['port']
                    enhanced_info = self.port_db.get_port_info(port)
                    category = enhanced_info.get('category', 'Unknown')
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(port)
                    
                f.write("SERVICES BY CATEGORY:\n")
                f.write("-" * 30 + "\n")
                for category, ports in sorted(categories.items()):
                    ports_str = ', '.join(map(str, sorted(ports)))
                    f.write(f"{category}: {ports_str}\n")
                    
                f.write("\nDETAILED PORT ANALYSIS:\n")
                f.write("=" * 40 + "\n")
                
                for i, port_info in enumerate(results, 1):
                    port = port_info['port']
                    enhanced_info = self.port_db.get_port_info(port)
                    
                    f.write(f"\n[{i}] PORT {port}\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"Service: {enhanced_info.get('service', 'Unknown')}\n")
                    f.write(f"Description: {enhanced_info.get('description', 'No description')}\n")
                    f.write(f"Category: {enhanced_info.get('category', 'Unknown')}\n")
                    f.write(f"IANA Status: {enhanced_info.get('status', 'Unknown')}\n")
                    
                    protocols = self.port_db.get_protocol_support(port)
                    f.write(f"Protocols: {', '.join(protocols)}\n")
                    
                    risk = self._assess_security_risk(port, enhanced_info)
                    f.write(f"Security Risk: {risk}\n")
                    
                    scan_commands = enhanced_info.get('scan_commands', [])
                    if scan_commands:
                        f.write("Scanning Commands:\n")
                        for j, cmd in enumerate(scan_commands, 1):
                            f.write(f"  {j}. {cmd}\n")
                            
            print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Analysis report exported to {filename}")
            
        except Exception as e:
            print(f"{Fore.RED}[✗]{Style.RESET_ALL} Error exporting report: {e}")
            
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")