"""
Interactive Menu System for P0rt$c4nn3r
Professional CLI interface with color support
"""

import os
import sys
import time
from core.scanner_engine import ScannerEngine
from core.scan_results import ScanResults
from core.config import Config

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback color class
    class ForeColor:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class StyleColor:
        BRIGHT = DIM = RESET_ALL = ""
    Fore = ForeColor()
    Style = StyleColor()

class InteractiveMenu:
    """Interactive menu system for port scanner"""
    
    def __init__(self):
        self.scanner = ScannerEngine()
        self.results = ScanResults()
        self.config = Config()
        
    def run(self):
        """Main menu loop"""
        while True:
            self.display_main_menu()
            choice = self.get_user_input("Select option", "1-9")
            
            if choice == "1":
                self.quick_scan_menu()
            elif choice == "2":
                self.full_scan_menu()
            elif choice == "3":
                self.custom_range_scan_menu()
            elif choice == "4":
                self.common_ports_scan_menu()
            elif choice == "5":
                self.configuration_menu()
            elif choice == "6":
                self.results_menu()
            elif choice == "7":
                self.profiles_menu()
            elif choice == "8":
                self.about_menu()
            elif choice == "9":
                self.exit_application()
            else:
                self.print_error("Invalid selection. Please try again.")
                
    def display_main_menu(self):
        """Display the main menu options"""
        menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                        MAIN MENU                             ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}[1]{Style.RESET_ALL} Quick Scan (Top 1000 ports)
{Fore.GREEN}[2]{Style.RESET_ALL} Full Scan (All 65,535 ports)
{Fore.GREEN}[3]{Style.RESET_ALL} Custom Range Scan
{Fore.GREEN}[4]{Style.RESET_ALL} Common Ports Scan
{Fore.GREEN}[5]{Style.RESET_ALL} Configuration Settings
{Fore.GREEN}[6]{Style.RESET_ALL} View/Export Results
{Fore.GREEN}[7]{Style.RESET_ALL} Scan Profiles
{Fore.GREEN}[8]{Style.RESET_ALL} About & License
{Fore.GREEN}[9]{Style.RESET_ALL} Exit

{Fore.YELLOW}Current Config:{Style.RESET_ALL} Threads: {self.config.threads}, Timeout: {self.config.timeout}s
        """
        print(menu)
        
    def quick_scan_menu(self):
        """Quick scan of top 1000 ports"""
        target = self.get_target_input()
        if not target:
            return
            
        self.print_info(f"Starting quick scan on {target}")
        self.print_info("Scanning top 1000 most common ports...")
        
        # Use predefined top 1000 ports range
        results = self.scanner.scan_target(target, [1, 1000], scan_type="quick", 
                                         threads=self.config.threads, timeout=self.config.timeout)
        if results:
            self.results.add_scan_result(target, results, "Quick Scan")
            self.display_scan_results(results, target)
        
    def full_scan_menu(self):
        """Full scan of all 65,535 ports"""
        target = self.get_target_input()
        if not target:
            return
            
        self.print_warning("Full scan will check all 65,535 ports. This may take a while.")
        confirm = self.get_user_input("Continue? (y/n)", "y/n").lower()
        
        if confirm == 'y':
            self.print_info(f"Starting full scan on {target}")
            self.print_info("Scanning all 65,535 ports...")
            
            results = self.scanner.scan_target(target, [1, 65535], scan_type="full",
                                             threads=self.config.threads, timeout=self.config.timeout)
            if results:
                self.results.add_scan_result(target, results, "Full Scan")
                self.display_scan_results(results, target)
                
    def custom_range_scan_menu(self):
        """Custom port range scan"""
        target = self.get_target_input()
        if not target:
            return
            
        try:
            start_port = int(self.get_user_input("Start port", "1-65535"))
            end_port = int(self.get_user_input("End port", "1-65535"))
            
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                self.print_error("Invalid port range. Please check your input.")
                return
                
            self.print_info(f"Starting custom scan on {target}")
            self.print_info(f"Scanning ports {start_port}-{end_port}...")
            
            results = self.scanner.scan_target(target, [start_port, end_port], scan_type="custom",
                                             threads=self.config.threads, timeout=self.config.timeout)
            if results:
                self.results.add_scan_result(target, results, f"Custom Scan ({start_port}-{end_port})")
                self.display_scan_results(results, target)
                
        except ValueError:
            self.print_error("Invalid port number. Please enter numeric values.")
            
    def common_ports_scan_menu(self):
        """Scan only well-known common ports"""
        target = self.get_target_input()
        if not target:
            return
            
        self.print_info(f"Starting common ports scan on {target}")
        self.print_info("Scanning well-known service ports...")
        
        results = self.scanner.scan_target(target, None, scan_type="common",
                                         threads=self.config.threads, timeout=self.config.timeout)
        if results:
            self.results.add_scan_result(target, results, "Common Ports Scan")
            self.display_scan_results(results, target)
            
    def configuration_menu(self):
        """Configuration settings menu"""
        while True:
            config_menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    CONFIGURATION MENU                       ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}[1]{Style.RESET_ALL} Set Thread Count (Current: {self.config.threads})
{Fore.GREEN}[2]{Style.RESET_ALL} Set Timeout (Current: {self.config.timeout}s)
{Fore.GREEN}[3]{Style.RESET_ALL} Set Scan Delay (Current: {self.config.delay}ms)
{Fore.GREEN}[4]{Style.RESET_ALL} Toggle Verbose Output (Current: {self.config.verbose})
{Fore.GREEN}[5]{Style.RESET_ALL} Toggle Enhanced Scanning (Current: {self.scanner.enable_enhanced_scanning})
{Fore.GREEN}[6]{Style.RESET_ALL} Toggle Vulnerability Scanning (Current: {self.scanner.enable_vulnerability_scanning})
{Fore.GREEN}[7]{Style.RESET_ALL} Reset to Defaults
{Fore.GREEN}[8]{Style.RESET_ALL} Back to Main Menu
            """
            print(config_menu)
            
            choice = self.get_user_input("Select option", "1-8")
            
            if choice == "1":
                try:
                    threads = int(self.get_user_input("Thread count (1-100)", "1-100"))
                    if 1 <= threads <= 100:
                        self.config.threads = threads
                        self.print_success(f"Thread count set to {threads}")
                    else:
                        self.print_error("Thread count must be between 1-100")
                except ValueError:
                    self.print_error("Invalid thread count")
                    
            elif choice == "2":
                try:
                    timeout = float(self.get_user_input("Timeout in seconds", "0.1-10"))
                    if 0.1 <= timeout <= 10:
                        self.config.timeout = timeout
                        self.print_success(f"Timeout set to {timeout}s")
                    else:
                        self.print_error("Timeout must be between 0.1-10 seconds")
                except ValueError:
                    self.print_error("Invalid timeout value")
                    
            elif choice == "3":
                try:
                    delay = int(self.get_user_input("Delay in milliseconds", "0-1000"))
                    if 0 <= delay <= 1000:
                        self.config.delay = delay
                        self.print_success(f"Scan delay set to {delay}ms")
                    else:
                        self.print_error("Delay must be between 0-1000ms")
                except ValueError:
                    self.print_error("Invalid delay value")
                    
            elif choice == "4":
                self.config.verbose = not self.config.verbose
                self.print_success(f"Verbose output {'enabled' if self.config.verbose else 'disabled'}")
                
            elif choice == "5":
                self.scanner.set_enhanced_scanning(not self.scanner.enable_enhanced_scanning)
                self.print_success(f"Enhanced scanning {'enabled' if self.scanner.enable_enhanced_scanning else 'disabled'}")
                
            elif choice == "6":
                self.scanner.set_vulnerability_scanning(not self.scanner.enable_vulnerability_scanning)
                self.print_success(f"Vulnerability scanning {'enabled' if self.scanner.enable_vulnerability_scanning else 'disabled'}")
                
            elif choice == "7":
                self.config.reset_defaults()
                self.scanner.set_enhanced_scanning(True)
                self.scanner.set_vulnerability_scanning(True)
                self.print_success("Configuration reset to defaults")
                
            elif choice == "8":
                break
                
    def results_menu(self):
        """Results viewing and export menu"""
        if not self.results.scan_history:
            self.print_info("No scan results available.")
            return
            
        while True:
            results_menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                      RESULTS MENU                           ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}[1]{Style.RESET_ALL} View Recent Scans
{Fore.GREEN}[2]{Style.RESET_ALL} Export Results (JSON)
{Fore.GREEN}[3]{Style.RESET_ALL} Export Results (CSV)
{Fore.GREEN}[4]{Style.RESET_ALL} Export Results (TXT)
{Fore.GREEN}[5]{Style.RESET_ALL} Clear All Results
{Fore.GREEN}[6]{Style.RESET_ALL} Back to Main Menu
            """
            print(results_menu)
            
            choice = self.get_user_input("Select option", "1-6")
            
            if choice == "1":
                self.results.display_history()
            elif choice == "2":
                filename = self.get_user_input("JSON filename", "filename") or "scan_results.json"
                if self.results.export_json(filename):
                    self.print_success(f"Results exported to {filename}")
            elif choice == "3":
                filename = self.get_user_input("CSV filename", "filename") or "scan_results.csv"
                if self.results.export_csv(filename):
                    self.print_success(f"Results exported to {filename}")
            elif choice == "4":
                filename = self.get_user_input("TXT filename", "filename") or "scan_results.txt"
                if self.results.export_txt(filename):
                    self.print_success(f"Results exported to {filename}")
            elif choice == "5":
                confirm = self.get_user_input("Clear all results? (y/n)", "y/n").lower()
                if confirm == 'y':
                    self.results.clear_history()
                    self.print_success("All results cleared")
            elif choice == "6":
                break
                
    def profiles_menu(self):
        """Scan profiles menu"""
        profiles_menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                     SCAN PROFILES                           ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}[1]{Style.RESET_ALL} Web Server Profile (80, 443, 8080, 8443)
{Fore.GREEN}[2]{Style.RESET_ALL} Database Profile (3306, 5432, 1433, 27017)
{Fore.GREEN}[3]{Style.RESET_ALL} Remote Access Profile (22, 23, 3389, 5900)
{Fore.GREEN}[4]{Style.RESET_ALL} Mail Server Profile (25, 110, 143, 993, 995)
{Fore.GREEN}[5]{Style.RESET_ALL} File Transfer Profile (20, 21, 22, 69, 873)
{Fore.GREEN}[6]{Style.RESET_ALL} Back to Main Menu
        """
        print(profiles_menu)
        
        choice = self.get_user_input("Select profile", "1-6")
        
        profile_ports = {
            "1": ([80, 443, 8080, 8443], "Web Server"),
            "2": ([3306, 5432, 1433, 27017], "Database"),
            "3": ([22, 23, 3389, 5900], "Remote Access"),
            "4": ([25, 110, 143, 993, 995], "Mail Server"),
            "5": ([20, 21, 22, 69, 873], "File Transfer")
        }
        
        if choice in profile_ports:
            target = self.get_target_input()
            if target:
                ports, profile_name = profile_ports[choice]
                self.print_info(f"Starting {profile_name} profile scan on {target}")
                
                results = self.scanner.scan_specific_ports(target, ports)
                if results:
                    self.results.add_scan_result(target, results, f"{profile_name} Profile")
                    self.display_scan_results(results, target)
                    
    def about_menu(self):
        """About and license information"""
        about_text = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    ABOUT P0rt$c4nn3r                         ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Application:{Style.RESET_ALL} P0rt$c4nn3r v2.0
{Fore.YELLOW}Author:{Style.RESET_ALL} RafalW3bCraft
{Fore.YELLOW}License:{Style.RESET_ALL} MIT License
{Fore.YELLOW}Website:{Style.RESET_ALL} https://github.com/RafalW3bCraft

{Fore.GREEN}Features:{Style.RESET_ALL}
• Comprehensive 65,535 port database
• Multi-threaded scanning engine
• Interactive CLI interface
• Multiple export formats
• Scan profiles and presets
• Real-time progress tracking

{Fore.RED}Legal Notice:{Style.RESET_ALL}
This tool is for educational and authorized testing purposes only.
Users are responsible for compliance with applicable laws and regulations.

{Fore.CYAN}Copyright (c) 2025 RafalW3bCraft. All rights reserved.{Style.RESET_ALL}
        """
        print(about_text)
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
    def get_target_input(self):
        """Get and validate target input from user"""
        while True:
            target = self.get_user_input("Target (IP/hostname)", "target")
            if not target:
                return None
                
            if self.scanner.validate_target(target):
                return target
            else:
                self.print_error("Invalid target. Please enter a valid IP address or hostname.")
                retry = self.get_user_input("Try again? (y/n)", "y/n").lower()
                if retry != 'y':
                    return None
                    
    def display_scan_results(self, results, target):
        """Display enhanced scan results with vulnerabilities and banners"""
        if not results:
            self.print_info(f"No open ports found on {target}")
            return
            
        # Use enhanced display from scanner engine
        print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
        self.scanner.display_enhanced_results(show_vulnerabilities=True, show_banners=True)
        
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        
    def get_user_input(self, prompt, input_type):
        """Get user input with prompt"""
        try:
            return input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} {prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            return ""
            
    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {message}")
        
    def print_info(self, message):
        """Print info message"""
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {message}")
        
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
        
    def print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}[✗]{Style.RESET_ALL} {message}")
        
    def exit_application(self):
        """Exit application gracefully"""
        print(f"\n{Fore.CYAN}Thank you for using P0rt$c4nn3r!")
        print(f"Created by RafalW3bCraft - https://github.com/RafalW3bCraft{Style.RESET_ALL}")
        sys.exit(0)
