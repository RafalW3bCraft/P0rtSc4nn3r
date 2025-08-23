#!/usr/bin/env python3
"""
P0rt$c4nn3r - Professional Port Scanner
Created by RafalW3bCraft
Licensed under MIT License

An interactive terminal-based port scanner with comprehensive 
65K+ port database and professional features.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ui.interactive_menu import InteractiveMenu

def main():
    """Main entry point for P0rt$c4nn3r"""
    try:
        # Display professional header
        print_header()
        
        # Initialize and run interactive menu
        menu = InteractiveMenu()
        menu.run()
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)

def print_header():
    """Display professional application header"""
    header = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                            P0rt$c4nn3r v2.0                                  ║
║                        Professional Port Scanner                              ║
║                                                                               ║
║  Created by: RafalW3bCraft                                                    ║
║  License: MIT License                                                         ║
║  Features: 65,535+ port database, Multi-threading, Export capabilities       ║
║                                                                               ║
║  Copyright (c) 2025 RafalW3bCraft. All rights reserved.                      ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(header)

if __name__ == "__main__":
    main()
