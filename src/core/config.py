"""
Configuration Management for P0rt$c4nn3r
Handle application settings and preferences
"""

import os

class Config:
    """Configuration management for scanner settings"""
    
    def __init__(self):
        self.threads = 50
        self.timeout = 1.0
        self.delay = 0
        self.verbose = True
        self.output_format = "table"
        self.save_results = True
        
    def reset_defaults(self):
        """Reset configuration to default values"""
        self.threads = 50
        self.timeout = 1.0
        self.delay = 0
        self.verbose = True
        self.output_format = "table"
        self.save_results = True
        
    def load_from_env(self):
        """Load configuration from environment variables"""
        self.threads = int(os.getenv("SCANNER_THREADS", self.threads))
        self.timeout = float(os.getenv("SCANNER_TIMEOUT", self.timeout))
        self.delay = int(os.getenv("SCANNER_DELAY", self.delay))
        self.verbose = os.getenv("SCANNER_VERBOSE", "true").lower() == "true"
        
    def validate_settings(self):
        """Validate current settings"""
        if not (1 <= self.threads <= 100):
            self.threads = 50
            
        if not (0.1 <= self.timeout <= 10.0):
            self.timeout = 1.0
            
        if not (0 <= self.delay <= 1000):
            self.delay = 0
            
    def get_settings_summary(self):
        """Get formatted settings summary"""
        return f"""
Current Configuration:
- Threads: {self.threads}
- Timeout: {self.timeout}s
- Delay: {self.delay}ms
- Verbose: {self.verbose}
- Output Format: {self.output_format}
- Save Results: {self.save_results}
        """
