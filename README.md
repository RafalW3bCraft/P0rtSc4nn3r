# P0rt$c4nn3r

**Professional Network Port Scanner with Enhanced Security Analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

P0rt$c4nn3r is a professional-grade, interactive terminal-based port scanner designed for network administrators, security professionals, and developers. It provides comprehensive network reconnaissance capabilities with advanced service detection, vulnerability analysis, and detailed reporting.

## 🚀 Features

### Core Scanning Capabilities
- **Multi-threaded Scanning**: Configurable thread pools (1-100) for optimal performance
- **Comprehensive Port Database**: 65,535+ ports with modern service mappings
- **Multiple Scan Types**: Quick, Full, Custom Range, and Common Ports scans
- **Advanced Target Resolution**: Support for hostnames and IP addresses

### Enhanced Security Analysis
- **🛡️ Vulnerability Detection**: Automated security assessment for common services
- **🎯 Banner Grabbing**: Service fingerprinting with SSL/TLS support
- **📊 Security Headers Analysis**: HTTP security configuration assessment
- **🔍 Service Version Detection**: Automated version identification and vulnerability mapping

### Professional Reporting
- **Color-coded Output**: Intuitive severity levels with visual indicators
- **Detailed Recommendations**: Actionable security improvement suggestions
- **Multiple Export Formats**: JSON, CSV, and TXT report generation
- **Scan History**: Track and compare multiple reconnaissance sessions

### Modern Service Support
- **Container Platforms**: Docker, Kubernetes, etcd
- **Databases**: Elasticsearch, MongoDB, Redis, PostgreSQL
- **Monitoring Tools**: Prometheus, Grafana, Zabbix
- **Message Queues**: Kafka, RabbitMQ, ActiveMQ
- **Development Servers**: Node.js, Flask, React, webpack

## 📋 Requirements

- Python 3.6 or higher
- Dependencies: `colorama` (optional, for colored output)

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/RafalW3bCraft/P0rtSc4nn3r.git
   cd P0rtSc4nn3r
   ```

2. **Install dependencies** (optional):
   ```bash
   pip install colorama
   ```

3. **Run the scanner**:
   ```bash
   python main.py
   ```

## 🎯 Quick Start

### Interactive Mode
```bash
python main.py
```
Follow the interactive menu to configure and run scans.

### Example Scan Output
```
[PORT 443] HTTPS (SSL/TLS)
  Service: https nginx/1.18.0
  Description: HTTP Secure (HTTPS) - encrypted web traffic
  Protocols: TCP, SCTP
  Category: Web Services
  Banner: HTTP/1.1 200 OK
  ⚠ Vulnerabilities: 3 found
    🟢 [LOW] Missing X-Frame-Options header
      → Add x-frame-options header to improve security
    🟡 [MEDIUM] Nginx version disclosed
      → Hide version information in server header
```

## 📊 Scan Types

| Scan Type | Description | Typical Use Case |
|-----------|-------------|------------------|
| **Quick Scan** | Top 1000 most common ports | Initial reconnaissance |
| **Full Scan** | All 65,535 ports | Comprehensive assessment |
| **Common Ports** | Well-known service ports | Standard security audit |
| **Custom Range** | User-defined port range | Targeted investigation |

## ⚙️ Configuration Options

- **Thread Count**: 1-100 concurrent threads
- **Timeout**: 0.1-10 seconds per port
- **Scan Delay**: 0-1000ms between attempts
- **Enhanced Scanning**: Toggle banner grabbing and service detection
- **Vulnerability Analysis**: Enable/disable security assessment

## 🛡️ Security Features

### Vulnerability Detection
- HTTP security headers analysis
- SSH version and configuration assessment
- FTP anonymous access detection
- SMTP open relay identification
- Service version vulnerability mapping

### Banner Analysis
- Service fingerprinting with signature database
- SSL/TLS connection support
- Version extraction and analysis
- Protocol detection and validation

## 📁 Export Formats

### JSON Export
```json
{
  "scan_info": {
    "target": "example.com",
    "scan_type": "Quick Scan",
    "timestamp": "2025-01-15 10:30:45"
  },
  "results": [
    {
      "port": 443,
      "service": "https",
      "vulnerabilities": [...],
      "banner_info": {...}
    }
  ]
}
```

### CSV Export
```csv
Port,Service,Status,Vulnerabilities,Category
443,https,open,3,Web Services
80,http,open,4,Web Services
```

## 🔧 Advanced Usage

### Configuration Menu
Access advanced settings through the interactive configuration menu:
- Adjust scanning parameters
- Toggle enhanced features
- Configure output preferences
- Reset to optimal defaults

### Scan Profiles
Save and load custom scanning configurations for different use cases:
- Stealth scanning (low threads, high timeout)
- Fast scanning (high threads, low timeout)
- Comprehensive auditing (all features enabled)

## 📈 Performance

- **Scan Rate**: Up to 100 ports/second (depending on network conditions)
- **Thread Efficiency**: Optimized thread pool management
- **Memory Usage**: Minimal footprint with efficient data structures
- **Network Friendly**: Configurable delays to avoid overwhelming targets

## ⚖️ Legal Notice

**Important**: This tool is designed for educational purposes and authorized penetration testing only. Users are responsible for:

- Obtaining proper authorization before scanning any network
- Complying with applicable laws and regulations
- Using the tool responsibly and ethically
- Respecting network resources and availability

**Unauthorized port scanning may be illegal in your jurisdiction.**

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**RafalW3bCraft**
- GitHub: [@RafalW3bCraft](https://github.com/RafalW3bCraft)

## 🙏 Acknowledgments

- Inspired by traditional network reconnaissance tools
- Built with modern Python best practices
- Designed for professional security assessment workflows

## 📚 Documentation

For detailed documentation, examples, and advanced configuration options, please visit the [project wiki](https://github.com/RafalW3bCraft/P0rtSc4nn3r/wiki).

---

**Disclaimer**: P0rt$c4nn3r is a penetration testing tool intended for authorized security assessments only. Always ensure you have explicit permission before scanning any network infrastructure.