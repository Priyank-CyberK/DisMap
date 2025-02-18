# DisMap: Advanced Network Vulnerability Scanner 🌐🔍

## Overview

DisMap is an advanced network scanning and vulnerability detection tool that provides comprehensive security insights by leveraging authoritative vulnerability databases and intelligent scanning techniques.

## Key Features 🚀

- **Comprehensive Vulnerability Intelligence**
  - Real-time vulnerability data integration
  - Cross-referenced vulnerability information
  - Multi-source vulnerability mapping

- **Advanced Scanning Capabilities**
  - Multi-protocol TCP scanning
  - Configurable scan strategies
  - Adaptive timing templates
  - Detailed service and version detection

- **Intelligent Vulnerability Management**
  - NVD (National Vulnerability Database) integration
  - MITRE CVE cross-referencing
  - Automated vulnerability correlation
  - Comprehensive reporting mechanisms

## Vulnerability Data Sources 📊

DisMap aggregates vulnerability information from multiple authoritative sources:

- **National Vulnerability Database (NVD)**
  - Maintained by NIST
  - Provides standardized vulnerability information
  - Includes CVSS scoring and detailed vulnerability descriptions

- **MITRE CVE List**
  - Comprehensive Common Vulnerabilities and Exposures (CVE) repository
  - Globally recognized vulnerability identification system
  - Provides unique identifiers for known cybersecurity vulnerabilities

## Installation 🛠️

### Prerequisites
- Python 3.8+
- pip package manager

### Dependencies
```bash
pip install -r requirements.txt
```

## Usage 📋

### Basic Scanning
```bash
# Quick network scan
python dismap.py 192.168.1.1

# Full comprehensive scan
python dismap.py 192.168.1.1 -t full -T4

# Targeted port scanning
python dismap.py 192.168.1.1 -p 22,80,443
```

### Scan Configurations

#### Scan Types
- `-t quick`: Rapid critical port scanning (default)
- `-t full`: Comprehensive network exploration

#### Timing Templates
- `-T0`: Paranoid (minimal network impact)
- `-T1`: Cautious (low-and-slow approach)
- `-T2`: Conservative (reduced network load)
- `-T3`: Balanced (default scanning strategy)
- `-T4`: Aggressive (faster scanning)
- `-T5`: Intense (maximum speed, higher detection risk)

## Security Considerations ⚠️

- **Ethical Use**: Obtain explicit authorization before scanning
- **Legal Compliance**: Unauthorized network scanning may violate laws
- **Responsible Disclosure**: Report vulnerabilities through proper channels

## Contributing 🤝

### Project Maintainer
**Priyank Vachhani**
- GitHub: [@Priyank-CyberK](https://github.com/Priyank-CyberK)
- Email: vachhanipriyank@gmail.com

### Contribution Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📄

### MIT License

Copyright (c) 2025 Priyank Vachhani

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer ⚖️

DisMap is an educational tool designed for authorized network security testing. 
Users are solely responsible for compliance with all applicable laws and regulations. 
Unauthorized network scanning is strictly prohibited.
