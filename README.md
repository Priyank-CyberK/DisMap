# DisMap: Advanced Network Vulnerability Scanner 

## Overview
DisMap is a powerful, multi-protocol network scanning and vulnerability detection tool designed to provide comprehensive insights into network security.

## Features 
- **Multi-Protocol Scanning**: Supports TCP scanning across various services
- **Vulnerability Detection**: Integrated vulnerability database with CVE information
- **Configurable Scan Types**: 
  - Quick Scan: Checks critical ports
  - Full Scan: Comprehensive port scanning
- **Timing Templates**: Customizable scan aggressiveness (T0-T5)
- **Detailed Reporting**: HTML and JSON report generation

## Installation 

### Prerequisites
- Python 3.8+
- pip

### Dependencies
Install required packages:
```bash
pip install -r requirements.txt
```

## Usage 

### Basic Scanning
```bash
# Quick scan of a target
python dismap.py 192.168.1.1

# Full scan with aggressive timing
python dismap.py 192.168.1.1 -t full -T4

# Scan specific ports
python dismap.py 192.168.1.1 -p 22,80,443
```

### Scan Types
- `-t quick`: Scan common ports (default)
- `-t full`: Comprehensive port scanning

### Timing Templates
- `-T0`: Paranoid (extremely slow)
- `-T1`: Sneaky (slow)
- `-T2`: Polite (reduced load)
- `-T3`: Normal (balanced, default)
- `-T4`: Aggressive (faster)
- `-T5`: Insane (fastest)

## Security Considerations 
- Always obtain proper authorization before scanning networks
- Scanning without permission may be illegal
- Use responsibly and ethically

## Vulnerability Detection 
DisMap includes a comprehensive vulnerability database covering:
- SMB vulnerabilities
- RPC vulnerabilities
- Windows-specific exploits

## Contributing 
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License 
[Specify your license, e.g., MIT License]

## Disclaimer 
This tool is for educational and authorized testing purposes only. 
Unauthorized scanning of networks you do not own is illegal.

## Author
[Your Name/Organization]
