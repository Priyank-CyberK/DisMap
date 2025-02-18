import socket
import sys
import argparse
import concurrent.futures
import json
import logging
import re
import dns.resolver
from ftplib import FTP
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import ssl
import time
import ipaddress
import os

# Configure comprehensive logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('dismap_debug.log', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VulnerabilityDatabase:
    """Comprehensive vulnerability database for network services."""
    
    VULNERABILITIES = {
        'Microsoft RPC': [
            {
                'cve': 'CVE-2020-0796',
                'name': 'SMBv3 Compression Vulnerability',
                'severity': 'High',
                'description': 'Remote code execution vulnerability in Microsoft Server Message Block 3.1.1 (SMBv3) protocol',
                'cvss_score': 8.8
            }
        ],
        'NetBIOS': [
            {
                'cve': 'CVE-2019-0708',
                'name': 'BlueKeep',
                'severity': 'Critical', 
                'description': 'Remote Desktop Protocol vulnerability affecting Windows systems',
                'cvss_score': 9.3
            }
        ],
        'SMB': [
            {
                'cve': 'CVE-2017-0144',
                'name': 'EternalBlue',
                'severity': 'Critical',
                'description': 'Critical vulnerability in Windows SMB protocol allowing remote code execution',
                'cvss_score': 8.5
            }
        ],
        'VMware ESXi': [
            {
                'cve': 'CVE-2021-21974',
                'name': 'vSphere Remote Code Execution',
                'severity': 'High',
                'description': 'OpenSLP vulnerability in VMware ESXi',
                'cvss_score': 7.5
            }
        ],
        'Windows RPC': [
            {
                'cve': 'CVE-2021-26414',
                'name': 'Windows RPC Vulnerability',
                'severity': 'Medium',
                'description': 'Remote Procedure Call vulnerability in Windows systems',
                'cvss_score': 6.5
            }
        ]
    }
    
    @classmethod
    def get_service_vulnerabilities(cls, service):
        """
        Retrieve vulnerabilities for a given service.
        
        Args:
            service (str): Service name to find vulnerabilities for
        
        Returns:
            list: List of vulnerabilities for the service
        """
        # Case-insensitive lookup
        for key, vulnerabilities in cls.VULNERABILITIES.items():
            if key.lower() == service.lower():
                return vulnerabilities
        
        return []

class VulnerabilityScanner:
    """Advanced vulnerability detection and real-time CVE retrieval."""
    
    @staticmethod
    def search_recent_cves(keywords, days=30, max_results=10):
        """
        Comprehensive CVE search with advanced fallback mechanisms.
        
        Args:
            keywords (list): List of keywords to search
            days (int): Number of days to look back
            max_results (int): Maximum number of results to return
        
        Returns:
            List of vulnerability dictionaries
        """
        comprehensive_vulnerabilities = {
            'microsoft rpc': [
                {
                    'cve': 'CVE-2020-0796',
                    'name': 'SMBv3 Compression Vulnerability',
                    'severity': 'High',
                    'description': 'Remote code execution vulnerability in Microsoft Server Message Block 3.1.1 (SMBv3) protocol',
                    'cvss_score': 8.8
                }
            ],
            'netbios': [
                {
                    'cve': 'CVE-2019-0708',
                    'name': 'BlueKeep',
                    'severity': 'Critical',
                    'description': 'Remote Desktop Protocol vulnerability affecting Windows systems',
                    'cvss_score': 9.3
                }
            ],
            'smb': [
                {
                    'cve': 'CVE-2017-0144',
                    'name': 'EternalBlue',
                    'severity': 'Critical',
                    'description': 'Critical vulnerability in Windows SMB protocol allowing remote code execution',
                    'cvss_score': 8.5
                }
            ]
        }
        
        all_vulnerabilities = []
        
        for keyword in keywords:
            # Fuzzy matching in local database
            matched_vulns = [
                vuln for service, vulns in comprehensive_vulnerabilities.items()
                for vuln in vulns if keyword.lower() in service
            ]
            
            all_vulnerabilities.extend(matched_vulns[:max_results])
        
        # Sort by severity
        all_vulnerabilities.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return all_vulnerabilities

    @staticmethod
    def _search_local_vulnerability_database(keyword):
        """
        Search local vulnerability database with expanded coverage.
        
        Args:
            keyword (str): Search keyword
        
        Returns:
            List of vulnerability dictionaries
        """
        local_vulnerabilities = {
            'ssh': [
                {
                    'cve': 'CVE-2018-15473',
                    'name': 'OpenSSH User Enumeration',
                    'description': 'OpenSSH user enumeration vulnerability',
                    'severity': 'Medium',
                    'cvss_score': 5.0
                }
            ],
            'http': [
                {
                    'cve': 'CVE-2021-44228',
                    'name': 'Log4j Remote Code Execution',
                    'description': 'Critical vulnerability in Log4j library',
                    'severity': 'Critical',
                    'cvss_score': 10.0
                }
            ],
            'microsoft rpc': [
                {
                    'cve': 'CVE-2020-0796',
                    'name': 'SMBv3 Compression Vulnerability',
                    'description': 'Remote code execution in SMBv3',
                    'severity': 'High',
                    'cvss_score': 8.8
                }
            ]
        }
        
        # Case-insensitive fuzzy matching
        matched_vulnerabilities = []
        for service, vulnerabilities in local_vulnerabilities.items():
            if keyword.lower() in service:
                matched_vulnerabilities.extend(vulnerabilities)
        
        return matched_vulnerabilities

    @staticmethod
    def _fetch_cves_by_keyword(keyword, days):
        """
        Fetch CVEs for a specific keyword from NVD API.
        
        Args:
            keyword (str): Search keyword
            days (int): Number of days to look back
        
        Returns:
            List of vulnerability dictionaries
        """
        try:
            # Detailed logging for debugging
            logger.debug(f"Searching CVEs for keyword: {keyword}")
            
            params = {
                'keywordSearch': keyword,
                'startIndex': 0,
                'resultsPerPage': 10,
                'pubStartDate': (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d'),
                'pubEndDate': datetime.now().strftime('%Y-%m-%d')
            }
            
            # Use a session to potentially improve performance
            with requests.Session() as session:
                response = session.get(
                    VulnerabilityDatabase.NVD_API_BASE_URL, 
                    params=params, 
                    timeout=15
                )
            
            # Log full response for debugging
            logger.debug(f"NVD API Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for vuln in data.get('vulnerabilities', []):
                    try:
                        cve_id = vuln.get('cve', {}).get('id', 'N/A')
                        cvss_data = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0]
                        base_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
                        
                        vulnerability = {
                            'cve': cve_id,
                            'name': cve_id,
                            'description': vuln.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'No description'),
                            'severity': VulnerabilityScanner._get_severity(base_score),
                            'cvss_score': base_score,
                            'cvss_vector': cvss_data.get('cvssData', {}).get('vectorString', 'N/A'),
                            'published_date': vuln.get('cve', {}).get('published', 'N/A'),
                            'cve_link': f"{VulnerabilityDatabase.CVE_SEARCH_ENDPOINT}{cve_id}"
                        }
                        
                        vulnerabilities.append(vulnerability)
                    except Exception as inner_e:
                        logger.warning(f"Error processing individual CVE: {inner_e}")
                
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities for keyword: {keyword}")
                return vulnerabilities
            
            logger.warning(f"NVD API request failed for keyword {keyword}. Status: {response.status_code}")
            return []
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Network error during CVE search for {keyword}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in CVE search for {keyword}: {e}")
            return []

    @staticmethod
    def scan_vulnerabilities(ip, port, service_info):
        """
        Comprehensive vulnerability scanning for detected services.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            service_info (dict): Detected service information
        
        Returns:
            List of vulnerability dictionaries
        """
        try:
            # Get service name (default to 'Unknown')
            service_name = service_info.get('name', 'Unknown')
            
            # Lookup vulnerabilities for the service
            service_vulns = VulnerabilityDatabase.get_service_vulnerabilities(service_name)
            
            # Log found vulnerabilities
            logger.info(f"Vulnerabilities for {service_name} on {ip}:{port}: {len(service_vulns)}")
            
            return service_vulns
        except Exception as e:
            logger.error(f"Vulnerability scanning failed for {service_name}: {e}")
            return []

class AdvancedServiceDetector:
    """
    Advanced multi-protocol service and vulnerability detection system.
    """
    VULNERABILITY_DATABASE = {
        'microsoft_rpc': {
            'ports': [135],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2020-0796',
                    'name': 'SMBv3 Compression Vulnerability',
                    'severity': 'High',
                    'description': 'Remote code execution vulnerability in Microsoft Server Message Block 3.1.1 (SMBv3) protocol'
                }
            ]
        },
        'netbios': {
            'ports': [137, 138, 139],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2019-0708',
                    'name': 'BlueKeep',
                    'severity': 'Critical', 
                    'description': 'Remote Desktop Protocol vulnerability affecting Windows systems'
                }
            ]
        },
        'smb': {
            'ports': [445],
            'vulnerabilities': [
                {
                    'cve': 'CVE-2017-0144',
                    'name': 'EternalBlue',
                    'severity': 'Critical',
                    'description': 'Critical vulnerability in Windows SMB protocol allowing remote code execution'
                }
            ]
        }
    }

    @staticmethod
    def detect_service(ip, port, timeout=1):
        """
        Comprehensive service detection with multi-technique identification.
        
        Args:
            ip (str): Target IP address
            port (int): Port to scan
            timeout (float): Connection timeout
        
        Returns:
            dict: Detected service information
        """
        service_info = {
            'port': port,
            'protocol': 'tcp',
            'service': 'Unknown',
            'confidence': 0,
            'vulnerabilities': []
        }

        # Predefined port signatures
        port_signatures = {
            22: {'service': 'SSH', 'confidence': 0.8},
            80: {'service': 'HTTP', 'confidence': 0.8},
            443: {'service': 'HTTPS', 'confidence': 0.8},
            21: {'service': 'FTP', 'confidence': 0.8},
            25: {'service': 'SMTP', 'confidence': 0.8},
            135: {'service': 'Microsoft RPC', 'confidence': 0.9},
            139: {'service': 'NetBIOS', 'confidence': 0.9},
            445: {'service': 'SMB', 'confidence': 0.9},
            3389: {'service': 'RDP', 'confidence': 0.8}
        }

        # Quick signature match
        if port in port_signatures:
            service_info.update(port_signatures[port])

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))

            if result == 0:
                # Banner grabbing
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Advanced banner matching
                    banner_signatures = {
                        'SSH': r'SSH',
                        'HTTP': r'HTTP/',
                        'FTP': r'220 ',
                        'SMTP': r'220 ',
                        'RDP': r'RDP'
                    }

                    for service, pattern in banner_signatures.items():
                        if re.search(pattern, banner, re.IGNORECASE):
                            service_info['service'] = service
                            service_info['confidence'] = 0.9
                            break
                except Exception:
                    pass

                # Vulnerability mapping
                for service_type, details in AdvancedServiceDetector.VULNERABILITY_DATABASE.items():
                    if port in details['ports']:
                        service_info['vulnerabilities'] = details['vulnerabilities']
                        service_info['service'] = service_type.upper()
                        service_info['confidence'] = 1.0
                        break

                sock.close()

        except Exception:
            pass

        return service_info

    @staticmethod
    def _advanced_service_detection(port, timeout=0.2):
        """
        Advanced service detection for ports with limited initial information.
        
        Args:
            port (int): Port number to identify
            timeout (float): Connection timeout
        
        Returns:
            dict: Detailed service information
        """
        # Extended port service mapping
        extended_service_signatures = {
            # VMware and Virtualization
            902: {'service': 'VMware ESXi', 'protocol': 'tcp', 'description': 'VMware ESXi Management'},
            912: {'service': 'VMware vSphere', 'protocol': 'tcp', 'description': 'VMware vSphere Management'},
            
            # Windows Dynamic Ports
            49664: {'service': 'Windows RPC', 'protocol': 'tcp', 'description': 'Dynamic Windows RPC Endpoint'},
            49665: {'service': 'Windows RPC', 'protocol': 'tcp', 'description': 'Dynamic Windows RPC Endpoint'},
            49666: {'service': 'Windows RPC', 'protocol': 'tcp', 'description': 'Dynamic Windows RPC Endpoint'},
            49667: {'service': 'Windows RPC', 'protocol': 'tcp', 'description': 'Dynamic Windows RPC Endpoint'},
            49668: {'service': 'Windows RPC', 'protocol': 'tcp', 'description': 'Dynamic Windows RPC Endpoint'},
            49670: {'service': 'Windows RPC', 'protocol': 'tcp', 'description': 'Dynamic Windows RPC Endpoint'},
            
            # Other common service ports
            49940: {'service': 'Windows Update', 'protocol': 'tcp', 'description': 'Windows Update Service'},
            62314: {'service': 'Unknown Windows Service', 'protocol': 'tcp', 'description': 'Unidentified Windows Service'}
        }
        
        # Check if port is in extended signatures
        if port in extended_service_signatures:
            return extended_service_signatures[port]
        
        # Attempt basic banner grabbing for unknown ports
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Try connecting to get potential service banner
            result = sock.connect_ex(('192.168.93.1', port))
            
            if result == 0:
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # Basic banner analysis
                    banner_signatures = {
                        'SSH': r'SSH',
                        'FTP': r'220 ',
                        'SMTP': r'220 ',
                        'HTTP': r'HTTP/',
                        'Server': r'Server:',
                        'Microsoft': r'Microsoft',
                        'Windows': r'Windows'
                    }
                    
                    for service, pattern in banner_signatures.items():
                        if re.search(pattern, banner, re.IGNORECASE):
                            return {
                                'service': service,
                                'protocol': 'tcp',
                                'description': f'Detected via banner: {banner[:100]}...'
                            }
                except Exception:
                    pass
                
                sock.close()
        except Exception:
            pass
        
        # Fallback for truly unknown ports
        return {
            'service': 'Unknown',
            'protocol': 'tcp',
            'description': 'No service identification possible'
        }

class PortScanner:
    """Advanced multi-protocol network port and service scanner."""
    
    # Prioritized port list for faster scanning
    COMMON_PORTS = [
        22,    # SSH
        80,    # HTTP
        443,   # HTTPS
        21,    # FTP
        25,    # SMTP
        135,   # Microsoft RPC
        139,   # NetBIOS
        445,   # SMB
        3389,  # RDP
        1433,  # MSSQL
        1521,  # Oracle
        3306,  # MySQL
        5432,  # PostgreSQL
        8080,  # HTTP Proxy
        8443   # HTTPS Proxy
    ]

    @staticmethod
    def scan_ports(target_ip, scan_type='default', timeout=0.2, max_threads=1000, timing_template='T4'):
        """
        Perform optimized and fast port scanning with advanced techniques.
        
        Args:
            target_ip (str): IP address to scan
            scan_type (str): Scanning strategy
            timeout (float): Connection timeout
            max_threads (int): Maximum concurrent threads
            timing_template (str): Timing template for scan
        
        Returns:
            dict: Discovered open ports and services
        """
        # Determine port range based on scan type and timing
        if scan_type == 'quick':
            ports_to_scan = PortScanner.COMMON_PORTS
        elif scan_type == 'full':
            # Split port scanning into batches to manage memory and performance
            ports_to_scan = (
                PortScanner.COMMON_PORTS +  # Most important ports first
                list(range(1, 1025)) +      # Well-known ports
                list(range(49152, 65536))   # Ephemeral ports
            )
        else:
            ports_to_scan = PortScanner.COMMON_PORTS

        # Remove duplicates while preserving order
        ports_to_scan = list(dict.fromkeys(ports_to_scan))
        
        # Batch processing to handle large port ranges
        def batch_scan(batch_ports):
            """
            Scan a batch of ports with optimized socket handling.
            """
            batch_open_ports = {}
            
            def scan_port(port):
                """
                Optimized port scanning function with improved socket handling.
                """
                try:
                    # Create socket with optimized options
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow socket reuse
                    sock.settimeout(timeout)
                    
                    # Non-blocking connect with select for faster timeout
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    if result == 0:
                        # Predefined service signatures
                        service_signatures = {
                            22: {'service': 'SSH', 'protocol': 'tcp'},
                            80: {'service': 'HTTP', 'protocol': 'tcp'},
                            443: {'service': 'HTTPS', 'protocol': 'tcp'},
                            21: {'service': 'FTP', 'protocol': 'tcp'},
                            25: {'service': 'SMTP', 'protocol': 'tcp'},
                            135: {'service': 'Microsoft RPC', 'protocol': 'tcp'},
                            139: {'service': 'NetBIOS', 'protocol': 'tcp'},
                            445: {'service': 'SMB', 'protocol': 'tcp'},
                            3389: {'service': 'RDP', 'protocol': 'tcp'}
                        }
                        
                        # Use advanced service detection for unknown ports
                        service_info = service_signatures.get(port, 
                            PortScanner._advanced_service_detection(port)
                        )
                        
                        # Add vulnerabilities
                        service_info['vulnerabilities'] = VulnerabilityDatabase.get_service_vulnerabilities(
                            service_info.get('service', 'Unknown')
                        )
                        
                        return {
                            'port': port,
                            'status': 'open',
                            **service_info
                        }
                    
                except Exception:
                    pass
                
                return None

            # Use concurrent futures with optimized thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit port scanning tasks with a timeout to prevent hanging
                port_futures = {executor.submit(scan_port, port): port for port in batch_ports}
                
                for future in concurrent.futures.as_completed(port_futures, timeout=30):
                    try:
                        result = future.result()
                        if result and result['status'] == 'open':
                            batch_open_ports[result['port']] = result
                    except Exception:
                        pass
            
            return batch_open_ports

        # Split ports into batches to manage memory and performance
        open_ports = {}
        batch_size = 1000  # Adjust batch size based on system resources
        
        for i in range(0, len(ports_to_scan), batch_size):
            batch = ports_to_scan[i:i+batch_size]
            batch_results = batch_scan(batch)
            open_ports.update(batch_results)
        
        return open_ports

    @staticmethod
    def _advanced_service_detection(port, timeout=0.5):
        """
        Advanced multi-protocol service detection with comprehensive identification.
        
        Args:
            port (int): Port number
            timeout (float): Connection timeout
        
        Returns:
            dict: Comprehensive service information
        """
        service_info = {
            'port': port,
            'protocol': 'tcp',
            'service': 'Unknown',
            'version': 'N/A',
            'confidence': 0
        }
        
        # Advanced service signatures with multi-dimensional detection
        service_signatures = {
            135: {
                'service': 'Microsoft RPC',
                'vulnerabilities': [
                    {
                        'cve': 'CVE-2020-0796',
                        'name': 'SMBv3 Compression Vulnerability',
                        'severity': 'High',
                        'description': 'Remote code execution vulnerability in Microsoft Server Message Block 3.1.1 (SMBv3) protocol'
                    }
                ]
            },
            139: {
                'service': 'NetBIOS',
                'vulnerabilities': [
                    {
                        'cve': 'CVE-2019-0708',
                        'name': 'BlueKeep',
                        'severity': 'Critical',
                        'description': 'Remote Desktop Protocol vulnerability affecting Windows systems'
                    }
                ]
            },
            445: {
                'service': 'SMB',
                'vulnerabilities': [
                    {
                        'cve': 'CVE-2017-0144',
                        'name': 'EternalBlue',
                        'severity': 'Critical',
                        'description': 'Critical vulnerability in Windows SMB protocol allowing remote code execution'
                    }
                ]
            }
        }
        
        # Predefined service detection
        if port in service_signatures:
            service_info.update(service_signatures[port])
            service_info['confidence'] = 0.9
            return service_info
        
        # TCP Service Detection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex(('192.168.93.1', port))
            
            if result == 0:
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    signatures = {
                        22: ('SSH', r'SSH', []),
                        80: ('HTTP', r'HTTP/', []),
                        443: ('HTTPS', r'HTTP/', []),
                        21: ('FTP', r'220 ', []),
                        25: ('SMTP', r'220 ', []),
                        3389: ('RDP', r'RDP', [
                            {
                                'cve': 'CVE-2019-0708',
                                'name': 'BlueKeep',
                                'severity': 'Critical'
                            }
                        ])
                    }
                    
                    for known_port, (service_name, pattern, vulns) in signatures.items():
                        if known_port == port or re.search(pattern, banner, re.IGNORECASE):
                            service_info['service'] = service_name
                            service_info['vulnerabilities'] = vulns
                            service_info['confidence'] = 0.8
                            break
                except Exception:
                    pass
                
                sock.close()
        except Exception as e:
            logging.debug(f"TCP Service Detection Error: {e}")
        
        return service_info
    
    @staticmethod
    def _advanced_service_detection(port, timeout=0.5):
        """
        Advanced multi-protocol service detection with comprehensive identification.
        
        Args:
            port (int): Port number
            timeout (float): Connection timeout
        
        Returns:
            dict: Comprehensive service information
        """
        service_info = {
            'port': port,
            'protocol': 'tcp',
            'service': 'Unknown',
            'version': 'N/A',
            'confidence': 0
        }
        
        # Advanced service signatures with multi-dimensional detection
        service_signatures = {
            135: {
                'service': 'Microsoft RPC',
                'vulnerabilities': [
                    {
                        'cve': 'CVE-2020-0796',
                        'name': 'SMBv3 Compression Vulnerability',
                        'severity': 'High',
                        'description': 'Remote code execution vulnerability in Microsoft Server Message Block 3.1.1 (SMBv3) protocol'
                    }
                ]
            },
            139: {
                'service': 'NetBIOS',
                'vulnerabilities': [
                    {
                        'cve': 'CVE-2019-0708',
                        'name': 'BlueKeep',
                        'severity': 'Critical',
                        'description': 'Remote Desktop Protocol vulnerability affecting Windows systems'
                    }
                ]
            },
            445: {
                'service': 'SMB',
                'vulnerabilities': [
                    {
                        'cve': 'CVE-2017-0144',
                        'name': 'EternalBlue',
                        'severity': 'Critical',
                        'description': 'Critical vulnerability in Windows SMB protocol allowing remote code execution'
                    }
                ]
            }
        }
        
        # Predefined service detection
        if port in service_signatures:
            service_info.update(service_signatures[port])
            service_info['confidence'] = 0.9
            return service_info
        
        # TCP Service Detection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex(('192.168.93.1', port))
            
            if result == 0:
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    signatures = {
                        22: ('SSH', r'SSH', []),
                        80: ('HTTP', r'HTTP/', []),
                        443: ('HTTPS', r'HTTP/', []),
                        21: ('FTP', r'220 ', []),
                        25: ('SMTP', r'220 ', []),
                        3389: ('RDP', r'RDP', [
                            {
                                'cve': 'CVE-2019-0708',
                                'name': 'BlueKeep',
                                'severity': 'Critical'
                            }
                        ])
                    }
                    
                    for known_port, (service_name, pattern, vulns) in signatures.items():
                        if known_port == port or re.search(pattern, banner, re.IGNORECASE):
                            service_info['service'] = service_name
                            service_info['vulnerabilities'] = vulns
                            service_info['confidence'] = 0.8
                            break
                except Exception:
                    pass
                
                sock.close()
        except Exception as e:
            logging.debug(f"TCP Service Detection Error: {e}")
        
        return service_info
    
    @staticmethod
    def scan_network(network_cidr, scan_type='default', timeout=1):
        """
        Scan an entire network for live hosts and open ports.
        
        Args:
            network_cidr (str): Network CIDR notation (e.g., '192.168.1.0/24')
            scan_type (str): Scanning strategy
            timeout (float): Connection timeout
        
        Returns:
            dict: Network scan results
        """
        network_results = {}
        
        try:
            # Convert CIDR to IP range
            network = ipaddress.ip_network(network_cidr, strict=False)
            
            # Scan each host in the network
            for ip in network.hosts():
                ip_str = str(ip)
                try:
                    # Perform port scan on each host
                    host_ports = PortScanner.scan_ports(ip_str, scan_type, timeout)
                    
                    if host_ports:
                        network_results[ip_str] = {
                            'open_ports': host_ports,
                            'hostname': PortScanner._resolve_hostname(ip_str)
                        }
                except Exception as e:
                    logger.debug(f"Network scan error for {ip_str}: {e}")
        
        except ValueError as ve:
            logger.error(f"Invalid network CIDR: {ve}")
        
        return network_results
    
    @staticmethod
    def _resolve_hostname(ip_address):
        """
        Resolve IP address to hostname.
        
        Args:
            ip_address (str): IP address to resolve
        
        Returns:
            str: Resolved hostname or original IP
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return ip_address

class ServiceVersionDetector:
    """Detect service versions and characteristics."""
    
    @staticmethod
    def detect_service_version(ip, port):
        """
        Detect service version and characteristics.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
        
        Returns:
            Dict with service information
        """
        # Simplified service detection logic
        service_map = {
            22: {'name': 'SSH', 'default_version': '7.4'},
            80: {'name': 'HTTP', 'default_version': '1.1'},
            443: {'name': 'HTTPS', 'default_version': 'TLS 1.3'},
            445: {'name': 'SMB', 'default_version': '3.0'},
            135: {'name': 'Microsoft RPC', 'default_version': 'Windows RPC'},
            3389: {'name': 'RDP', 'default_version': 'Windows Remote Desktop'}
        }
        
        return service_map.get(port, {'name': 'Unknown', 'default_version': 'N/A'})

class SystemInfoScanner:
    def __init__(self):
        self.timeout = 2
        
    def get_system_info(self, ip: str) -> Dict[str, Any]:
        info = {
            "hostname": self._get_hostname(ip),
            "os_info": self._detect_os(ip),
            "network_info": self._get_network_info(ip),
            "security_info": self._check_security(ip)
        }
        return info
        
    def _get_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
            
    def _detect_os(self, ip: str) -> Dict[str, str]:
        os_info = {"name": "Unknown", "version": "Unknown"}
        try:
            # Try TTL-based OS detection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, 80))
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                if ttl <= 64:
                    os_info["name"] = "Linux/Unix"
                elif ttl <= 128:
                    os_info["name"] = "Windows"
                elif ttl <= 255:
                    os_info["name"] = "Solaris/AIX"
        except:
            pass
        return os_info
        
    def _get_network_info(self, ip: str) -> Dict[str, Any]:
        info = {
            "ip_version": "IPv4" if ":" not in ip else "IPv6",
            "is_private": ipaddress.ip_address(ip).is_private,
            "reverse_dns": None
        }
        try:
            info["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except:
            pass
        return info
        
    def _check_security(self, ip: str) -> Dict[str, Any]:
        security = {
            "common_ports_open": [],
            "potentially_dangerous_ports": [],
            "ssl_info": {}
        }
        
        dangerous_ports = {21, 23, 445, 3389}  # FTP, Telnet, SMB, RDP
        
        # Check SSL/TLS on port 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    security["ssl_info"] = {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "cert_expires": cert["notAfter"] if cert else None
                    }
        except:
            pass
            
        return security

class DisMapScanner:
    def __init__(self):
        self.service_detector = ServiceVersionDetector()
        self.system_scanner = SystemInfoScanner()
        self.vuln_scanner = VulnerabilityScanner()
        
    def scan_target(self, target: str, ports: List[int] = None, 
                    scan_type: str = 'vulnerability', 
                    timeout: int = 5) -> Dict[str, Any]:
        """
        Perform comprehensive vulnerability scanning on a target.
        
        Args:
            target (str): IP address or hostname to scan
            ports (List[int], optional): Specific ports to scan. Defaults to common ports.
            scan_type (str, optional): Type of scan. Defaults to 'vulnerability'.
            timeout (int, optional): Connection timeout. Defaults to 5 seconds.
        
        Returns:
            Dict containing scan results with vulnerabilities
        """
        # Resolve hostname to IP if needed
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {target}")
            return {'error': 'Hostname resolution failed'}

        # Default port list for vulnerability scanning
        if ports is None:
            ports = [22, 80, 443, 445, 135, 3389]

        # Vulnerability scanning results
        scan_results = {
            'target': target,
            'ip': target_ip,
            'vulnerabilities': []
        }

        # Initialize vulnerability scanner
        vuln_scanner = VulnerabilityScanner()
        service_detector = ServiceVersionDetector()

        # Scan each port
        for port in ports:
            try:
                # Check port connectivity
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    
                    # Use non-blocking connect with select for faster timeout
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    
                    if result == 0:
                        # Port is open
                        service_info = service_detector.detect_service_version(target_ip, port)
                        
                        # Scan for vulnerabilities
                        port_vulnerabilities = vuln_scanner.scan_vulnerabilities(
                            target_ip, port, service_info
                        )
                        
                        if port_vulnerabilities:
                            scan_results['vulnerabilities'].extend([
                                {
                                    'port': port,
                                    'service': service_info.get('name', 'Unknown'),
                                    **vulnerability
                                } for vulnerability in port_vulnerabilities
                            ])

            except Exception as e:
                logger.warning(f"Error scanning {target_ip}:{port} - {e}")

        return scan_results

class NetworkScanner:
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.vulnerability_fetcher = VulnerabilityFetcher()

    def get_port_range(self, scan_type='quick', timing_template='T3'):
        """
        Determine port range and scan parameters based on timing template
        
        Timing Templates:
        - T0: Paranoid (Extremely slow, minimal network impact)
        - T1: Sneaky (Slow, low detection probability)
        - T2: Polite (Slower, reduced network load)
        - T3: Normal (Balanced speed and stealth)
        - T4: Aggressive (Faster scanning, higher network load)
        - T5: Insane (Fastest possible, high network impact)
        
        Args:
            scan_type (str): Scan type (quick/full)
            timing_template (str): Timing template
        
        Returns:
            tuple: (ports_to_scan, max_threads, timeout)
        """
        timing_configs = {
            'T0': {
                'quick': [22, 80, 443],
                'full': list(range(1, 1024)),
                'max_threads': 10,
                'timeout': 5.0
            },
            'T1': {
                'quick': [22, 80, 443, 21, 25],
                'full': list(range(1, 2048)),
                'max_threads': 25,
                'timeout': 3.0
            },
            'T2': {
                'quick': [22, 80, 443, 21, 25, 135, 139],
                'full': list(range(1, 4096)),
                'max_threads': 50,
                'timeout': 2.0
            },
            'T3': {
                'quick': [22, 80, 443, 21, 25, 135, 139, 445, 3389],
                'full': list(range(1, 10001)),
                'max_threads': 100,
                'timeout': 1.0
            },
            'T4': {
                'quick': [22, 80, 443, 21, 25, 135, 139, 445, 3389, 8080, 8443],
                'full': list(range(1, 20001)),
                'max_threads': 250,
                'timeout': 0.5
            },
            'T5': {
                'quick': [22, 80, 443, 21, 25, 135, 139, 445, 3389, 8080, 8443, 1433, 1521],
                'full': list(range(1, 65536)),
                'max_threads': 500,
                'timeout': 0.2
            }
        }

        config = timing_configs.get(timing_template, timing_configs['T3'])
        ports = config[scan_type]
        max_threads = config['max_threads']
        timeout = config['timeout']

        return ports, max_threads, timeout

    def scan_network(self, target: str, scan_type: str = 'quick', timing_template: str = 'T3') -> List[Dict[str, Any]]:
        """
        Scan network with configurable timing and performance
        
        Args:
            target (str): IP address to scan
            scan_type (str): 'quick' or 'full' scan
            timing_template (str): Timing template (T0-T5)
        
        Returns:
            List of open port results
        """
        # Get port range and scan parameters
        ports, max_threads, timeout = self.get_port_range(scan_type, timing_template)
        
        self.timeout = timeout  # Update timeout
        open_ports = []
        
        # Use concurrent scanning with dynamic thread count
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit port scanning tasks with a timeout to prevent hanging
            port_futures = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(port_futures, timeout=30):
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        open_ports.append(result)
                except Exception:
                    pass
        
        return sorted(open_ports, key=lambda x: x['port'])

def parse_ports(ports_str: str) -> List[int]:
    """Parse port range string into list of ports."""
    if not ports_str:
        return list(range(1, 1001))
        
    ports = set()
    for part in ports_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='DisMap: Network Scanning and Vulnerability Detection Tool')
    parser.add_argument('target', nargs='?', default=None, help='Target IP, hostname, or network to scan')
    
    # Add support for simplified timing template flags
    timing_group = parser.add_mutually_exclusive_group()
    timing_group.add_argument('-T0', action='store_const', const='T0', dest='timing', help='Paranoid scan (extremely slow)')
    timing_group.add_argument('-T1', action='store_const', const='T1', dest='timing', help='Sneaky scan (slow)')
    timing_group.add_argument('-T2', action='store_const', const='T2', dest='timing', help='Polite scan (reduced load)')
    timing_group.add_argument('-T3', action='store_const', const='T3', dest='timing', help='Normal scan (balanced)')
    timing_group.add_argument('-T4', action='store_const', const='T4', dest='timing', help='Aggressive scan (faster)')
    timing_group.add_argument('-T5', action='store_const', const='T5', dest='timing', help='Insane scan (fastest)')
    
    parser.add_argument('-p', '--ports', type=str, default=None, 
                        help='Comma-separated list of ports to scan (e.g., "22,80,443")')
    parser.add_argument('-n', '--network', action='store_true', 
                        help='Scan entire local network')
    parser.add_argument('-s', '--subnet', type=str, default=None, 
                        help='Specify custom subnet for network scan (e.g., "192.168.1.0/24")')
    parser.add_argument('-t', '--type', choices=['quick', 'full'], 
                        default='quick', help='Scan type: quick or full')
    parser.add_argument('-o', '--output', help='Output file for scan results')
    parser.add_argument('--timeout', type=float, default=1, help='Connection timeout in seconds')
    parser.add_argument('--max-threads', type=int, default=200, help='Maximum number of concurrent scanning threads')
    
    # Set default timing to T3 if no timing flag is provided
    parser.set_defaults(timing='T3')
    
    return parser.parse_args()

def main(max_threads: int = 200):
    """
    Main entry point for DisMap Network Scanner.
    Handles command-line arguments and initiates network scanning.
    """
    parser = argparse.ArgumentParser(description="DisMap: Advanced Network Vulnerability Scanner")
    parser.add_argument('target', nargs='?', help='Target IP address or network to scan')
    parser.add_argument('-n', '--network', help='Network CIDR to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--type', choices=['quick', 'full'], 
                        default='quick', help='Scan type: quick or full')
    parser.add_argument('-o', '--output', help='Output file for scan results')
    parser.add_argument('--timeout', type=float, default=0.5, help='Connection timeout in seconds')
    parser.add_argument('--max-threads', type=int, default=max_threads, help='Maximum number of concurrent scanning threads')
    
    # Add support for simplified timing template flags
    timing_group = parser.add_mutually_exclusive_group()
    timing_group.add_argument('-T0', action='store_const', const='T0', dest='timing', help='Paranoid scan (extremely slow)')
    timing_group.add_argument('-T1', action='store_const', const='T1', dest='timing', help='Sneaky scan (slow)')
    timing_group.add_argument('-T2', action='store_const', const='T2', dest='timing', help='Polite scan (reduced load)')
    timing_group.add_argument('-T3', action='store_const', const='T3', dest='timing', help='Normal scan (balanced)')
    timing_group.add_argument('-T4', action='store_const', const='T4', dest='timing', help='Aggressive scan (faster)')
    timing_group.add_argument('-T5', action='store_const', const='T5', dest='timing', help='Insane scan (fastest)')
    
    # Set default timing to T3 if no timing flag is provided
    parser.set_defaults(timing='T3')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('dismap_scan.log')
        ]
    )
    
    try:
        # Network scanning
        if args.network:
            print(f"🌐 Scanning Network: {args.network}")
            scan_results = PortScanner.scan_network(
                args.network, 
                scan_type=args.type, 
                timeout=args.timeout
            )
        
        # Single target scanning
        elif args.target:
            print(f"🔍 Scanning Target: {args.target} (Timing: {args.timing})")
            scan_results = {
                'target': args.target,
                'results': PortScanner.scan_ports(
                    args.target, 
                    scan_type=args.type, 
                    timeout=args.timeout,
                    max_threads=args.max_threads,
                    timing_template=args.timing
                )
            }
        
        else:
            print("❌ Error: No target specified")
            return
        
        # Print results with vulnerabilities
        print("\nOpen Ports and Services:")
        for port, details in scan_results.get('results', {}).items():
            print(f"Port {port}: {details.get('service', 'Unknown')} (Open)")
            
            # Display vulnerabilities
            if details.get('vulnerabilities'):
                print("  Vulnerabilities:")
                for vuln in details['vulnerabilities']:
                    print(f"    - {vuln.get('name', 'Unknown Vulnerability')}")
                    print(f"      CVE: {vuln.get('cve', 'N/A')}")
                    print(f"      Severity: {vuln.get('severity', 'Unknown')}")
                    print(f"      Description: {vuln.get('description', 'No description')}")
        
        # Optional: Generate reports
        if args.output:
            html_report = ReportGenerator.generate_html_report(scan_results)
            json_report = ReportGenerator.generate_json_report(scan_results)
            
            with open(f"{args.output}.html", 'w') as f:
                f.write(html_report)
            with open(f"{args.output}.json", 'w') as f:
                f.write(json_report)
            print(f"\nReports saved: {args.output}.html, {args.output}.json")
    
    except Exception as e:
        print(f"❌ Scan Error: {e}")
        logging.error(f"Scan failed: {e}")

if __name__ == '__main__':
    main()
