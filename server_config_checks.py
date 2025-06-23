#!/usr/bin/env python3
"""
Owner: Abdul Mannan aka ShaheenUX
Social Handles: github.com/shaheenUX , instagram.com/shaheen_hacker , linktr.ee/shaheen_hacker
WebCrackerUX v1.O - SERVER CONFIGURATION CHECKS
Description: 
  Comprehensive server configuration vulnerability scanner covering 10 attack vectors
  with advanced detection techniques and security header analysis.
  
"""

import os
import sys
import re
import json
import time
import socket
import ssl
import requests
import urllib.parse
import dns.resolver
from bs4 import BeautifulSoup
from colorama import Fore, Style
from config import TARGET_DOMAIN, BASE_URL, HTTPS_URL, USER_AGENT, REQUEST_TIMEOUT

# Global configuration
REPORT_FILE = "reports/server_config_report.txt"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

class ServerConfigScanner:
    def __init__(self):
        self.target = BASE_URL
        self.https_target = HTTPS_URL
        self.results = []
        self.server_info = {}
        self.cipher_info = {}
        
    def _check_http_headers(self):
        """Check for missing security headers and misconfigurations"""
        print(f"{Fore.CYAN}[*] Checking HTTP security headers...{Style.RESET_ALL}")
        
        required_headers = {
            "Strict-Transport-Security": {
                "description": "Enforces secure (HTTPS) connections to the server",
                "severity": "High"
            },
            "X-Content-Type-Options": {
                "description": "Prevents MIME type sniffing",
                "severity": "Medium"
            },
            "X-Frame-Options": {
                "description": "Protects against clickjacking attacks",
                "severity": "Medium"
            },
            "Content-Security-Policy": {
                "description": "Prevents XSS and other code injection attacks",
                "severity": "High"
            },
            "X-XSS-Protection": {
                "description": "Enables XSS filtering in browsers",
                "severity": "Medium"
            },
            "Referrer-Policy": {
                "description": "Controls referrer information in requests",
                "severity": "Low"
            },
            "Feature-Policy": {
                "description": "Controls which browser features can be used",
                "severity": "Low"
            },
            "Permissions-Policy": {
                "description": "Replaces Feature-Policy, controls browser features",
                "severity": "Low"
            }
        }
        
        try:
            response = SESSION.get(self.https_target if self.https_target.startswith('http') else self.target)
            headers = response.headers
            
            for header, info in required_headers.items():
                if header not in headers:
                    self.results.append({
                        "vulnerability": f"Missing Security Header: {header}",
                        "severity": info["severity"],
                        "description": info["description"],
                        "recommendation": f"Add {header} header with appropriate value"
                    })
                    print(f"{Fore.RED}[-] Missing header: {header}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Found header: {header}{Style.RESET_ALL}")
                    
                    # Additional checks for specific headers
                    if header == "Strict-Transport-Security":
                        if "max-age=0" in headers[header]:
                            self.results.append({
                                "vulnerability": "Insecure HSTS Configuration",
                                "severity": "High",
                                "description": "HSTS header includes max-age=0 which disables HSTS",
                                "recommendation": "Set max-age to at least 31536000 (1 year)"
                            })
                            print(f"{Fore.RED}[-] Insecure HSTS configuration{Style.RESET_ALL}")
                    
                    if header == "X-Frame-Options":
                        if headers[header].lower() != "deny" and "sameorigin" not in headers[header].lower():
                            self.results.append({
                                "vulnerability": "Insecure X-Frame-Options Configuration",
                                "severity": "Medium",
                                "description": "X-Frame-Options should be set to 'DENY' or 'SAMEORIGIN'",
                                "recommendation": "Update X-Frame-Options to 'DENY' or 'SAMEORIGIN'"
                            })
                            print(f"{Fore.RED}[-] Insecure X-Frame-Options configuration{Style.RESET_ALL}")
                    
                    if header == "Content-Security-Policy":
                        if "unsafe-inline" in headers[header] or "unsafe-eval" in headers[header]:
                            self.results.append({
                                "vulnerability": "Insecure CSP Configuration",
                                "severity": "Medium",
                                "description": "CSP contains unsafe directives (unsafe-inline or unsafe-eval)",
                                "recommendation": "Remove unsafe directives from CSP"
                            })
                            print(f"{Fore.RED}[-] Insecure CSP configuration{Style.RESET_ALL}")
            
            # Check for server information leakage
            server_header = headers.get("Server", "")
            if server_header:
                self.server_info["Server"] = server_header
                print(f"{Fore.YELLOW}[~] Server header: {server_header}{Style.RESET_ALL}")
                if any(x in server_header.lower() for x in ["version", "build", "details"]):
                    self.results.append({
                        "vulnerability": "Server Information Leakage",
                        "severity": "Low",
                        "description": f"Server header reveals version information: {server_header}",
                        "recommendation": "Remove or obfuscate server version information"
                    })
                    print(f"{Fore.RED}[-] Server version information exposed{Style.RESET_ALL}")
            
            x_powered_by = headers.get("X-Powered-By", "")
            if x_powered_by:
                self.server_info["X-Powered-By"] = x_powered_by
                print(f"{Fore.YELLOW}[~] X-Powered-By: {x_powered_by}{Style.RESET_ALL}")
                self.results.append({
                    "vulnerability": "X-Powered-By Header Present",
                    "severity": "Low",
                    "description": f"X-Powered-By header reveals technology stack: {x_powered_by}",
                    "recommendation": "Remove X-Powered-By header"
                })
                print(f"{Fore.RED}[-] X-Powered-By header exposes technology stack{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking headers: {e}{Style.RESET_ALL}")
    
    def _check_tls_configuration(self):
        """Check for TLS/SSL misconfigurations and vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking TLS/SSL configuration...{Style.RESET_ALL}")
        
        if not self.https_target.startswith("https://"):
            print(f"{Fore.YELLOW}[!] No HTTPS target configured{Style.RESET_ALL}")
            return
        
        hostname = TARGET_DOMAIN
        port = 443
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Establish connection
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Store cipher info
                    self.cipher_info = {
                        "Version": cipher[1],
                        "Cipher": cipher[0],
                        "Protocol": cipher[2]
                    }
                    
                    print(f"{Fore.YELLOW}[~] TLS Protocol: {cipher[2]}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[~] Cipher Suite: {cipher[0]}{Style.RESET_ALL}")
                    
                    # Check for weak protocols
                    if cipher[2] in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        self.results.append({
                            "vulnerability": "Weak TLS Protocol",
                            "severity": "High",
                            "description": f"Server supports insecure protocol: {cipher[2]}",
                            "recommendation": "Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1"
                        })
                        print(f"{Fore.RED}[-] Insecure protocol supported: {cipher[2]}{Style.RESET_ALL}")
                    
                    # Check for weak ciphers
                    weak_ciphers = [
                        "RC4", "DES", "3DES", "MD5", "SHA1", "CBC", "NULL", "EXPORT", 
                        "ANON", "ADH", "AECDH", "PSK", "SRP", "CAMELLIA", "SEED", "IDEA"
                    ]
                    if any(cipher in cipher[0] for cipher in weak_ciphers):
                        self.results.append({
                            "vulnerability": "Weak Cipher Suite",
                            "severity": "High",
                            "description": f"Server supports weak cipher: {cipher[0]}",
                            "recommendation": "Disable weak ciphers and prefer AES-GCM with ECDHE"
                        })
                        print(f"{Fore.RED}[-] Weak cipher supported: {cipher[0]}{Style.RESET_ALL}")
                    
                    # Check certificate validity
                    cert_expires = ssl.cert_time_to_seconds(cert['notAfter'])
                    current_time = time.time()
                    days_remaining = (cert_expires - current_time) / 86400
                    
                    print(f"{Fore.YELLOW}[~] Certificate expires in {int(days_remaining)} days{Style.RESET_ALL}")
                    
                    if days_remaining < 30:
                        self.results.append({
                            "vulnerability": "Certificate Expiring Soon",
                            "severity": "Medium",
                            "description": f"Certificate expires in {int(days_remaining)} days",
                            "recommendation": "Renew SSL certificate before expiration"
                        })
                        print(f"{Fore.RED}[-] Certificate expiring soon{Style.RESET_ALL}")
                    
                    # Check for self-signed certificate
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    if issuer == subject:
                        self.results.append({
                            "vulnerability": "Self-Signed Certificate",
                            "severity": "Medium",
                            "description": "Server uses self-signed SSL certificate",
                            "recommendation": "Replace with certificate from trusted CA"
                        })
                        print(f"{Fore.RED}[-] Self-signed certificate detected{Style.RESET_ALL}")
                    
        except ssl.SSLError as e:
            self.results.append({
                "vulnerability": "SSL/TLS Error",
                "severity": "High",
                "description": f"SSL/TLS connection failed: {str(e)}",
                "recommendation": "Check server SSL configuration"
            })
            print(f"{Fore.RED}[-] SSL/TLS connection error: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking TLS configuration: {e}{Style.RESET_ALL}")
    
    def _check_dns_security(self):
        """Check DNS configuration for security issues"""
        print(f"{Fore.CYAN}[*] Checking DNS configuration...{Style.RESET_ALL}")
        
        try:
            # Check for DNSSEC
            try:
                answers = dns.resolver.resolve(TARGET_DOMAIN, 'DNSKEY')
                print(f"{Fore.GREEN}[+] DNSSEC enabled{Style.RESET_ALL}")
            except:
                self.results.append({
                    "vulnerability": "DNSSEC Not Enabled",
                    "severity": "Medium",
                    "description": "DNSSEC is not enabled for this domain",
                    "recommendation": "Enable DNSSEC to prevent DNS spoofing"
                })
                print(f"{Fore.RED}[-] DNSSEC not enabled{Style.RESET_ALL}")
            
            # Check for DMARC
            try:
                answers = dns.resolver.resolve(f'_dmarc.{TARGET_DOMAIN}', 'TXT')
                dmarc_found = any('DMARC1' in str(r) for r in answers)
                if dmarc_found:
                    print(f"{Fore.GREEN}[+] DMARC record found{Style.RESET_ALL}")
                else:
                    self.results.append({
                        "vulnerability": "DMARC Not Configured",
                        "severity": "Medium",
                        "description": "No DMARC record found for domain",
                        "recommendation": "Configure DMARC policy to prevent email spoofing"
                    })
                    print(f"{Fore.RED}[-] DMARC not configured{Style.RESET_ALL}")
            except:
                self.results.append({
                    "vulnerability": "DMARC Not Configured",
                    "severity": "Medium",
                    "description": "No DMARC record found for domain",
                    "recommendation": "Configure DMARC policy to prevent email spoofing"
                })
                print(f"{Fore.RED}[-] DMARC not configured{Style.RESET_ALL}")
            
            # Check for DKIM
            common_dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'dkim']
            dkim_found = False
            for selector in common_dkim_selectors:
                try:
                    answers = dns.resolver.resolve(f'{selector}._domainkey.{TARGET_DOMAIN}', 'TXT')
                    if any('DKIM1' in str(r) for r in answers):
                        dkim_found = True
                        break
                except:
                    continue
            
            if dkim_found:
                print(f"{Fore.GREEN}[+] DKIM record found{Style.RESET_ALL}")
            else:
                self.results.append({
                    "vulnerability": "DKIM Not Configured",
                    "severity": "Medium",
                    "description": "No DKIM record found for domain",
                    "recommendation": "Configure DKIM to authenticate email messages"
                })
                print(f"{Fore.RED}[-] DKIM not configured{Style.RESET_ALL}")
            
            # Check for SPF
            try:
                answers = dns.resolver.resolve(TARGET_DOMAIN, 'TXT')
                spf_found = any('v=spf1' in str(r).lower() for r in answers)
                if spf_found:
                    print(f"{Fore.GREEN}[+] SPF record found{Style.RESET_ALL}")
                else:
                    self.results.append({
                        "vulnerability": "SPF Not Configured",
                        "severity": "Medium",
                        "description": "No SPF record found for domain",
                        "recommendation": "Configure SPF to prevent email spoofing"
                    })
                    print(f"{Fore.RED}[-] SPF not configured{Style.RESET_ALL}")
            except:
                self.results.append({
                    "vulnerability": "SPF Not Configured",
                    "severity": "Medium",
                    "description": "No SPF record found for domain",
                    "recommendation": "Configure SPF to prevent email spoofing"
                })
                print(f"{Fore.RED}[-] SPF not configured{Style.RESET_ALL}")
            
            # Check for open DNS resolvers
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(TARGET_DOMAIN)]
                resolver.resolve('google.com')
                self.results.append({
                    "vulnerability": "Open DNS Resolver",
                    "severity": "Medium",
                    "description": "Server allows recursive DNS queries from external clients",
                    "recommendation": "Restrict recursive DNS queries to authorized clients only"
                })
                print(f"{Fore.RED}[-] Open DNS resolver detected{Style.RESET_ALL}")
            except:
                print(f"{Fore.GREEN}[+] No open DNS resolver detected{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking DNS configuration: {e}{Style.RESET_ALL}")
    
    def _check_directory_listing(self):
        """Check for directory listing vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking for directory listing...{Style.RESET_ALL}")
        
        common_dirs = [
            "images", "img", "assets", "static", "uploads", 
            "files", "docs", "backup", "admin", "tmp"
        ]
        
        vulnerable = False
        
        for directory in common_dirs:
            try:
                url = f"{self.target}{directory}/"
                response = SESSION.get(url)
                
                # Check for directory listing indicators
                if ("Index of /" in response.text or 
                    "Directory listing for /" in response.text or
                    "<title>Directory Listing</title>" in response.text or
                    "<h1>Directory Listing</h1>" in response.text):
                    vulnerable = True
                    self.results.append({
                        "vulnerability": "Directory Listing Enabled",
                        "severity": "Medium",
                        "description": f"Directory listing enabled at {url}",
                        "recommendation": "Disable directory listing in server configuration"
                    })
                    print(f"{Fore.RED}[-] Directory listing enabled at {url}{Style.RESET_ALL}")
            except Exception:
                continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No directory listing vulnerabilities detected{Style.RESET_ALL}")
    
    def _check_http_methods(self):
        """Check for dangerous HTTP methods"""
        print(f"{Fore.CYAN}[*] Checking allowed HTTP methods...{Style.RESET_ALL}")
        
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
        allowed_methods = []
        
        try:
            # Use OPTIONS to check allowed methods
            response = SESSION.options(self.target)
            if "Allow" in response.headers:
                allowed_methods = response.headers["Allow"].split(", ")
                print(f"{Fore.YELLOW}[~] Allowed methods: {', '.join(allowed_methods)}{Style.RESET_ALL}")
                
                for method in dangerous_methods:
                    if method in allowed_methods:
                        self.results.append({
                            "vulnerability": f"Dangerous HTTP Method Allowed: {method}",
                            "severity": "Medium",
                            "description": f"Server allows {method} method which could be abused",
                            "recommendation": f"Disable {method} method unless absolutely required"
                        })
                        print(f"{Fore.RED}[-] Dangerous method allowed: {method}{Style.RESET_ALL}")
            
            # Test each method directly if OPTIONS not available
            else:
                for method in dangerous_methods:
                    try:
                        response = SESSION.request(method, self.target)
                        if response.status_code != 405:  # 405 is Method Not Allowed
                            allowed_methods.append(method)
                            self.results.append({
                                "vulnerability": f"Dangerous HTTP Method Allowed: {method}",
                                "severity": "Medium",
                                "description": f"Server allows {method} method which could be abused",
                                "recommendation": f"Disable {method} method unless absolutely required"
                            })
                            print(f"{Fore.RED}[-] Dangerous method allowed: {method}{Style.RESET_ALL}")
                    except Exception:
                        continue
            
            if not any(m in allowed_methods for m in dangerous_methods):
                print(f"{Fore.GREEN}[+] No dangerous HTTP methods allowed{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking HTTP methods: {e}{Style.RESET_ALL}")
    
    def _check_cors_misconfig(self):
        """Check for CORS misconfigurations"""
        print(f"{Fore.CYAN}[*] Checking CORS configuration...{Style.RESET_ALL}")
        
        try:
            # Test with Origin header
            headers = {"Origin": "https://attacker.com"}
            response = SESSION.get(self.target, headers=headers)
            
            cors_headers = response.headers.get("Access-Control-Allow-Origin", "")
            cors_creds = response.headers.get("Access-Control-Allow-Credentials", "")
            
            if cors_headers:
                print(f"{Fore.YELLOW}[~] CORS headers detected{Style.RESET_ALL}")
                
                # Check for overly permissive CORS
                if cors_headers == "*":
                    self.results.append({
                        "vulnerability": "Overly Permissive CORS",
                        "severity": "Medium",
                        "description": "Access-Control-Allow-Origin set to '*'",
                        "recommendation": "Avoid using '*' and specify trusted origins"
                    })
                    print(f"{Fore.RED}[-] Overly permissive CORS (Allow-Origin: *){Style.RESET_ALL}")
                
                # Check if credentials allowed with wildcard
                if cors_headers == "*" and cors_creds.lower() == "true":
                    self.results.append({
                        "vulnerability": "Insecure CORS with Credentials",
                        "severity": "High",
                        "description": "Credentials allowed with wildcard origin",
                        "recommendation": "Never combine Access-Control-Allow-Credentials with wildcard origin"
                    })
                    print(f"{Fore.RED}[-] Insecure CORS with credentials and wildcard origin{Style.RESET_ALL}")
                
                # Check if reflects arbitrary origin
                if "attacker.com" in cors_headers:
                    self.results.append({
                        "vulnerability": "Origin Reflection CORS",
                        "severity": "High",
                        "description": "Server reflects arbitrary Origin header in Access-Control-Allow-Origin",
                        "recommendation": "Validate and whitelist trusted origins"
                    })
                    print(f"{Fore.RED}[-] Origin reflection vulnerability in CORS{Style.RESET_ALL}")
                
                # Check for null origin
                headers = {"Origin": "null"}
                response = SESSION.get(self.target, headers=headers)
                if response.headers.get("Access-Control-Allow-Origin") == "null":
                    self.results.append({
                        "vulnerability": "Null Origin CORS",
                        "severity": "Medium",
                        "description": "Server allows null origin in CORS",
                        "recommendation": "Disable CORS for null origin"
                    })
                    print(f"{Fore.RED}[-] Null origin allowed in CORS{Style.RESET_ALL}")
            
            else:
                print(f"{Fore.GREEN}[+] No CORS headers detected{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking CORS configuration: {e}{Style.RESET_ALL}")
    
    def _check_security_txt(self):
        """Check for security.txt file"""
        print(f"{Fore.CYAN}[*] Checking for security.txt...{Style.RESET_ALL}")
        
        locations = [
            "/.well-known/security.txt",
            "/security.txt",
            "/.well-known/security.txt.sig"
        ]
        
        found = False
        
        for location in locations:
            try:
                response = SESSION.get(f"{self.target}{location}")
                if response.status_code == 200 and "security" in response.text.lower():
                    found = True
                    print(f"{Fore.GREEN}[+] Found security.txt at {location}{Style.RESET_ALL}")
                    break
            except Exception:
                continue
        
        if not found:
            self.results.append({
                "vulnerability": "Missing security.txt",
                "severity": "Low",
                "description": "No security.txt file found",
                "recommendation": "Add security.txt to /.well-known/ with security contact information"
            })
            print(f"{Fore.RED}[-] No security.txt file found{Style.RESET_ALL}")
    
    def _check_exposed_files(self):
        """Check for commonly exposed files"""
        print(f"{Fore.CYAN}[*] Checking for exposed files...{Style.RESET_ALL}")
        
        common_files = [
            "/.git/config", "/.env", "/.htaccess", "/.htpasswd",
            "/web.config", "/phpinfo.php", "/info.php", "/test.php",
            "/package.json", "/composer.json", "/config.json",
            "/backup.zip", "/dump.sql", "/database.sql",
            "/adminer.php", "/phpMyAdmin/index.php",
            "/server-status", "/server-info"
        ]
        
        vulnerable = False
        
        for file_path in common_files:
            try:
                response = SESSION.get(f"{self.target}{file_path}")
                
                # Check for sensitive file indicators
                if response.status_code == 200:
                    sensitive = False
                    content_type = response.headers.get("Content-Type", "")
                    
                    # Check for known sensitive files
                    if file_path == "/.env" and ("DB_" in response.text or "PASSWORD" in response.text):
                        sensitive = True
                    elif file_path == "/.git/config" and "[core]" in response.text:
                        sensitive = True
                    elif file_path.endswith(".php") and "phpinfo()" in response.text:
                        sensitive = True
                    elif file_path.endswith((".json", ".sql")) and "application/json" in content_type:
                        sensitive = True
                    elif "text/plain" in content_type and ("password" in response.text.lower() or "secret" in response.text.lower()):
                        sensitive = True
                    
                    if sensitive:
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "Exposed Sensitive File",
                            "severity": "High",
                            "description": f"Sensitive file exposed at {file_path}",
                            "recommendation": "Restrict access to sensitive files and remove from web root"
                        })
                        print(f"{Fore.RED}[-] Sensitive file exposed at {file_path}{Style.RESET_ALL}")
            except Exception:
                continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No exposed sensitive files detected{Style.RESET_ALL}")
    
    def _check_robots_txt(self):
        """Check robots.txt for sensitive paths"""
        print(f"{Fore.CYAN}[*] Checking robots.txt...{Style.RESET_ALL}")
        
        try:
            response = SESSION.get(f"{self.target}robots.txt")
            if response.status_code == 200:
                print(f"{Fore.YELLOW}[~] Found robots.txt{Style.RESET_ALL}")
                
                # Check for sensitive disallowed paths
                sensitive_paths = []
                for line in response.text.splitlines():
                    if line.lower().startswith("disallow:") and len(line) > 10:
                        path = line[9:].strip()
                        if any(x in path.lower() for x in ["admin", "login", "config", "backup", "sql", "git"]):
                            sensitive_paths.append(path)
                
                if sensitive_paths:
                    self.results.append({
                        "vulnerability": "Sensitive Paths in robots.txt",
                        "severity": "Low",
                        "description": f"robots.txt reveals sensitive paths: {', '.join(sensitive_paths)}",
                        "recommendation": "Review robots.txt and remove sensitive path disclosures"
                    })
                    print(f"{Fore.RED}[-] Sensitive paths disclosed in robots.txt{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No robots.txt found or not accessible{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking robots.txt: {e}{Style.RESET_ALL}")
    
    def _check_server_software(self):
        """Check for outdated server software"""
        print(f"{Fore.CYAN}[*] Checking server software versions...{Style.RESET_ALL}")
        
        if not self.server_info:
            print(f"{Fore.YELLOW}[!] No server information gathered{Style.RESET_ALL}")
            return
        
        # Common vulnerable versions (simplified for example)
        vulnerable_versions = {
            "Apache": ["2.4.0", "2.4.1", "2.4.2"],
            "nginx": ["1.0.0", "1.0.1", "1.0.2"],
            "IIS": ["7.0", "7.5", "8.0"],
            "OpenSSL": ["1.0.1", "1.0.2", "1.1.0"]
        }
        
        for component, version_info in self.server_info.items():
            if isinstance(version_info, str):
                for software, versions in vulnerable_versions.items():
                    if software.lower() in version_info.lower():
                        for vulnerable_version in versions:
                            if vulnerable_version in version_info:
                                self.results.append({
                                    "vulnerability": f"Outdated {software} Version",
                                    "severity": "High",
                                    "description": f"Server running vulnerable {software} version: {version_info}",
                                    "recommendation": f"Upgrade {software} to latest stable version"
                                })
                                print(f"{Fore.RED}[-] Vulnerable {software} version: {version_info}{Style.RESET_ALL}")
                                break
        
        if not any("Outdated" in r["vulnerability"] for r in self.results):
            print(f"{Fore.GREEN}[+] No outdated server software detected{Style.RESET_ALL}")
    
    def _generate_report(self):
        """Generate vulnerability report"""
        os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
        
        with open(REPORT_FILE, 'w') as f:
            f.write(f"Server Configuration Test Report\n")
            f.write(f"Target: {TARGET_DOMAIN}\n")
            f.write(f"Date: {time.ctime()}\n\n")
            
            # Server information
            if self.server_info:
                f.write("Server Information:\n")
                f.write("=" * 80 + "\n")
                for key, value in self.server_info.items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
            
            # TLS information
            if self.cipher_info:
                f.write("TLS Information:\n")
                f.write("=" * 80 + "\n")
                for key, value in self.cipher_info.items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
            
            # Vulnerabilities
            if not self.results:
                f.write("No server configuration vulnerabilities found!\n")
                return
            
            f.write("Vulnerabilities Found:\n")
            f.write("=" * 80 + "\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"{i}. {result['vulnerability']} ({result['severity']})\n")
                f.write(f"   Description: {result['description']}\n")
                f.write(f"   Recommendation: {result['recommendation']}\n\n")
        
        print(f"{Fore.GREEN}[+] Report saved to {REPORT_FILE}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Found {len(self.results)} vulnerabilities!{Style.RESET_ALL}")
    
    def run_all_checks(self):
        """Execute all server configuration tests"""
        print(f"\n{Fore.BLUE}=== Starting Server Configuration Tests ==={Style.RESET_ALL}")
        
        tests = [
            self._check_http_headers,
            self._check_tls_configuration,
            self._check_dns_security,
            self._check_directory_listing,
            self._check_http_methods,
            self._check_cors_misconfig,
            self._check_security_txt,
            self._check_exposed_files,
            self._check_robots_txt,
            self._check_server_software
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"{Fore.RED}[-] Test failed: {e}{Style.RESET_ALL}")
        
        # Generate report
        self._generate_report()

if __name__ == "__main__":
    scanner = ServerConfigScanner()
    scanner.run_all_checks()