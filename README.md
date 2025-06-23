# Web Penetration Testing Framework / WebCrackerUX

**Owner:** ABDUL MANNAN a.k.a ShaheenUX  
**Version:** 1.0  
**License:** [GNU GPLv3](LICENSE)  

## 📌 Overview
Comprehensive web application security testing framework with 40+ automated tests across 4 specialized modules.

## 🧰 Modules
### 1. Authentication & Session Checks (`auth-session-checks.py`)
- Credential stuffing
- Session fixation
- JWT vulnerabilities
- Password policy testing
- Concurrent sessions
- Cookie attributes
- 2FA bypass techniques

### 2. Injection Checks (`injection-checks.py`)
- SQL injection (time-based/error-based)
- Cross-site scripting (XSS)
- Command injection
- XXE injection
- Server-side request forgery (SSRF)

### 3. Server Config Checks (`server-config-checks.py`)
- Security headers analysis
- TLS/SSL configuration
- DNS security (DNSSEC/DMARC/DKIM)
- Directory listing
- Exposed sensitive files
- HTTP methods

### 4. Advanced Checks (`advance-checks.py`)
- Insecure deserialization
- Prototype pollution
- GraphQL vulnerabilities
- Cache poisoning
- Host header injection
- WebSocket security

## 🚀 ***Installation***

# Clone repository
     git clone https://github.com/shaheenux/WebcrackerUX.git
     cd WebCrackerUX

# Install dependencies
    python3 prerequisites-web-penetration.py


## ***Usage***

# Run complete test suite (recommended order):
    python3 auth-session-checks.py
    python3 injection-checks.py
    python3 server-config-checks.py
    python3 advance-checks.py

# Or run individual modules:
    python3 [module-name].py

📊 ***Reports***

All reports are generated in /reports/ directory:

    auth_session_report.txt

    injection_report.txt

    server_config_report.txt

    advance_report.txt

⚙️ ***Configuration***

Edit config.py to set:  (It will created after running preriquisites-web-penetration.py)

    TARGET_DOMAIN - Target website domain

    TARGET_IP - Server IP address

    REQUEST_TIMEOUT - HTTP request timeout (seconds)

📋 ***Requirements***

    OS: Kali Linux (recommended), Ubuntu/Debian

    Python: 3.8+

    RAM: 4GB minimum

    Storage: 10GB free space

⚠️ ***Legal Disclaimer***

This tool is for authorized security testing and educational purposes only. Unauthorized use against any system without explicit permission is strictly prohibited. The owner (ABDUL MANNAN aka ShaheenUX) is not responsible for any misuse or damage caused by this software.


 📬 **Contact**
 📧 shaheenux@gmail.com
 🔗 **https://github.com/shaheenux**
