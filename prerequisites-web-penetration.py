#!/usr/bin/env python3
"""
Owner: Abdul Mannan aka ShaheenUX
Social Handles: github.com/shaheenUX , instagram.com/shaheen_hacker , linktr.ee/shaheen_hacker
WebCrackerUX v1.O - PREREQUISITES INSTALLER
Description: 
  Installs dependencies, validates environment, and configures target information
  for 4 penetration testing modules (40+ attacks).
"""

import os
import sys
import subprocess
import platform
import re
from pathlib import Path
import importlib.util

# package mapping
PACKAGE_MAP = {
    'bs4': 'beautifulsoup4',          
    'selenium': 'selenium',
    'paramiko': 'paramiko',
    'lxml': 'lxml',
    'dns': 'dnspython',               
    'cryptography': 'cryptography',
    'OpenSSL': 'pyOpenSSL',
    'colorama': 'colorama',
    'requests': 'requests'
}

# External tools to verify/install
EXTERNAL_TOOLS = {
    'rockyou.txt': {
        'path': '/usr/share/wordlists/rockyou.txt',
        'install': 'sudo apt-get update && sudo apt-get install -y wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null',
        'fallback': 'wget https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz && gunzip rockyou.txt.gz'
    },
    'nmap': {'install': 'sudo apt-get install -y nmap'},
    'nikto': {'install': 'sudo apt-get install -y nikto'},
    'whatweb': {'install': 'sudo apt-get install -y whatweb'},
    'hydra': {'install': 'sudo apt-get install -y hydra'}  # Added for auth attacks
}

# WebDriver paths for Selenium
WEBDRIVERS = {
    'geckodriver': {
        'url': 'https://github.com/mozilla/geckodriver/releases',
        'install': 'wget https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-linux64.tar.gz -O /tmp/geckodriver.tar.gz && tar -xzf /tmp/geckodriver.tar.gz -C /tmp/ && chmod +x /tmp/geckodriver && sudo mv /tmp/geckodriver /usr/local/bin/'
    },
    'chromedriver': {
        'url': 'https://chromedriver.chromium.org/downloads',
        'install': 'wget https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip -O /tmp/chromedriver.zip && unzip /tmp/chromedriver.zip -d /tmp/ && chmod +x /tmp/chromedriver && sudo mv /tmp/chromedriver /usr/local/bin/'
    }
}

def print_banner():
    banner = r"""
    #######################################################
    #          WEB PENETRATION FRAMEWORK SETUP            #
    #  - 5 Modules | 50+ Attacks | Automated Pentesting   #
    #######################################################
    """
    print(banner)

def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(num) <= 255 for num in ip.split('.'))
    return False

def validate_domain(domain):
    pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_package_installed(package_name):
    """Robust package check using importlib"""
    spec = importlib.util.find_spec(package_name)
    return spec is not None

def get_pip_command():
    """Determine available pip command with fallback"""
    for cmd in ['pip3', 'pip']:
        try:
            subprocess.run([cmd, '--version'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None

def install_package(pip_cmd, package):
    """Install package with proper error handling"""
    install_cmd = [pip_cmd, 'install', PACKAGE_MAP.get(package, package)]
    try:
        result = subprocess.run(install_cmd, check=True, capture_output=True, text=True)
        if "Successfully installed" in result.stdout:
            return True
        return False
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Installation failed: {e.stderr.strip()}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {str(e)}")
        return False

def install_packages():
    print("\n[+] Checking required Python packages")
    pip_cmd = get_pip_command()
    if not pip_cmd:
        print("  ✗ Critical: No pip installation found. Install pip and restart.")
        return False
    
    print(f"  Using {pip_cmd} for package management")
    
    success = True
    for package in PACKAGE_MAP.keys():
        if is_package_installed(package):
            print(f"  ✓ {package} already installed")
            continue
            
        print(f"  ➜ Installing {package}...")
        if install_package(pip_cmd, package):
            print(f"  ✓ Successfully installed {package}")
        else:
            print(f"  ✗ Failed to install {package}. Manual installation required.")
            success = False
    
    return success

def check_external_tools():
    print("\n[+] Verifying external tools")
    missing_tools = []
    
    # Check rockyou.txt with fallback
    rockyou_path = Path(EXTERNAL_TOOLS['rockyou.txt']['path'])
    if rockyou_path.exists():
        print("  ✓ rockyou.txt found")
    else:
        print("  ✗ rockyou.txt not found")
        try:
            print("  Attempting installation...")
            subprocess.run(EXTERNAL_TOOLS['rockyou.txt']['install'], shell=True, check=True)
            
            # Verify installation
            if rockyou_path.exists():
                print("  ✓ rockyou.txt installed")
            else:
                print("  ➜ Trying fallback download...")
                subprocess.run(EXTERNAL_TOOLS['rockyou.txt']['fallback'], shell=True, check=True)
                if Path('rockyou.txt').exists():
                    print("  ✓ Downloaded rockyou.txt to current directory")
                else:
                    print("  ✗ Could not acquire rockyou.txt")
                    missing_tools.append('rockyou.txt')
        except Exception as e:
            print(f"  ✗ Installation failed: {str(e)}")
            missing_tools.append('rockyou.txt')
    
    # Check security tools
    for tool, info in EXTERNAL_TOOLS.items():
        if tool == 'rockyou.txt': 
            continue
            
        try:
            subprocess.run(['which', tool], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  ✓ {tool} installed")
        except subprocess.CalledProcessError:
            print(f"  ✗ {tool} not found")
            try:
                print(f"  Installing {tool}...")
                subprocess.run(info['install'], shell=True, check=True)
                print(f"  ✓ Installed {tool}")
            except Exception as e:
                print(f"  ✗ Installation failed: {str(e)}")
                missing_tools.append(tool)
    
    return missing_tools

def check_webdrivers():
    print("\n[+] Checking browser automation components")
    missing_drivers = []
    
    for driver, info in WEBDRIVERS.items():
        try:
            subprocess.run(['which', driver], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  ✓ {driver} found")
        except subprocess.CalledProcessError:
            print(f"  ✗ {driver} not in PATH")
            try:
                print(f"  Installing {driver}...")
                subprocess.run(info['install'], shell=True, check=True)
                print(f"  ✓ Installed {driver}")
            except Exception as e:
                print(f"  ✗ Installation failed: {str(e)}")
                print(f"  Manual download: {info['url']}")
                missing_drivers.append(driver)
    
    return missing_drivers

def create_config(target_ip, target_domain):
    config_content = f"""# AUTO-GENERATED CONFIGURATION
TARGET_IP = "{target_ip}"
TARGET_DOMAIN = "{target_domain}"
BASE_URL = "http://{target_domain}/"
HTTPS_URL = "https://{target_domain}/"

# Additional configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
REQUEST_TIMEOUT = 15
"""
    with open('config.py', 'w') as f:
        f.write(config_content)
    print("\n[+] Configuration file created: config.py")

def main():
    print_banner()
    
    # System check
    if platform.system() != 'Linux':
        print("[!] Warning: This toolset is optimized for Linux environments")
    
    # Installation process
    packages_ok = install_packages()
    missing_tools = check_external_tools()
    missing_drivers = check_webdrivers()
    
    # Get target information
    print("\n[+] Target Configuration")
    while True:
        target_ip = input("Enter target server IP: ").strip()
        if validate_ip(target_ip):
            break
        print("Invalid IP format. Example: 192.168.1.100")
    
    while True:
        target_domain = input("Enter target domain (e.g. example.com): ").strip()
        if validate_domain(target_domain):
            break
        print("Invalid domain format. Example: example.com")
    
    # Create configuration file
    create_config(target_ip, target_domain)
    
    # Final report
    print("\n[+] Setup Summary")
    print(f"Target: {target_domain} ({target_ip})")
    
    status = "✓ READY FOR TESTING" if packages_ok and not missing_tools and not missing_drivers else "⚠ PARTIALLY READY"
    print(f"\nStatus: {status}")
    
    if missing_tools:
        print("\n[!] Missing security tools:")
        for tool in missing_tools:
            print(f"  - {tool}")
    
    if missing_drivers:
        print("\n[!] Missing web drivers:")
        for driver in missing_drivers:
            print(f"  - {driver}")
    
    if not packages_ok:
        print("\n[!] Some Python packages failed to install")
    
    print("\nNEXT STEPS:")
    print("1. Run attack modules in this order:")
    print("   auth-session-checks.py → injection-checks.py → server-config-checks.py")
    print("   → business-logic-checks.py → advance-checks.py")
    print("2. Results will be saved in ./reports/ directory")
    print("\nNote: All attack scripts will automatically import configuration from config.py")

if __name__ == "__main__":
    main()