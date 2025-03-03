import re
import requests
import whois
from urllib.parse import urlparse

def is_suspicious_url(url):
    # Common phishing patterns
    patterns = [
        r"https?://[a-zA-Z0-9.-]+\.tk",  # .tk domains (often suspicious)
        r"https?://[a-zA-Z0-9.-]+\.ml",
        r"https?://[a-zA-Z0-9.-]+\.ga",
        r"https?://[a-zA-Z0-9.-]+\.cf",
        r"https?://[a-zA-Z0-9.-]+\.gq",
        r"https?://.*@",  # URLs with '@' symbol
        r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # IP addresses instead of domain names
        r"https?://.*[-]{2,}.*",  # URLs with multiple hyphens
        r"https?://.*login.*|.*bank.*|.*secure.*",  # URLs containing suspicious keywords
        r"https?://.*bit\.ly.*|.*tinyurl\.com.*|.*short\.ly.*"  # Shortened URLs
    ]
    
    for pattern in patterns:
        if re.search(pattern, url):
            return True
    return False

def get_domain_reputation(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        if w.status is None:
            return False  # No WHOIS info often means suspicious domain
        return True
    except:
        return False

def check_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        if len(response.history) > 2:  # Multiple redirects can indicate phishing
            return True
    except requests.RequestException:
        return True  # Connection failure can be a red flag
    return False

def phishing_scanner(url):
    print(f"\nScanning URL: {url}\n")
    is_phishing = False
    
    if is_suspicious_url(url):
        print("⚠️ Warning: URL matches common phishing patterns!")
        is_phishing = True
    
    if not get_domain_reputation(url):
        print("⚠️ Caution: Domain has no WHOIS information, could be suspicious!")
        is_phishing = True
    
    if check_redirects(url):
        print("⚠️ Warning: URL has multiple redirects, potential phishing!")
        is_phishing = True
    
    if not is_phishing:
        print("✅ The URL appears to be safe.")
    else:
        print("🚨 The URL is likely a phishing link!")
    
    print("\nScan complete.")

if __name__ == "__main__":
    user_url = input("Enter a URL to check: ")
    phishing_scanner(user_url)
