#!/usr/bin/env python3
"""
Quick test script to verify Google Safe Browsing API is working correctly.
Run this to test your API key and see what responses you get.
"""

import os
import requests
import json

API_KEY = "AIzaSyDOoR_W2klXfNFlJnkwJEvKbKaeT4o8Qxg"

# Test URLs
test_urls = [
    "https://www.google.com",  # Should be safe
    "https://testsafebrowsing.appspot.com/s/malware.html",  # Google's test malware page
    "https://example.com",  # Should be safe
]

endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

print("=" * 60)
print("Google Safe Browsing API Test")
print("=" * 60)
print(f"API Key: {API_KEY[:20]}...")
print()

for url in test_urls:
    print(f"\nTesting URL: {url}")
    print("-" * 60)
    
    payload = {
        "client": {"clientId": "secure-click-test", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        r = requests.post(endpoint, json=payload, timeout=10)
        print(f"Status Code: {r.status_code}")
        
        if r.status_code == 200:
            response_data = r.json()
            print(f"Response: {json.dumps(response_data, indent=2)}")
            
            if response_data and "matches" in response_data and len(response_data["matches"]) > 0:
                print("✅ FLAGGED as malicious by Safe Browsing")
                for match in response_data["matches"]:
                    print(f"  Threat Type: {match.get('threatType', 'Unknown')}")
                    print(f"  Platform: {match.get('platformType', 'Unknown')}")
            else:
                print("✅ NOT FLAGGED (safe)")
        elif r.status_code == 400:
            error_data = r.json() if r.text else {}
            print(f"❌ Error 400: {error_data}")
        elif r.status_code == 403:
            print("❌ Error 403: Invalid API key or quota exceeded")
            print(f"Response: {r.text}")
        else:
            print(f"❌ Error {r.status_code}: {r.text}")
            
    except requests.exceptions.Timeout:
        print("❌ Request timeout")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

print("\n" + "=" * 60)
print("Test complete!")
print("=" * 60)

