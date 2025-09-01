#!/usr/bin/env python3
"""
Test script to demonstrate enhanced pattern matching capabilities
Run this script to test the new regex patterns for:
- IP-based URLs
- Hex-encoded characters  
- Known suspicious patterns/domains
"""

import requests
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_pattern_detection():
    """Test the enhanced pattern detection features"""
    
    print("🔍 Testing Enhanced Phishing Detection Patterns")
    print("=" * 60)
    
    # Test cases for IP-based URLs
    ip_urls = [
        "http://192.168.1.100/secure-login",
        "https://203.45.67.89/paypal-verify", 
        "http://10.0.0.1/amazon-security",
        "https://172.16.0.1/microsoft-update"
    ]
    
    # Test cases for hex-encoded URLs
    hex_urls = [
        "https://paypal%2ecom%2esecurity.tk/login",
        "http://amazon%2Dverify%2Dupdate.ml/secure",
        "https://microsoft&#x2e;security&#x2e;update.cf/verify",
        "http://google%u002esecurity.ga/account"
    ]
    
    # Test cases for suspicious domain patterns
    suspicious_domains = [
        "https://paypal-verification.tk/login", 
        "http://amazon-security-update.ml/verify",
        "https://microsoft-account-verify.ga/secure",
        "http://apple-id-suspended.cf/unlock",
        "https://facebook-security-alert.pw/confirm"
    ]
    
    # Test cases for legitimate URLs (should be safe)
    safe_urls = [
        "https://www.paypal.com/signin",
        "https://amazon.com/your-account", 
        "https://account.microsoft.com/security",
        "https://appleid.apple.com/signin",
        "https://www.facebook.com/login"
    ]
    
    test_categories = [
        ("IP-based URLs", ip_urls),
        ("Hex-encoded URLs", hex_urls), 
        ("Suspicious Domains", suspicious_domains),
        ("Safe URLs", safe_urls)
    ]
    
    for category, urls in test_categories:
        print(f"\n📊 Testing {category}")
        print("-" * 40)
        
        for url in urls:
            try:
                response = requests.post(f"{BASE_URL}/scan", 
                    json={"type": "url", "value": url},
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    result = response.json()
                    safety = "✅ SAFE" if result['is_safe'] else "⚠️ SUSPICIOUS"
                    confidence = result['confidence']
                    
                    print(f"{safety} | {confidence}% | {url[:50]}...")
                    for detail in result['details'][:2]:  # Show first 2 details
                        print(f"    └─ {detail}")
                else:
                    print(f"❌ ERROR | {url}")
                    
            except Exception as e:
                print(f"❌ CONNECTION ERROR | {url}")
    
    print(f"\n🔬 Testing Pattern Analysis Endpoint")
    print("-" * 40)
    
    # Test the pattern analysis endpoint
    test_text = "https://192.168.1.1/paypal%2Dverification.tk/urgent%2Daction"
    
    try:
        response = requests.post(f"{BASE_URL}/analyze-patterns",
            json={"text": test_text, "type": "url"},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Text: {result['text_analyzed']}")
            print(f"Patterns found:")
            for pattern_type, patterns in result['patterns_found'].items():
                if patterns:
                    print(f"  {pattern_type}: {patterns}")
            print(f"Total patterns: {result['total_patterns']}")
            print(f"Risk level: {[k for k, v in result['risk_assessment'].items() if v][0].upper()}")
        else:
            print("Error testing pattern analysis")
            
    except Exception as e:
        print(f"Connection error: {e}")

def test_email_patterns():
    """Test email pattern detection"""
    
    print(f"\n📧 Testing Email Pattern Detection")
    print("-" * 40)
    
    suspicious_emails = [
        "Your account has been suspended. Verify your identity immediately at https://192.168.1.1/secure",
        "Urgent: Click here https://paypal%2Dverify.tk to update your payment information",
        "Security Alert: Unauthorized access detected. Confirm now at microsoft-security.ml",
        "IRS Notice: Tax refund pending. Visit bit.ly/irs-refund to claim"
    ]
    
    for email in suspicious_emails:
        try:
            response = requests.post(f"{BASE_URL}/scan",
                json={"type": "email", "value": email},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                safety = "✅ SAFE" if result['is_safe'] else "⚠️ SUSPICIOUS"
                confidence = result['confidence']
                
                print(f"{safety} | {confidence}% | {email[:40]}...")
                for detail in result['details'][:2]:
                    print(f"    └─ {detail}")
            else:
                print(f"❌ ERROR | {email[:40]}...")
                
        except Exception as e:
            print(f"❌ CONNECTION ERROR | {email[:40]}...")

if __name__ == "__main__":
    print("🚀 Starting Enhanced Pattern Matching Tests")
    print("Make sure the Flask app is running on http://127.0.0.1:5000")
    print()
    
    try:
        # Test if server is running
        response = requests.get(f"{BASE_URL}/test-patterns", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            test_pattern_detection()
            test_email_patterns()
            
            print(f"\n🎯 Summary")
            print("-" * 40)
            print("✅ IP-based URL detection")
            print("✅ Hex-encoded character detection") 
            print("✅ Suspicious domain pattern matching")
            print("✅ Advanced email phishing detection")
            print("✅ Pattern analysis endpoint")
            
        else:
            print("❌ Server not responding correctly")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask server")
        print("Make sure to run: python app.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)
