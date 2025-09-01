#!/usr/bin/env python3
"""
Simple test script for the clean app
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import the clean app functions directly
from app_clean import check_url_phishing_simple, check_email_phishing_simple

def test_url_scan():
    """Test URL scanning function directly"""
    print("🌐 Testing URL Scanning Function")
    
    test_urls = [
        "https://www.google.com",
        "http://paypal-security-update.malicious.net",
        "https://github.com"
    ]
    
    for url in test_urls:
        print(f"   Testing: {url}")
        try:
            result = check_url_phishing_simple(url)
            print(f"   ✅ Result: {result['result']} ({result['confidence']}% confidence)")
            print(f"      Risk Score: {result['risk_score']}, ML Used: {result['ml_used']}")
            print(f"      Threats: {len(result['threats_detected'])}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        print()

def test_email_scan():
    """Test email scanning function directly"""
    print("📧 Testing Email Scanning Function")
    
    test_emails = [
        "Hello, this is a normal business email about our meeting.",
        "URGENT! Your account will be suspended! Click here now!"
    ]
    
    for email in test_emails:
        print(f"   Testing: {email[:50]}...")
        try:
            result = check_email_phishing_simple(email)
            print(f"   ✅ Result: {result['result']} ({result['confidence']}% confidence)")
            print(f"      Risk Score: {result['risk_score']}, ML Used: {result['ml_used']}")
            print(f"      Threats: {len(result['threats_detected'])}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        print()

if __name__ == "__main__":
    print("🧪 Direct Function Testing")
    print("=" * 50)
    
    # Test ML models loading
    try:
        from app_clean import ML_MODELS_AVAILABLE, ml_predictor
        print(f"🤖 ML Models Available: {ML_MODELS_AVAILABLE}")
        if ml_predictor:
            print(f"🎯 ML Predictor: {type(ml_predictor).__name__}")
    except Exception as e:
        print(f"❌ ML Status Error: {e}")
    
    print()
    test_url_scan()
    test_email_scan()
    
    print("✅ Direct function testing complete!")
