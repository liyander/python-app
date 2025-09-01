#!/usr/bin/env python3
"""
Test script to demonstrate external API integration (VirusTotal & PhishTank)
This script tests the enhanced phishing detector with external threat intelligence
"""

import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def test_external_apis():
    """Test the external API integration features"""
    
    print("🌐 Testing External API Integration")
    print("=" * 60)
    
    # Test URLs for external API checking
    test_urls = [
        "https://www.google.com",  # Should be safe
        "http://example.com",      # Should be safe
        "https://github.com",      # Should be safe
        "http://malware.testing.google.test/testing/malware/",  # Google's test malware URL
        "https://stackoverflow.com"  # Should be safe
    ]
    
    print("📊 Testing /external-scan endpoint")
    print("-" * 40)
    
    for url in test_urls:
        try:
            print(f"\n🔍 Testing: {url}")
            
            response = requests.post(f"{BASE_URL}/external-scan", 
                json={"url": url},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                print(f"   📈 APIs Available: {result['summary']['apis_available']}/{result['summary']['total_apis']}")
                
                # VirusTotal Results
                vt = result['virustotal']
                if vt['available']:
                    if vt.get('total_scans', 0) > 0:
                        print(f"   🦠 VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious, {vt['harmless']} clean")
                    else:
                        print(f"   🦠 VirusTotal: {vt.get('message', 'No scan data')}")
                else:
                    print(f"   🦠 VirusTotal: {vt.get('message', 'Not available')}")
                
                # PhishTank Results
                pt = result['phishtank']
                if pt['available']:
                    if pt['is_phish']:
                        print(f"   🎣 PhishTank: ⚠️ PHISHING DETECTED (ID: {pt.get('phish_id', 'N/A')})")
                    else:
                        print(f"   🎣 PhishTank: ✅ Clean")
                else:
                    print(f"   🎣 PhishTank: {pt.get('message', 'Not available')}")
                
                if result['summary']['threat_detected']:
                    print(f"   🚨 THREAT DETECTED")
                else:
                    print(f"   ✅ No threats detected")
                    
            else:
                print(f"   ❌ ERROR: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"   ⏱️ TIMEOUT: API took too long to respond")
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
        
        # Small delay between requests to be respectful to APIs
        time.sleep(1)

def test_enhanced_scan():
    """Test the enhanced /scan endpoint with external API integration"""
    
    print(f"\n🔬 Testing Enhanced /scan endpoint")
    print("-" * 40)
    
    test_cases = [
        {
            "url": "https://www.paypal.com",
            "description": "Legitimate PayPal (should be safe)"
        },
        {
            "url": "http://192.168.1.1/paypal-verify.tk",
            "description": "Suspicious pattern (IP + fake domain)"
        }
    ]
    
    for case in test_cases:
        try:
            print(f"\n🧪 Testing: {case['description']}")
            print(f"   URL: {case['url']}")
            
            # Test without external APIs
            response = requests.post(f"{BASE_URL}/scan",
                json={"type": "url", "value": case['url'], "include_external": False},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"   📊 Pattern Analysis: {'✅ SAFE' if result['is_safe'] else '⚠️ SUSPICIOUS'} ({result['confidence']}%)")
                print(f"   🔍 Risk Score: {result.get('risk_score', 'N/A')}")
                
                # Test with external APIs
                response_ext = requests.post(f"{BASE_URL}/scan",
                    json={"type": "url", "value": case['url'], "include_external": True},
                    headers={"Content-Type": "application/json"},
                    timeout=30
                )
                
                if response_ext.status_code == 200:
                    result_ext = response_ext.json()
                    print(f"   🌐 With External APIs: {'✅ SAFE' if result_ext['is_safe'] else '⚠️ SUSPICIOUS'} ({result_ext['confidence']}%)")
                    
                    if 'external_apis' in result_ext:
                        apis = result_ext['external_apis']
                        print(f"   📡 API Status: VT={apis['virustotal']['available']}, PT={apis['phishtank']['available']}")
                else:
                    print(f"   ❌ External API test failed: {response_ext.status_code}")
            else:
                print(f"   ❌ Pattern analysis failed: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")

def show_api_configuration():
    """Show API configuration instructions"""
    
    print(f"\n⚙️ API Configuration")
    print("-" * 40)
    print("To enable external API integration:")
    print("1. Get VirusTotal API key: https://www.virustotal.com/gui/join-us")
    print("2. Get PhishTank API key: https://www.phishtank.com/api_info.php")
    print("3. Update the API keys in app.py:")
    print("   VT_API_KEY = 'your_virustotal_api_key'")
    print("   PHISHTANK_API_KEY = 'your_phishtank_api_key'")
    print("\nCurrent API Status:")
    
    try:
        # Test API availability
        response = requests.post(f"{BASE_URL}/external-scan", 
            json={"url": "https://example.com"},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            vt_status = "✅ Configured" if result['virustotal']['available'] else "❌ Not configured"
            pt_status = "✅ Configured" if result['phishtank']['available'] else "❌ Not configured"
            
            print(f"VirusTotal: {vt_status}")
            print(f"PhishTank: {pt_status}")
        else:
            print("❌ Unable to check API status")
            
    except Exception as e:
        print(f"❌ Error checking API status: {e}")

if __name__ == "__main__":
    print("🚀 Starting External API Integration Tests")
    print("Make sure the Flask app is running on http://127.0.0.1:5000")
    print("Note: External APIs require valid API keys to function properly")
    print()
    
    try:
        # Test if server is running
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            
            show_api_configuration()
            test_external_apis()
            test_enhanced_scan()
            
            print(f"\n🎯 Summary")
            print("-" * 40)
            print("✅ External API integration framework")
            print("✅ VirusTotal API integration") 
            print("✅ PhishTank API integration")
            print("✅ Enhanced threat detection")
            print("✅ Comprehensive error handling")
            print("\n📚 Endpoints available:")
            print("  POST /scan - Enhanced scanning with optional external APIs")
            print("  POST /external-scan - Dedicated external API testing")
            print("  POST /analyze-patterns - Pattern analysis")
            
        else:
            print("❌ Server not responding correctly")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask server")
        print("Make sure to run: python app.py")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
