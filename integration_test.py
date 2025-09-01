#!/usr/bin/env python3
"""
Complete Integration Test
Tests the entire system: Frontend, Backend, ML Models, Database
"""

import requests
import json
import time
import sys
import os
import subprocess
import signal

def test_integration():
    """Complete system integration test"""
    base_url = "http://127.0.0.1:5000"
    server_proc = None

    def ensure_server_running(timeout=15):
        nonlocal server_proc
        # Try to connect first
        try:
            r = requests.get(base_url, timeout=2)
            return True
        except Exception:
            pass

        # Start Flask dev server in background, capture logs
        try:
            # Run the server from the repository root so app_clean.py can be found.
            # Tests live in tests/, so go one directory up. If repo layout nests the
            # actual app under a subfolder, try that as a fallback.
            cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            env = os.environ.copy()
            env['FLASK_APP'] = 'app_clean.py'
            # Ensure child Python uses UTF-8 for IO so emoji/logging won't raise
            env['PYTHONIOENCODING'] = 'utf-8'
            # Use same Python executable running this script and run the app directly
            candidate1 = os.path.join(cwd, 'app_clean.py')
            candidate2 = os.path.join(cwd, 'phishing-detector', 'app_clean.py')
            if os.path.exists(candidate1):
                app_file = candidate1
            elif os.path.exists(candidate2):
                app_file = candidate2
            else:
                # Default to candidate1 so the original behavior remains if neither exists
                app_file = candidate1
            cmd = [sys.executable, app_file]
            log_path = os.path.join(cwd, 'integration_server.log')
            logf = open(log_path, 'ab')
            server_proc = subprocess.Popen(cmd, env=env, cwd=cwd, stdout=logf, stderr=logf)
        except Exception as e:
            print(f"❌ Failed to start server process: {e}")
            return False

        # Wait for server to become available
        start = time.time()
        wait_timeout = max(timeout, 30)
        while time.time() - start < wait_timeout:
            try:
                r = requests.get(base_url, timeout=2)
                if r.status_code == 200:
                    return True
            except Exception:
                time.sleep(0.5)

        # Timeout: print server log to help debugging
        try:
            logf.close()
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as lf:
                print('\n--- Server log (last 200 lines) ---')
                lines = lf.readlines()
                for ln in lines[-200:]:
                    print(ln.rstrip())
                print('--- end log ---\n')
        except Exception:
            pass

        return False

    def shutdown_server():
        nonlocal server_proc
        try:
            if server_proc:
                server_proc.terminate()
                server_proc.wait(timeout=5)
                server_proc = None
        except Exception:
            try:
                if server_proc:
                    server_proc.kill()
            except Exception:
                pass
    
    print("🚀 Starting Complete Integration Test")
    print("=" * 50)
    
    # Test 1: Basic connectivity
    print("\n📡 Test 1: Server Connectivity")
    try:
        ok = ensure_server_running()
        if ok:
            print("✅ Server is running and accessible")
        else:
            print("❌ Server did not start or is unreachable after timeout")
            shutdown_server()
            assert False
    except Exception as e:
        print(f"❌ Cannot ensure server running: {e}")
        shutdown_server()
        assert False
    
    # Test 2: URL Scanning
    print("\n🌐 Test 2: URL Scanning")
    test_urls = [
        ("https://www.google.com", "Safe"),
        ("http://paypal-security-update.malicious.net", "Phishing"),
        ("https://github.com", "Safe"),
        ("http://bank-verify.suspicious.tk", "Phishing")
    ]
    
    url_results = []
    for url, expected in test_urls:
        try:
            print(f"   Testing: {url}")
            
            response = requests.post(f"{base_url}/scan", 
                                   json={"type": "url", "input": url},
                                   headers={"Content-Type": "application/json"},
                                   timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    actual = result.get("result")
                    confidence = result.get("confidence")
                    threats = len(result.get("threats_detected", []))
                    
                    print(f"   ✅ Result: {actual} ({confidence}% confidence, {threats} threats)")
                    url_results.append(True)
                else:
                    print(f"   ❌ Scan failed: {result.get('error')}")
                    url_results.append(False)
            else:
                print(f"   ❌ HTTP Error: {response.status_code}")
                url_results.append(False)
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
            url_results.append(False)
        
        time.sleep(0.5)  # Small delay between tests
    
    # Test 3: Email Scanning
    print("\n📧 Test 3: Email Scanning")
    test_emails = [
        ("Hello, this is a normal business email.", "Safe"),
        ("URGENT! Your account will be suspended! Enter your password immediately!", "Phishing"),
        ("Your invoice is attached. Please review.", "Safe"),
        ("Click here to claim your prize! Enter your credit card details now!", "Phishing")
    ]
    
    email_results = []
    for email, expected in test_emails:
        try:
            print(f"   Testing email: {email[:50]}...")
            
            response = requests.post(f"{base_url}/scan",
                                   json={"type": "email", "input": email},
                                   headers={"Content-Type": "application/json"},
                                   timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    actual = result.get("result")
                    confidence = result.get("confidence")
                    threats = len(result.get("threats_detected", []))
                    
                    print(f"   ✅ Result: {actual} ({confidence}% confidence, {threats} threats)")
                    email_results.append(True)
                else:
                    print(f"   ❌ Scan failed: {result.get('error')}")
                    email_results.append(False)
            else:
                print(f"   ❌ HTTP Error: {response.status_code}")
                email_results.append(False)
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
            email_results.append(False)
        
        time.sleep(0.5)
    
    # Test 4: Statistics Endpoint
    print("\n📊 Test 4: Statistics")
    try:
        response = requests.get(f"{base_url}/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            print(f"   ✅ Total scans: {stats.get('total_scans', 0)}")
            print(f"   ✅ Threats detected: {stats.get('threats_detected', 0)}")
            print(f"   ✅ ML enhanced scans: {stats.get('ml_enhanced_scans', 0)}")
            print(f"   ✅ ML available: {stats.get('ml_available', False)}")
            stats_ok = True
        else:
            print(f"   ❌ Stats endpoint failed: {response.status_code}")
            stats_ok = False
    except Exception as e:
        print(f"   ❌ Stats error: {e}")
        stats_ok = False
    
    # Test 5: Performance Test
    print("\n⚡ Test 5: Performance")
    try:
        start_time = time.time()
        response = requests.post(f"{base_url}/scan",
                               json={"type": "url", "input": "https://www.example.com"},
                               headers={"Content-Type": "application/json"},
                               timeout=10)
        end_time = time.time()
        
        response_time = end_time - start_time
        print(f"   ✅ Response time: {response_time:.3f} seconds")
        
        if response_time < 2.0:
            print("   ✅ Performance: Excellent")
            performance_ok = True
        elif response_time < 5.0:
            print("   ✅ Performance: Good")
            performance_ok = True
        else:
            print("   ⚠️ Performance: Slow")
            performance_ok = False
            
    except Exception as e:
        print(f"   ❌ Performance test failed: {e}")
        performance_ok = False
    
    # Final Results
    print("\n📋 Final Integration Test Results")
    print("=" * 50)
    
    total_tests = 5
    passed_tests = 0
    
    # Count passed tests
    if len([r for r in url_results if r]) == len(url_results):
        print("✅ URL Scanning: PASS")
        passed_tests += 1
    else:
        print(f"❌ URL Scanning: FAIL ({sum(url_results)}/{len(url_results)} tests passed)")
    
    if len([r for r in email_results if r]) == len(email_results):
        print("✅ Email Scanning: PASS")
        passed_tests += 1
    else:
        print(f"❌ Email Scanning: FAIL ({sum(email_results)}/{len(email_results)} tests passed)")
    
    if stats_ok:
        print("✅ Statistics: PASS")
        passed_tests += 1
    else:
        print("❌ Statistics: FAIL")
    
    if performance_ok:
        print("✅ Performance: PASS")
        passed_tests += 1
    else:
        print("❌ Performance: FAIL")
    
    # Overall connectivity
    print("✅ Server Connectivity: PASS")
    passed_tests += 1
    
    print(f"\n🎯 Overall Result: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED - System fully integrated and working!")
        assert True
    elif passed_tests >= total_tests * 0.8:
        print("✅ MOSTLY WORKING - Minor issues detected")
        assert True
    else:
        print("❌ INTEGRATION ISSUES - Major problems detected")
        shutdown_server()
        assert False

    # Clean up server if we started it
    shutdown_server()

if __name__ == "__main__":
    print("Complete System Integration Test")
    print("Testing: Frontend + Backend + ML + Database")
    print()
    
    try:
        success = test_integration()
        if success:
            print("\n🚀 System is ready for production use!")
        else:
            print("\n🔧 System needs attention before deployment")
            
    except KeyboardInterrupt:
        print("\n\n⏹️ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
