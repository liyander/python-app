#!/usr/bin/env python3
"""
Simple database test script
"""

import requests
import json

def test_simple():
    print("Testing database integration...")
    
    # Test a simple scan
    try:
        response = requests.post("http://127.0.0.1:5000/scan", 
            json={"type": "url", "value": "https://google.com"},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Scan successful!")
            print(f"   Record ID: {result.get('record_id')}")
            print(f"   Safe: {result.get('is_safe')}")
            print(f"   Confidence: {result.get('confidence')}%")
            print(f"   Processing Time: {result.get('processing_time')}s")
        else:
            print(f"❌ Scan failed: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_simple()
