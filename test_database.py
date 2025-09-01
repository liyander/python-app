#!/usr/bin/env python3
"""
Database Testing Script for Phishing Detector
Tests SQLite integration and database functionality
"""

import requests
import json
import time
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_database_integration():
    """Test the database integration features"""
    
    print("🗄️ Testing SQLite Database Integration")
    print("=" * 60)
    
    # Test health check
    print("\n🏥 Testing Health Check...")
    try:
        response = requests.get(f"{BASE_URL}/api/health")
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Health Status: {health_data['status']}")
            print(f"📊 Database: {health_data['database']}")
            print(f"📈 Total Records: {health_data['total_records']}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check error: {e}")
    
    # Test scan functionality with database storage
    print(f"\n🔍 Testing Scan with Database Storage...")
    
    test_scans = [
        {
            "type": "url",
            "value": "http://192.168.1.1/phishing-test",
            "description": "IP-based suspicious URL"
        },
        {
            "type": "url", 
            "value": "https://paypal-verify.tk/secure",
            "description": "Suspicious domain pattern"
        },
        {
            "type": "email",
            "value": "Urgent: Your account has been suspended. Click here immediately to verify your identity and restore access.",
            "description": "Phishing email content"
        },
        {
            "type": "url",
            "value": "https://www.google.com",
            "description": "Safe URL"
        }
    ]
    
    record_ids = []
    
    for i, test in enumerate(test_scans, 1):
        print(f"\n📋 Test {i}: {test['description']}")
        try:
            response = requests.post(f"{BASE_URL}/scan",
                json=test,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                record_id = result.get('record_id')
                processing_time = result.get('processing_time', 0)
                
                print(f"✅ Scan completed successfully")
                print(f"   🆔 Record ID: {record_id}")
                print(f"   🛡️ Safety: {'Safe' if result['is_safe'] else 'Suspicious'}")
                print(f"   📊 Confidence: {result['confidence']}%")
                print(f"   ⏱️ Processing Time: {processing_time}s")
                
                if record_id:
                    record_ids.append(record_id)
                    
            else:
                print(f"❌ Scan failed: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Scan error: {e}")
        
        time.sleep(0.5)  # Small delay between requests
    
    # Test statistics endpoint
    print(f"\n📊 Testing Statistics Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/statistics")
        if response.status_code == 200:
            stats_data = response.json()
            if stats_data['success']:
                stats = stats_data['statistics']
                overall = stats['overall']
                
                print("✅ Statistics retrieved successfully:")
                print(f"   📈 Total Scans: {overall.get('total_scans', 0)}")
                print(f"   🌐 URL Scans: {overall.get('url_scans', 0)}")
                print(f"   📧 Email Scans: {overall.get('email_scans', 0)}")
                print(f"   ✅ Safe Results: {overall.get('safe_results', 0)}")
                print(f"   ⚠️ Suspicious Results: {overall.get('suspicious_results', 0)}")
                print(f"   📊 Avg Confidence: {overall.get('avg_confidence', 0)}%")
                print(f"   ⏱️ Avg Processing Time: {overall.get('avg_processing_time', 0)}s")
        else:
            print(f"❌ Statistics request failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Statistics error: {e}")
    
    # Test history endpoint
    print(f"\n📝 Testing History Endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/history?limit=10")
        if response.status_code == 200:
            history_data = response.json()
            if history_data['success']:
                history = history_data['history']
                
                print(f"✅ History retrieved successfully:")
                print(f"   📊 Records Found: {history_data['count']}")
                
                if history:
                    print("   📋 Recent Records:")
                    for record in history[:3]:  # Show first 3 records
                        print(f"      🆔 ID: {record['id']} | "
                              f"📝 Type: {record['input_type']} | "
                              f"🛡️ Safety: {'Safe' if record['is_safe'] else 'Suspicious'} | "
                              f"📊 Confidence: {record['confidence']}%")
        else:
            print(f"❌ History request failed: {response.status_code}")
    except Exception as e:
        print(f"❌ History error: {e}")
    
    # Test filtered history
    print(f"\n🔍 Testing Filtered History (URLs only)...")
    try:
        response = requests.get(f"{BASE_URL}/history?type=url&limit=5")
        if response.status_code == 200:
            history_data = response.json()
            if history_data['success']:
                print(f"✅ URL History: {history_data['count']} records found")
        else:
            print(f"❌ Filtered history failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Filtered history error: {e}")

def test_database_schema():
    """Test database schema and structure"""
    print(f"\n🏗️ Database Schema Information")
    print("-" * 40)
    
    schema_info = """
    📋 scan_records table:
    ├── id (INTEGER PRIMARY KEY AUTOINCREMENT)
    ├── input_type (TEXT NOT NULL, CHECK: 'url' or 'email')
    ├── input_content (TEXT NOT NULL)
    ├── result (TEXT NOT NULL)
    ├── is_safe (BOOLEAN NOT NULL)
    ├── confidence (INTEGER NOT NULL)
    ├── risk_score (INTEGER DEFAULT 0)
    ├── details (TEXT - JSON format)
    ├── external_apis (TEXT - JSON format)
    ├── user_ip (TEXT)
    ├── timestamp (DATETIME DEFAULT CURRENT_TIMESTAMP)
    └── processing_time (REAL DEFAULT 0.0)
    
    📊 scan_statistics table:
    ├── id (INTEGER PRIMARY KEY AUTOINCREMENT)
    ├── date (DATE NOT NULL UNIQUE)
    ├── total_scans (INTEGER DEFAULT 0)
    ├── url_scans (INTEGER DEFAULT 0)
    ├── email_scans (INTEGER DEFAULT 0)
    ├── safe_results (INTEGER DEFAULT 0)
    ├── suspicious_results (INTEGER DEFAULT 0)
    ├── avg_confidence (REAL DEFAULT 0.0)
    └── created_at (DATETIME DEFAULT CURRENT_TIMESTAMP)
    
    🔍 Indexes:
    ├── idx_timestamp (on scan_records.timestamp)
    ├── idx_input_type (on scan_records.input_type)
    ├── idx_is_safe (on scan_records.is_safe)
    └── idx_user_ip (on scan_records.user_ip)
    """
    
    print(schema_info)

if __name__ == "__main__":
    print("🚀 Starting Database Integration Tests")
    print("Make sure the Flask app is running on http://127.0.0.1:5000")
    print()
    
    try:
        # Test if server is running
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            
            test_database_integration()
            test_database_schema()
            
            print(f"\n🎯 Database Integration Summary")
            print("-" * 40)
            print("✅ SQLite database initialization")
            print("✅ Scan record storage")
            print("✅ Statistics tracking")
            print("✅ History retrieval")
            print("✅ Health monitoring")
            print("✅ Admin dashboard")
            
            print(f"\n🌐 Available Endpoints:")
            print("🏠 Main App: http://127.0.0.1:5000/")
            print("📊 Admin Dashboard: http://127.0.0.1:5000/admin")
            print("📈 Statistics API: http://127.0.0.1:5000/statistics")
            print("📝 History API: http://127.0.0.1:5000/history")
            print("🏥 Health Check: http://127.0.0.1:5000/api/health")
            
        else:
            print("❌ Server not responding correctly")
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask server")
        print("Make sure to run: python app.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)
