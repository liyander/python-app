#!/usr/bin/env python3
"""
Day 13 Testing Script - ML Model Integration Demo
Test the ML-enhanced phishing detection system
"""

import requests
import json
import time
from typing import List, Dict

class MLPhishingTester:
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_ml_status(self) -> Dict:
        """Test ML system status"""
        try:
            response = self.session.get(f"{self.base_url}/ml-status")
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def test_url_scanning(self, url: str, use_ml: bool = True) -> Dict:
        """Test URL scanning with ML"""
        try:
            data = {
                "type": "url",
                "input": url,
                "use_ml": use_ml
            }
            
            start_time = time.time()
            response = self.session.post(f"{self.base_url}/scan", 
                                       json=data,
                                       headers={"Content-Type": "application/json"})
            end_time = time.time()
            
            result = response.json()
            result["client_response_time"] = end_time - start_time
            return result
            
        except Exception as e:
            return {"error": str(e)}
    
    def test_batch_urls(self, urls: List[str]) -> List[Dict]:
        """Test multiple URLs"""
        results = []
        for url in urls:
            print(f"\n🔍 Testing: {url}")
            
            # Test with ML
            ml_result = self.test_url_scanning(url, use_ml=True)
            
            # Test without ML
            rule_result = self.test_url_scanning(url, use_ml=False)
            
            results.append({
                "url": url,
                "ml_result": ml_result,
                "rule_result": rule_result
            })
            
            # Print immediate results
            if ml_result.get("success"):
                ml_confidence = ml_result.get("confidence", 0)
                ml_method = ml_result.get("detection_method", "unknown")
                print(f"   🤖 ML Result: {ml_result.get('result', 'Error')} ({ml_confidence}% confidence)")
                print(f"   📋 Method: {ml_method}")
                
                if ml_result.get("ml_details"):
                    ml_conf = ml_result["ml_details"].get("confidence", 0)
                    voting = ml_result["ml_details"].get("voting_ratio", "N/A")
                    print(f"   🎯 ML Confidence: {ml_conf:.3f}, Voting: {voting}")
            else:
                print(f"   ❌ Error: {ml_result.get('error', 'Unknown error')}")
            
            time.sleep(0.5)  # Small delay between requests
            
        return results
    
    def run_comprehensive_test(self):
        """Run comprehensive testing"""
        print("🚀 Starting ML-Enhanced Phishing Detector Test Suite")
        print("=" * 60)
        
        # Test 1: ML Status
        print("\n📊 Test 1: ML System Status")
        status = self.test_ml_status()
        if status.get("available"):
            print(f"✅ ML System: Online ({status.get('models_loaded', 0)} models)")
            if status.get("models"):
                for model in status["models"]:
                    print(f"   - {model['name']}: {model['features']} features")
        else:
            print(f"❌ ML System: {status.get('message', 'Offline')}")
            return
        
        # Test 2: URL Scanning
        print("\n🌐 Test 2: URL Scanning (Mixed Dataset)")
        
        test_urls = [
            # Legitimate websites
            "https://www.google.com",
            "https://github.com/microsoft/vscode",
            "https://stackoverflow.com/questions",
            
            # Suspicious patterns (simulated phishing)
            "http://paypal-security-update.suspicious-domain.net",
            "https://amazon-prize-winner.fake-rewards.org",
            "http://microsoft-account-verify.phishing-test.com",
            
            # Mixed cases
            "https://docs.python.org/3/tutorial/",
            "http://bank-alert-urgent.test-phishing.xyz"
        ]
        
        results = self.test_batch_urls(test_urls)
        
        # Test 3: Performance Analysis
        print("\n📈 Test 3: Performance Analysis")
        ml_times = []
        rule_times = []
        
        for result in results:
            if result["ml_result"].get("success"):
                ml_time = result["ml_result"].get("processing_time", 0)
                ml_times.append(ml_time)
                
            if result["rule_result"].get("success"):
                rule_time = result["rule_result"].get("processing_time", 0)
                rule_times.append(rule_time)
        
        if ml_times:
            avg_ml_time = sum(ml_times) / len(ml_times)
            print(f"⚡ Average ML Processing Time: {avg_ml_time:.4f}s")
            
        if rule_times:
            avg_rule_time = sum(rule_times) / len(rule_times)
            print(f"⚡ Average Rule Processing Time: {avg_rule_time:.4f}s")
        
        # Test 4: Comparison Analysis
        print("\n🔬 Test 4: ML vs Rule-Based Comparison")
        comparison_data = []
        
        for result in results:
            if (result["ml_result"].get("success") and 
                result["rule_result"].get("success")):
                
                ml_res = result["ml_result"]["result"]
                rule_res = result["rule_result"]["result"]
                url = result["url"]
                
                comparison_data.append({
                    "url": url,
                    "ml_result": ml_res,
                    "rule_result": rule_res,
                    "agreement": ml_res == rule_res
                })
        
        agreement_count = sum(1 for item in comparison_data if item["agreement"])
        total_comparisons = len(comparison_data)
        agreement_rate = 0.0  # Ensure agreement_rate is always defined
        
        if total_comparisons > 0:
            agreement_rate = (agreement_count / total_comparisons) * 100
            print(f"🤝 ML-Rule Agreement Rate: {agreement_rate:.1f}% ({agreement_count}/{total_comparisons})")
            
            # Show disagreements
            disagreements = [item for item in comparison_data if not item["agreement"]]
            if disagreements:
                print("\n🔍 Disagreements Found:")
                for item in disagreements:
                    print(f"   URL: {item['url']}")
                    print(f"   ML: {item['ml_result']} | Rules: {item['rule_result']}")
        
        print("\n✅ Testing Complete!")
        print(f"📊 Total URLs Tested: {len(test_urls)}")
        print(f"🤖 ML System Performance: {'Excellent' if agreement_rate > 80 else 'Good' if agreement_rate > 60 else 'Needs Review'}")

def main():
    """Main testing function"""
    print("Day 13: ML Model Training & Serialization - TESTING PHASE")
    print("Testing ML-enhanced phishing detection system...")
    print()
    
    tester = MLPhishingTester()
    
    try:
        tester.run_comprehensive_test()
    except KeyboardInterrupt:
        print("\n\n⏹️ Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Testing failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
