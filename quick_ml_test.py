#!/usr/bin/env python3
"""
Quick ML Test - Test the ML models directly
"""

import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from ml_predictor import PhishingPredictor
    print("✅ Successfully imported PhishingPredictor")
    
    # Initialize predictor
    predictor = PhishingPredictor()
    print(f"✅ Loaded {len(predictor.models)} ML models")
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://paypal-security-update.suspicious-domain.net",
        "https://github.com/microsoft/vscode",
        "http://bank-alert-urgent.test-phishing.xyz"
    ]
    
    print("\n🔍 Testing ML Predictions:")
    print("-" * 50)
    
    for url in test_urls:
        try:
            result = predictor.predict_single_url(url)
            print(f"\nURL: {url}")
            print(f"Raw result: {result}")
            
            if 'predictions' in result:
                predictions = result['predictions']
                print(f"Individual predictions:")
                if isinstance(predictions, dict):
                    for model_name, pred in predictions.items():
                        if 'error' not in pred:
                            print(f"  {model_name}: {pred['prediction']} (conf: {pred.get('confidence', 'N/A')})")
                        else:
                            print(f"  {model_name}: Error - {pred['error']}")
                else:
                    print(f"  predictions: {predictions}")
            
            # Try ensemble prediction
            try:
                ensemble = predictor.get_ensemble_prediction(url)
                print(f"Ensemble: {ensemble}")
            except Exception as e:
                print(f"Ensemble error: {e}")
                
        except Exception as e:
            print(f"\nURL: {url}")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n✅ ML Testing Complete!")
    
except ImportError as e:
    print(f"❌ Import failed: {e}")
    print("Make sure ml_predictor.py is in the same directory")
    
except Exception as e:
    print(f"❌ Testing failed: {e}")
    import traceback
    traceback.print_exc()
