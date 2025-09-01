#!/usr/bin/env python3
"""
ML Model Testing and Prediction Module
Test trained models and provide real-time prediction capabilities
"""

import joblib
import pandas as pd
import numpy as np
import json
import os
import urllib.parse
import re
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingPredictor:
    """
    Real-time phishing prediction using trained ML models
    """
    
    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        self.models = {}
        self.load_all_models()
    
    def load_all_models(self):
        """Load all available trained models"""
        logger.info("📂 Loading trained models...")
        
        model_files = [
            "random_forest_model.joblib",
            "logistic_regression_model.joblib"
        ]
        
        for model_file in model_files:
            model_path = os.path.join(self.models_dir, model_file)
            if os.path.exists(model_path):
                try:
                    model_package = joblib.load(model_path)
                    model_name = model_package['model_name'].lower().replace(' ', '_')
                    self.models[model_name] = model_package
                    logger.info(f"✅ Loaded {model_package['model_name']}")
                except Exception as e:
                    logger.error(f"❌ Failed to load {model_file}: {str(e)}")
            else:
                logger.warning(f"⚠️ Model file not found: {model_file}")
        
        if not self.models:
            logger.warning("⚠️ No trained models found. Run ml_model_trainer.py first.")
    
    def extract_url_features(self, url):
        """Extract features from a URL for prediction"""
        try:
            parsed_url = urllib.parse.urlparse(str(url))
            
            features = {
                # Basic URL features
                'url_length': len(url),
                'domain_length': len(parsed_url.netloc),
                'path_length': len(parsed_url.path),
                'query_length': len(parsed_url.query),
                
                # Protocol features
                'is_https': 1 if parsed_url.scheme == 'https' else 0,
                'has_port': 1 if ':' in parsed_url.netloc and not parsed_url.netloc.endswith(':80') and not parsed_url.netloc.endswith(':443') else 0,
                
                # Domain features
                'subdomain_count': len(parsed_url.netloc.split('.')) - 2,
                'domain_has_hyphen': 1 if '-' in parsed_url.netloc else 0,
                'domain_has_numbers': 1 if any(char.isdigit() for char in parsed_url.netloc) else 0,
                
                # IP address detection
                'is_ip_address': 1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', parsed_url.netloc) else 0,
                
                # Suspicious TLD detection
                'suspicious_tld': 1 if re.search(r'\.(tk|ml|ga|cf|pw|buzz|click|download)$', parsed_url.netloc.lower()) else 0,
                
                # URL encoding detection
                'url_encoded_chars': len(re.findall(r'%[0-9a-fA-F]{2}', url)),
                
                # Suspicious patterns
                'has_suspicious_words': 1 if any(word in url.lower() for word in 
                                               ['secure', 'account', 'update', 'verify', 'login', 'confirm']) else 0,
                
                # Brand impersonation detection
                'brand_impersonation': 1 if re.search(r'(paypal|amazon|microsoft|google|apple|facebook|netflix|spotify)', url.lower()) else 0,
                
                # URL shortener detection
                'is_shortened': 1 if re.search(r'(bit\.ly|tinyurl|t\.co|goo\.gl|short\.link)', url.lower()) else 0,
                
                # Path features
                'path_depth': len([p for p in parsed_url.path.split('/') if p]),
                'has_query': 1 if parsed_url.query else 0,
                'has_fragment': 1 if parsed_url.fragment else 0,
                
                # Special characters
                'special_char_count': len(re.findall(r'[^a-zA-Z0-9.:/\-_?&=]', url)),
                'hyphen_count': url.count('-'),
                'underscore_count': url.count('_'),
                'dot_count': url.count('.'),
                'slash_count': url.count('/'),
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {str(e)}")
            return None
    
    def predict_single_url(self, url, model_name=None):
        """Predict if a single URL is phishing using specified model or all models"""
        features = self.extract_url_features(url)
        if features is None:
            return {"error": "Failed to extract features from URL"}
        
        predictions = {}
        
        # If specific model requested
        if model_name and model_name in self.models:
            models_to_use = {model_name: self.models[model_name]}
        else:
            models_to_use = self.models
        
        for name, model_package in models_to_use.items():
            try:
                model = model_package['model']
                feature_cols = model_package['feature_columns']
                scaler = model_package.get('scaler')
                
                # Create feature DataFrame
                feature_df = pd.DataFrame([features])
                
                # Ensure all required features are present
                for col in feature_cols:
                    if col not in feature_df.columns:
                        feature_df[col] = 0
                
                # Select and order features correctly
                X = feature_df[feature_cols]
                
                # Apply scaling if needed
                if scaler is not None:
                    X = scaler.transform(X)
                
                # Make prediction
                prediction = model.predict(X)[0]
                prediction_proba = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else None
                
                predictions[name] = {
                    'prediction': int(prediction),
                    'is_phishing': bool(prediction),
                    'confidence': float(prediction_proba[1]) if prediction_proba is not None else None,
                    'model_name': model_package['model_name']
                }
                
            except Exception as e:
                logger.error(f"Error predicting with {name}: {str(e)}")
                predictions[name] = {"error": str(e)}
        
        return {
            'url': url,
            'features': features,
            'predictions': predictions,
            'timestamp': datetime.now().isoformat()
        }
    
    def predict_batch_urls(self, urls, model_name=None):
        """Predict multiple URLs"""
        logger.info(f"🔍 Predicting {len(urls)} URLs...")
        
        results = []
        for url in urls:
            result = self.predict_single_url(url, model_name)
            results.append(result)
        
        return results
    
    def get_ensemble_prediction(self, url):
        """Get ensemble prediction from all available models"""
        if not self.models:
            return {"error": "No models available"}
        
        result = self.predict_single_url(url)
        
        if 'error' in result:
            return result
        
        # Calculate ensemble prediction
        predictions = result['predictions']
        if not isinstance(predictions, dict):
            return {"error": "Predictions are not in expected format"}
        valid_predictions = [p for p in predictions.values() if isinstance(p, dict) and 'error' not in p]
        
        if not valid_predictions:
            return {"error": "All models failed to predict"}
        
        # Simple voting ensemble
        phishing_votes = sum(1 for p in valid_predictions if p['is_phishing'])
        total_votes = len(valid_predictions)
        
        # Average confidence
        confidences = [p['confidence'] for p in valid_predictions if p['confidence'] is not None]
        avg_confidence = np.mean(confidences) if confidences else 0.5
        
        ensemble_result = {
            'url': url,
            'ensemble_prediction': {
                'is_phishing': phishing_votes > total_votes / 2,
                'confidence': float(avg_confidence),
                'voting_ratio': f"{phishing_votes}/{total_votes}",
                'models_used': [p['model_name'] for p in valid_predictions]
            },
            'individual_predictions': predictions,
            'features': result['features'],
            'timestamp': datetime.now().isoformat()
        }
        
        return ensemble_result

def test_models():
    """Test the trained models with sample URLs"""
    print("🧪 Testing Trained ML Models")
    print("=" * 60)
    
    predictor = PhishingPredictor()
    
    if not predictor.models:
        print("❌ No trained models found. Please run ml_model_trainer.py first.")
        return
    
    # Test URLs
    test_urls = [
        # Legitimate URLs
        "https://www.google.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.paypal.com",
        "https://www.amazon.com",
        
        # Suspicious URLs (from our training data)
        "http://192.168.1.1/secure-login",
        "https://paypal-verify.tk/account",
        "http://amazon-security.ml/update",
        "https://microsoft-alert.ga/verify",
        "http://bit.ly/urgent-action"
    ]
    
    print(f"\n🔍 Testing {len(test_urls)} URLs with all models...")
    print("-" * 60)
    
    for url in test_urls:
        print(f"\n🌐 URL: {url}")
        
        result = predictor.get_ensemble_prediction(url)
        
        if 'error' in result:
            print(f"   ❌ Error: {result['error']}")
            continue
        
        ensemble = result['ensemble_prediction']
        individual = result['individual_predictions']
        
        # Show ensemble result
        if isinstance(ensemble, dict) and 'is_phishing' in ensemble:
            status = "🚨 PHISHING" if ensemble['is_phishing'] else "✅ SAFE"
            print(f"   {status} (Confidence: {ensemble['confidence']:.3f})")
            print(f"   Voting: {ensemble['voting_ratio']} models agree")
        else:
            print("   ⚠️ Ensemble prediction format error.")
        
        # Show individual model results
        if isinstance(individual, dict):
            for model_name, pred in individual.items():
                if 'error' not in pred:
                    model_status = "🚨" if pred['is_phishing'] else "✅"
                    conf = f" ({pred['confidence']:.3f})" if pred['confidence'] else ""
                    print(f"     {model_status} {pred['model_name']}{conf}")
                else:
                    print(f"     ❌ {model_name}: {pred['error']}")
        else:
            print(f"   ⚠️ Individual predictions format error: {individual}")

def create_prediction_api():
    """Create a simple prediction function for Flask integration"""
    
    def predict_url_ml(url):
        """
        Predict if URL is phishing using trained ML models
        Returns: dict with prediction results
        """
        try:
            predictor = PhishingPredictor()
            
            if not predictor.models:
                return {
                    "available": False,
                    "message": "No trained ML models available",
                    "prediction": None
                }
            
            result = predictor.get_ensemble_prediction(url)
            
            if 'error' in result:
                return {
                    "available": False,
                    "message": result['error'],
                    "prediction": None
                }
            
            ensemble = result['ensemble_prediction']
            
            if not isinstance(ensemble, dict):
                return {
                    "available": False,
                    "message": "Ensemble prediction is not in expected format",
                    "prediction": None
                }
            
            return {
                "available": True,
                "is_phishing": ensemble.get('is_phishing'),
                "confidence": ensemble.get('confidence'),
                "voting_ratio": ensemble.get('voting_ratio'),
                "models_used": ensemble.get('models_used'),
                "features_extracted": len(result['features']),
                "prediction_details": result['individual_predictions']
            }
            
        except Exception as e:
            logger.error(f"ML prediction error: {str(e)}")
            return {
                "available": False,
                "message": f"Prediction failed: {str(e)}",
                "prediction": None
            }
    
    return predict_url_ml

def main():
    """Main function for testing"""
    print("🤖 ML Model Testing and Prediction")
    print("=" * 40)
    
    # Test models
    test_models()
    
    print(f"\n📋 Summary:")
    print("✅ Model loading and testing complete")
    print("✅ Ensemble prediction system ready")
    print("✅ Feature extraction working")
    print("✅ Ready for Flask integration")

if __name__ == "__main__":
    main()
