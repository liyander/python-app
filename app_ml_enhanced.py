#!/usr/bin/env python3
"""
Enhanced Flask Application with ML Model Integration
Day 13: Integrates trained Random Forest and Logistic Regression models
"""

from flask import Flask, render_template, request, jsonify
import re
import urllib.parse
import logging
import sqlite3
import json
import os
from datetime import datetime

# Import ML prediction module
try:
    from ml_predictor import PhishingPredictor, create_prediction_api
    ML_MODELS_AVAILABLE = True
    predict_url_ml = create_prediction_api()
except ImportError as e:
    ML_MODELS_AVAILABLE = False
    predict_url_ml = None
    # Define a dummy predictor to avoid unbound errors
    class DummyPhishingPredictor:
        def __init__(self):
            self.models = {}
    PhishingPredictor = DummyPhishingPredictor
    logging.warning(f"ML models not available: {e}")

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration
DATABASE_PATH = 'phishing_detector.db'

def init_database():
    """Initialize SQLite database with the required schema"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Create scan_records table with ML integration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL CHECK(input_type IN ('url', 'email')),
                input_content TEXT NOT NULL,
                result TEXT NOT NULL,
                is_safe BOOLEAN NOT NULL,
                confidence INTEGER NOT NULL,
                risk_score INTEGER DEFAULT 0,
                ml_prediction TEXT,
                ml_confidence REAL,
                detection_method TEXT DEFAULT 'rule_based',
                details TEXT,
                user_ip TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                processing_time REAL DEFAULT 0.0
            )
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info("✅ Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")
        return False

def check_url_phishing_advanced(url, use_ml=True):
    """Enhanced phishing detection using both rule-based and ML approaches"""
    start_time = datetime.now()
    
    # Rule-based detection (existing logic)
    rule_result = check_url_phishing_basic(url)
    
    # ML-based detection
    ml_result = None
    if use_ml and ML_MODELS_AVAILABLE and predict_url_ml:
        try:
            ml_result = predict_url_ml(url)
        except Exception as e:
            logger.error(f"ML prediction failed: {str(e)}")
            ml_result = {"available": False, "message": str(e)}
    
    # Combine results
    combined_result = combine_predictions(rule_result, ml_result, url)
    combined_result['processing_time'] = (datetime.now() - start_time).total_seconds()
    
    return combined_result

def check_url_phishing_basic(url):
    """Basic rule-based phishing detection"""
    url_lower = url.lower()
    
    # IP-based URL detection
    ip_patterns = [
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
    ]
    
    # Suspicious domain patterns
    suspicious_patterns = [
        r'[a-zA-Z0-9]+-[a-zA-Z0-9]+\.(tk|ml|ga|cf|pw|buzz)',
        r'(amazon|paypal|microsoft|google|apple|facebook).*\.(tk|ml|ga|cf)',
    ]
    
    # URL shortener patterns
    shortener_patterns = [
        r'bit\.ly|tinyurl|t\.co|short\.link|goo\.gl',
    ]
    
    is_phishing = False
    confidence = 0
    risk_score = 0
    threats_detected = []
    
    # Check patterns
    for pattern in ip_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            is_phishing = True
            confidence += 30
            risk_score += 25
            threats_detected.append("IP-based URL detected")
            break
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            is_phishing = True
            confidence += 40
            risk_score += 30
            threats_detected.append("Suspicious domain pattern")
            break
    
    for pattern in shortener_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            confidence += 15
            risk_score += 10
            threats_detected.append("URL shortener detected")
            break
    
    # Additional checks
    if len(url) > 150:
        confidence += 10
        risk_score += 5
        threats_detected.append("Unusually long URL")
    
    if url.count('-') > 5:
        confidence += 10
        risk_score += 5
        threats_detected.append("Excessive hyphens")
    
    confidence = min(confidence, 100)
    risk_score = min(risk_score, 100)
    
    if confidence >= 30:
        is_phishing = True
    
    return {
        'method': 'rule_based',
        'is_phishing': is_phishing,
        'confidence': confidence / 100.0,  # Normalize to 0-1
        'risk_score': risk_score,
        'threats_detected': threats_detected
    }

def combine_predictions(rule_result, ml_result, url):
    """Combine rule-based and ML predictions intelligently"""
    
    # Start with rule-based result
    final_result = {
        'url': url,
        'is_phishing': rule_result['is_phishing'],
        'confidence': rule_result['confidence'],
        'risk_score': rule_result['risk_score'],
        'threats_detected': rule_result['threats_detected'].copy(),
        'detection_method': 'rule_based',
        'ml_available': ML_MODELS_AVAILABLE and ml_result and ml_result.get('available', False),
        'rule_based': rule_result
    }
    
    # Add ML prediction if available
    if ml_result and ml_result.get('available', False):
        final_result['ml_prediction'] = ml_result
        final_result['detection_method'] = 'hybrid'
        
        # Ensemble logic: combine rule-based and ML predictions
        ml_confidence = ml_result.get('confidence', 0.5)
        ml_is_phishing = ml_result.get('is_phishing', False)
        
        # Weighted average of confidences (70% ML, 30% rule-based)
        combined_confidence = (0.7 * ml_confidence) + (0.3 * rule_result['confidence'])
        
        # Final decision: if either method strongly indicates phishing, flag it
        if ml_is_phishing and ml_confidence > 0.7:
            final_result['is_phishing'] = True
            final_result['threats_detected'].append(f"ML models detected phishing ({ml_result.get('voting_ratio', 'N/A')})")
        elif rule_result['is_phishing'] and rule_result['confidence'] > 0.7:
            final_result['is_phishing'] = True
        else:
            # Use ML prediction as primary if confidence is high
            if ml_confidence > 0.6:
                final_result['is_phishing'] = ml_is_phishing
            
        final_result['confidence'] = combined_confidence
        final_result['ml_confidence'] = ml_confidence
        
        # Add ML model information
        if 'models_used' in ml_result:
            final_result['threats_detected'].append(f"ML analysis: {len(ml_result['models_used'])} models")
    
    return final_result

def save_scan_record_ml(input_type, input_content, result, processing_time=0.0):
    """Save scan record with ML integration"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Extract ML information
        ml_prediction = None
        ml_confidence = None
        detection_method = result.get('detection_method', 'rule_based')
        
        if 'ml_prediction' in result:
            ml_prediction = json.dumps(result['ml_prediction'])
            ml_confidence = result.get('ml_confidence')
        
        cursor.execute('''
            INSERT INTO scan_records 
            (input_type, input_content, result, is_safe, confidence, risk_score, 
             ml_prediction, ml_confidence, detection_method, details, user_ip, processing_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            input_type, 
            input_content, 
            'Phishing' if result['is_phishing'] else 'Safe',
            not result['is_phishing'],
            int(result['confidence'] * 100),
            result.get('risk_score', 0),
            ml_prediction,
            ml_confidence,
            detection_method,
            json.dumps(result),
            request.remote_addr if request else None,
            processing_time
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Saved scan record with ML data")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to save scan record: {str(e)}")
        return False

# Routes
@app.route('/')
def index():
    return render_template('index_ml.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        input_type = data.get('type')
        input_value = data.get('input', '').strip()
        use_ml = data.get('use_ml', True)
        
        if not input_value:
            return jsonify({'error': 'Input value is required'}), 400
        
        if input_type == 'url':
            result = check_url_phishing_advanced(input_value, use_ml=use_ml)
            
            # Save to database
            save_scan_record_ml('url', input_value, result, result.get('processing_time', 0))
            
            # Prepare response
            response = {
                'success': True,
                'result': 'Phishing' if result['is_phishing'] else 'Safe',
                'confidence': int(result['confidence'] * 100),
                'risk_score': result.get('risk_score', 0),
                'threats_detected': result['threats_detected'],
                'detection_method': result['detection_method'],
                'ml_available': result['ml_available'],
                'processing_time': result.get('processing_time', 0)
            }
            
            # Add ML details if available
            if 'ml_prediction' in result:
                response['ml_details'] = {
                    'confidence': result['ml_confidence'],
                    'models_used': result['ml_prediction'].get('models_used', []),
                    'voting_ratio': result['ml_prediction'].get('voting_ratio', 'N/A')
                }
            
            return jsonify(response)
        
        else:
            return jsonify({'error': 'Only URL scanning supported in this version'}), 400
            
    except Exception as e:
        logger.error(f"Error in scan: {str(e)}")
        return jsonify({'error': 'Scan failed'}), 500

@app.route('/ml-status')
def ml_status():
    """Get ML models status"""
    if not ML_MODELS_AVAILABLE:
        return jsonify({
            'available': False,
            'message': 'ML models not available',
            'models': []
        })
    
    try:
        predictor = PhishingPredictor()
        models_info = []
        
        for name, model_package in predictor.models.items():
            models_info.append({
                'name': model_package['model_name'],
                'version': model_package.get('version', 'Unknown'),
                'created_at': model_package.get('created_at', 'Unknown'),
                'features': len(model_package.get('feature_columns', []))
            })
        
        return jsonify({
            'available': True,
            'models_loaded': len(predictor.models),
            'models': models_info,
            'prediction_ready': len(predictor.models) > 0
        })
        
    except Exception as e:
        return jsonify({
            'available': False,
            'message': f'Error checking ML status: {str(e)}',
            'models': []
        })

@app.route('/test-ml')
def test_ml():
    """Test ML models with sample URLs"""
    if not ML_MODELS_AVAILABLE:
        return jsonify({'error': 'ML models not available'}), 503
    
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/secure-login",
        "https://paypal-verify.tk/account"
    ]
    
    results = []
    for url in test_urls:
        result = check_url_phishing_advanced(url, use_ml=True)
        results.append({
            'url': url,
            'prediction': 'Phishing' if result['is_phishing'] else 'Safe',
            'confidence': result['confidence'],
            'method': result['detection_method']
        })
    
    return jsonify({
        'test_results': results,
        'ml_available': ML_MODELS_AVAILABLE
    })

@app.route('/api/health')
def health_check():
    """Enhanced health check with ML status"""
    try:
        # Test database connectivity
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scan_records')
        total_records = cursor.fetchone()[0]
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'total_records': total_records,
            'ml_models_available': ML_MODELS_AVAILABLE,
            'ml_models_loaded': len(PhishingPredictor().models) if ML_MODELS_AVAILABLE else 0,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard route"""
    return render_template('index_ml.html')

@app.route('/ml-dashboard')
def ml_dashboard():
    """ML dashboard route"""
    return render_template('index_ml.html')

@app.route('/dashboard')
def dashboard():
    """General dashboard route"""
    return render_template('index_ml.html')

if __name__ == '__main__':
    # Initialize database on startup
    init_database()
    
    if ML_MODELS_AVAILABLE:
        logger.info("✅ Flask application starting with ML model integration")
        logger.info("🤖 ML-enhanced phishing detection available")
        
        # Test ML models on startup
        try:
            predictor = PhishingPredictor()
            logger.info(f"✅ Loaded {len(predictor.models)} ML models")
        except Exception as e:
            logger.error(f"❌ ML model loading failed: {str(e)}")
    else:
        logger.warning("⚠️ Flask application starting without ML models")
        logger.warning("📝 Run ml_model_trainer.py to train models first")
    
    app.run(debug=True)
