#!/usr/bin/env python3
"""
Simplified Flask App with ML Dataset Integration Demo
This version avoids heavy ML dependencies while demonstrating the concept
"""

from flask import Flask, render_template, request, jsonify
import re
import urllib.parse
import logging
import requests
import sqlite3
import json
import os
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration
DATABASE_PATH = 'phishing_detector.db'

# ML Integration Status
ML_DEMO_AVAILABLE = True

def init_database():
    """Initialize SQLite database with the required schema"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Create scan_records table with comprehensive schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL CHECK(input_type IN ('url', 'email')),
                input_content TEXT NOT NULL,
                result TEXT NOT NULL,
                is_safe BOOLEAN NOT NULL,
                confidence INTEGER NOT NULL,
                risk_score INTEGER DEFAULT 0,
                details TEXT,
                external_apis TEXT,
                user_ip TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                processing_time REAL DEFAULT 0.0
            )
        ''')
        
        # Create scan_statistics table for analytics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE NOT NULL,
                total_scans INTEGER DEFAULT 0,
                url_scans INTEGER DEFAULT 0,
                email_scans INTEGER DEFAULT 0,
                phishing_detected INTEGER DEFAULT 0,
                safe_results INTEGER DEFAULT 0,
                avg_confidence REAL DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_records_timestamp ON scan_records(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_records_type ON scan_records(input_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_statistics_date ON scan_statistics(date)')
        
        conn.commit()
        conn.close()
        
        logger.info("✅ Database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")
        return False

def check_url_phishing(url, include_external_apis=False):
    """Check if URL is potentially phishing with advanced pattern matching"""
    url_lower = url.lower()
    
    # Advanced IP-based URL detection patterns
    ip_patterns = [
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # Standard IPv4
        r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # HTTP(S) with IP
    ]
    
    # Hex-encoded character detection patterns
    hex_patterns = [
        r'%[0-9a-fA-F]{2}',  # URL-encoded hex characters
        r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
    ]
    
    # Known suspicious domain patterns
    suspicious_domain_patterns = [
        r'[a-zA-Z0-9]+-[a-zA-Z0-9]+\.(tk|ml|ga|cf|pw|buzz)',  # Free TLD abuse
        r'(amazon|paypal|microsoft|google|apple|facebook).*\.(tk|ml|ga|cf)',
    ]
    
    # URL shortener patterns
    url_shortener_patterns = [
        r'bit\.ly|tinyurl|t\.co|short\.link|goo\.gl',
    ]
    
    is_phishing = False
    confidence = 0
    risk_score = 0
    threats_detected = []
    
    # Check for IP-based URLs
    for pattern in ip_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            is_phishing = True
            confidence += 30
            risk_score += 25
            threats_detected.append("IP-based URL detected")
            break
    
    # Check for hex-encoded characters
    hex_matches = 0
    for pattern in hex_patterns:
        matches = re.findall(pattern, url, re.IGNORECASE)
        hex_matches += len(matches)
    
    if hex_matches > 0:
        is_phishing = True
        confidence += min(hex_matches * 10, 30)
        risk_score += min(hex_matches * 5, 20)
        threats_detected.append(f"Hex-encoded characters detected ({hex_matches})")
    
    # Check for suspicious domain patterns
    for pattern in suspicious_domain_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            is_phishing = True
            confidence += 40
            risk_score += 30
            threats_detected.append("Suspicious domain pattern detected")
            break
    
    # Check for URL shorteners
    for pattern in url_shortener_patterns:
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
        threats_detected.append("Excessive hyphens in URL")
    
    # Ensure confidence doesn't exceed 100
    confidence = min(confidence, 100)
    risk_score = min(risk_score, 100)
    
    # Determine if phishing based on confidence threshold
    if confidence >= 30:
        is_phishing = True
    
    return {
        'is_phishing': is_phishing,
        'confidence': confidence,
        'risk_score': risk_score,
        'threats_detected': threats_detected,
        'analysis_details': {
            'url_length': len(url),
            'hyphen_count': url.count('-'),
            'suspicious_patterns': len(threats_detected)
        }
    }

def save_scan_record(input_type, input_content, result, is_safe, confidence, risk_score=0, details=None, user_ip=None, processing_time=0.0):
    """Save scan record to database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_records 
            (input_type, input_content, result, is_safe, confidence, risk_score, details, user_ip, processing_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (input_type, input_content, result, is_safe, confidence, risk_score, 
              json.dumps(details) if details else None, user_ip, processing_time))
        
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Saved scan record: {input_type} - {result}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to save scan record: {str(e)}")
        return False

# ML Dataset Integration (Demo Version)
def get_ml_dataset_status():
    """Get status of ML datasets"""
    try:
        data_dir = "data"
        
        dataset_files = {
            "combined_dataset": os.path.exists(os.path.join(data_dir, "combined_phishing_dataset.csv")),
            "feature_dataset": os.path.exists(os.path.join(data_dir, "feature_dataset.csv")),
            "train_dataset": os.path.exists(os.path.join(data_dir, "train_dataset.csv")),
            "test_dataset": os.path.exists(os.path.join(data_dir, "test_dataset.csv"))
        }
        
        # Try to load statistics
        stats_file = os.path.join(data_dir, "dataset_statistics.json")
        statistics = {}
        
        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r') as f:
                    statistics = json.load(f)
            except:
                statistics = {}
        
        return {
            "status": "ready",
            "statistics": statistics,
            "files": dataset_files,
            "datasets_ready": all(dataset_files.values())
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def prepare_ml_datasets():
    """Prepare ML datasets using the demo script"""
    try:
        logger.info("🚀 Starting ML dataset preparation...")
        
        # Run the ML demo script
        import subprocess
        import sys
        
        result = subprocess.run([
            sys.executable, "ml_demo.py"
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            # Get updated statistics
            status = get_ml_dataset_status()
            
            return {
                "status": "success",
                "message": "ML datasets prepared successfully",
                "statistics": status.get("statistics", {}),
                "files_created": [
                    "data/combined_phishing_dataset.csv",
                    "data/feature_dataset.csv", 
                    "data/train_dataset.csv",
                    "data/test_dataset.csv",
                    "data/dataset_statistics.json"
                ],
                "output": result.stdout
            }
        else:
            return {
                "status": "error", 
                "message": f"Dataset preparation failed: {result.stderr}"
            }
            
    except Exception as e:
        logger.error(f"❌ ML dataset preparation failed: {str(e)}")
        return {"status": "error", "message": str(e)}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        input_type = data.get('type')
        input_value = data.get('input', '').strip()
        
        if not input_value:
            return jsonify({'error': 'Input value is required'}), 400
        
        start_time = datetime.now()
        
        if input_type == 'url':
            result = check_url_phishing(input_value)
            
            # Save to database
            save_scan_record(
                input_type='url',
                input_content=input_value,
                result='Phishing' if result['is_phishing'] else 'Safe',
                is_safe=not result['is_phishing'],
                confidence=result['confidence'],
                risk_score=result['risk_score'],
                details=result,
                user_ip=request.remote_addr,
                processing_time=(datetime.now() - start_time).total_seconds()
            )
            
            return jsonify({
                'success': True,
                'result': 'Phishing' if result['is_phishing'] else 'Safe',
                'confidence': result['confidence'],
                'risk_score': result['risk_score'],
                'threats_detected': result['threats_detected'],
                'details': result['analysis_details']
            })
        
        else:
            return jsonify({'error': 'Invalid input type'}), 400
            
    except Exception as e:
        logger.error(f"Error in scan: {str(e)}")
        return jsonify({'error': 'Scan failed'}), 500

@app.route('/api/ml/status')
def ml_status_api():
    """API endpoint to get ML dataset status"""
    try:
        status = get_ml_dataset_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting ML status: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ml/prepare', methods=['POST'])
def ml_prepare_api():
    """API endpoint to prepare ML datasets"""
    try:
        result = prepare_ml_datasets()
        
        if result['status'] == 'success':
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Error preparing ML datasets: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/ml-dashboard')
def ml_dashboard():
    """ML Dashboard for dataset management and preparation"""
    return render_template('ml_dashboard.html')

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard to view statistics"""
    return render_template('admin.html')

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connectivity
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scan_records')
        total_records = cursor.fetchone()[0]
        conn.close()
        
        # Check ML status
        ml_status = get_ml_dataset_status()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'total_records': total_records,
            'ml_available': ML_DEMO_AVAILABLE,
            'ml_datasets_ready': ml_status.get('datasets_ready', False),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    # Initialize database on startup
    init_database()
    logger.info("Starting Flask application with ML dataset integration demo")
    logger.info("🤖 ML Dataset preparation available - use /ml-dashboard to manage datasets")
    
    app.run(debug=True)
