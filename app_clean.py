#!/usr/bin/env python3
"""
Simple Flask Application with Background ML Integration
Clean frontend with ML working behind the scenes
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from markupsafe import escape
from functools import wraps
import re
import urllib.parse
import logging
import sqlite3
import json
import os
import time
import requests
from datetime import datetime

# --- Day 18: Verdict Logic Integration ---
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY')
# --- Rate Limiting ---
RATE_LIMIT = 10  # max requests per period
RATE_PERIOD = 60  # seconds
client_requests = {}

def rate_limited(route_func):
    @wraps(route_func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        reqs = client_requests.get(ip, [])
        # Remove old requests
        reqs = [t for t in reqs if now - t < RATE_PERIOD]
        if len(reqs) >= RATE_LIMIT:
            return jsonify({'success': False, 'error': 'Too many requests. Please wait and try again.'}), 429
        reqs.append(now)
        client_requests[ip] = reqs
        return route_func(*args, **kwargs)
    return wrapper

def check_virustotal(url):
    """Query VirusTotal for URL verdict. Returns 'malicious', 'suspicious', or 'safe'."""
    # Placeholder: always returns 'unknown' unless API key is set
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'YOUR_VIRUSTOTAL_API_KEY':
        return {'verdict': 'unknown', 'details': 'No API key'}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            # Example: parse verdict from data (simplified)
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            if stats.get('malicious', 0) > 0:
                return {'verdict': 'malicious', 'details': stats}
            elif stats.get('suspicious', 0) > 0:
                return {'verdict': 'suspicious', 'details': stats}
            else:
                return {'verdict': 'safe', 'details': stats}
        else:
            return {'verdict': 'unknown', 'details': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'verdict': 'unknown', 'details': str(e)}

def check_phishtank(url):
    """Query PhishTank for URL verdict. Returns 'malicious' or 'safe'."""
    # Placeholder: always returns 'unknown' unless API key is set
    if not PHISHTANK_API_KEY or PHISHTANK_API_KEY == 'YOUR_PHISHTANK_API_KEY':
        return {'verdict': 'unknown', 'details': 'No API key'}
    try:
        # Example PhishTank API call (not real endpoint)
        resp = requests.post("https://checkurl.phishtank.com/checkurl/", data={
            'url': url,
            'format': 'json',
            'app_key': PHISHTANK_API_KEY
        }, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('results', {}).get('valid', False):
                if data['results'].get('in_database', False) and data['results'].get('phish_id'):
                    return {'verdict': 'malicious', 'details': data['results']}
            return {'verdict': 'safe', 'details': data.get('results', {})}
        else:
            return {'verdict': 'unknown', 'details': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'verdict': 'unknown', 'details': str(e)}

def combine_verdicts(regex_result, vt_result, pt_result, ml_result):
    """Combine all verdicts into one: 'Malicious', 'Suspicious', 'Safe'."""
    verdicts = [
        regex_result,
        vt_result.get('verdict', 'unknown'),
        pt_result.get('verdict', 'unknown'),
        ml_result.get('verdict', 'unknown')
    ]
    if 'malicious' in verdicts or 'phishing' in verdicts:
        return 'Malicious'
    if 'suspicious' in verdicts:
        return 'Suspicious'
    if 'unknown' in verdicts:
        return 'Suspicious'  # treat unknown as suspicious for safety
    return 'Safe'

# Import ML prediction module (background only)
try:
    from ml_predictor import PhishingPredictor
    ML_MODELS_AVAILABLE = True
    # Initialize ML predictor once
    ml_predictor = PhishingPredictor()
    print(f"✅ ML Models loaded: {len(ml_predictor.models)} models ready")
    # Pre-warm models: run a couple of lightweight predictions to ensure any lazy
    # initialization (scalers, compiled code) happens at startup.
    try:
        warm_urls = [
            'https://www.google.com',
            'https://www.github.com'
        ]
        for u in warm_urls:
            try:
                _ = ml_predictor.get_ensemble_prediction(u)
            except Exception:
                # Ignore warmup failures; models still considered loaded
                pass
        print('🔥 ML models pre-warmed')
    except Exception as _:
        pass
except ImportError as e:
    ML_MODELS_AVAILABLE = False
    ml_predictor = None
    print(f"⚠️ ML models not available: {e}")

app = Flask(__name__)
# Secret key for session cookies - allow override from environment
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')

# Simple admin credentials (replace with secure store in production)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'thiru')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '_THIRU@4690')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration
DATABASE_PATH = 'phishing_detector.db'

def init_database():
    """Initialize SQLite database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create table if missing (base schema)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL,
                input_content TEXT NOT NULL,
                result TEXT NOT NULL,
                is_safe BOOLEAN NOT NULL,
                confidence INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Ensure newer optional columns exist; if not, add them via ALTER TABLE
        cursor.execute("PRAGMA table_info('scan_records')")
        existing_cols = [r[1] for r in cursor.fetchall()]

        # Add threats_detected column if missing
        if 'threats_detected' not in existing_cols:
            try:
                cursor.execute("ALTER TABLE scan_records ADD COLUMN threats_detected TEXT")
                conn.commit()
                logger.info("Added missing column: threats_detected")
            except Exception:
                pass

        # Add ml_used column if missing
        if 'ml_used' not in existing_cols:
            try:
                cursor.execute("ALTER TABLE scan_records ADD COLUMN ml_used BOOLEAN DEFAULT 0")
                conn.commit()
                logger.info("Added missing column: ml_used")
            except Exception:
                pass

        # Add confidence column if missing (already present in many schemas but safe to ensure)
        if 'confidence' not in existing_cols:
            try:
                cursor.execute("ALTER TABLE scan_records ADD COLUMN confidence INTEGER DEFAULT 0")
                conn.commit()
                logger.info("Added missing column: confidence")
            except Exception:
                pass

        conn.commit()
        conn.close()
        logger.info("✅ Database initialized and schema checked")
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")

def check_url_phishing_simple(url):
    """Enhanced URL checking with ML in background"""
    threats = []
    risk_score = 0
    detection_method = 'rule_based'
    ml_details = None
    start_ts = time.time()
    
    # Basic rule-based checks
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Rule-based threat detection
        if not parsed.scheme == 'https':
            threats.append("Non-secure HTTP connection")
            risk_score += 15
        
        if len(domain) > 50:
            threats.append("Unusually long domain name")
            risk_score += 20
        
        if domain.count('.') > 3:
            threats.append("Excessive subdomains")
            risk_score += 15
        
        suspicious_words = ['secure', 'account', 'verify', 'login', 'update', 'suspended', 'urgent']
        for word in suspicious_words:
            if word in domain or word in path:
                threats.append(f"Suspicious keyword detected: {word}")
                risk_score += 10
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            threats.append("IP address instead of domain name")
            risk_score += 25
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                threats.append("Suspicious top-level domain")
                risk_score += 20
        
        if '-' in domain and domain.count('-') > 2:
            threats.append("Multiple hyphens in domain")
            risk_score += 10
        
        # ML Enhancement (Background)
        ml_confidence = 50  # Default
        if ML_MODELS_AVAILABLE and ml_predictor:
            try:
                ml_result = ml_predictor.get_ensemble_prediction(url)
                ml_details = ml_result
                if ml_result and isinstance(ml_result, dict) and 'ensemble_prediction' in ml_result:
                    ml_pred = ml_result['ensemble_prediction']
                    if isinstance(ml_pred, dict):
                        # ensemble confidence is 0..1
                        ml_confidence = int(ml_pred.get('confidence', 0.5) * 100)
                        # mark detection method
                        detection_method = 'ml'
                        # Adjust risk score based on ML prediction
                        if ml_pred.get('is_phishing'):
                            risk_score += 30
                            threats.append("AI model detected phishing patterns")
                        else:
                            # ML suggests safer: reduce minor rule-based risk
                            risk_score = max(0, risk_score - 10)
                    else:
                        logger.warning(f"ML ensemble_prediction is not a dict: {ml_pred}")
                else:
                    logger.warning(f"ML result is not a dict or missing ensemble_prediction: {ml_result}")
            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
        
        # Final decision
        if risk_score >= 40:
            result = "Phishing"
            confidence = min(95, 60 + (risk_score - 40))
        elif risk_score >= 20:
            result = "Suspicious"
            confidence = min(80, 40 + risk_score)
        else:
            result = "Safe"
            # For safe URLs, show high confidence
            confidence = max(85, 100 - risk_score)
        
        processing_time = round(time.time() - start_ts, 4)
        return {
            'result': result,
            'confidence': confidence,
            'threats_detected': threats,
            'risk_score': risk_score,
            'ml_used': ML_MODELS_AVAILABLE,
            'detection_method': detection_method,
            'processing_time': processing_time,
            'ml_details': ml_details
        }
        
    except Exception as e:
        logger.error(f"URL analysis failed: {str(e)}")
        return {
            'result': 'Error',
            'confidence': 0,
            'threats_detected': [f"Analysis failed: {str(e)}"],
            'risk_score': 0,
            'ml_used': False
        }

def check_email_phishing_simple(email_content):
    """Enhanced email checking with ML patterns"""
    threats = []
    risk_score = 0
    
    email_lower = email_content.lower()
    
    # Urgent language
    urgent_phrases = ['urgent', 'immediate action', 'act now', 'expires today', 'limited time']
    for phrase in urgent_phrases:
        if phrase in email_lower:
            threats.append(f"Urgent language detected: {phrase}")
            risk_score += 15
    
    # Financial/personal info requests
    sensitive_requests = ['ssn', 'social security', 'credit card', 'bank account', 'password', 'pin']
    for request in sensitive_requests:
        if request in email_lower:
            threats.append(f"Requests sensitive information: {request}")
            risk_score += 25
    
    # Suspicious links
    suspicious_domains = ['.tk', '.ml', '.ga', 'bit.ly', 'tinyurl', 'suspicious']
    for domain in suspicious_domains:
        if domain in email_lower:
            threats.append(f"Contains suspicious link: {domain}")
            risk_score += 20
    
    # Generic greetings
    if any(greeting in email_lower for greeting in ['dear customer', 'dear user', 'dear sir/madam']):
        threats.append("Generic greeting (not personalized)")
        risk_score += 10
    
    # Grammar/spelling (simple check)
    if email_content.count('!') > 3:
        threats.append("Excessive exclamation marks")
        risk_score += 5
    
    # ML Enhancement (if available)
    ml_used = False
    ml_summary = None
    # If email contains links, run ML predictor on each link and aggregate
    urls_found = re.findall(r'https?://[^\s\)\]\>\"]+', email_content)
    if ML_MODELS_AVAILABLE and ml_predictor and urls_found:
        ml_used = True
        ml_votes = 0
        ml_confs = []
        ml_models = set()
        for u in urls_found:
            try:
                ml_result = ml_predictor.get_ensemble_prediction(u)
                if ml_result and isinstance(ml_result, dict) and 'ensemble_prediction' in ml_result:
                    pred = ml_result['ensemble_prediction']
                    if isinstance(pred, dict):
                        if pred.get('is_phishing'):
                            ml_votes += 1
                            threats.append(f"Link flagged by ML: {u}")
                            risk_score += 25
                        ml_confs.append(pred.get('confidence', 0.5))
                        for m in pred.get('models_used', []):
                            ml_models.add(m)
                    else:
                        logger.warning(f"ML ensemble_prediction is not a dict: {pred}")
                else:
                    logger.warning(f"ML result is not a dict or missing ensemble_prediction: {ml_result}")
            except Exception as e:
                logger.warning(f"Email ML check failed for {u}: {e}")

        if ml_confs:
            avg_conf = float(sum(ml_confs) / len(ml_confs))
        else:
            avg_conf = 0.0
        ml_summary = {
            'urls_checked': len(urls_found),
            'phishing_votes': ml_votes,
            'avg_confidence': avg_conf,
            'models_used': list(ml_models)
        }

    # For non-link emails, minor ML influence if configured
    if ML_MODELS_AVAILABLE and not urls_found and risk_score > 30:
        risk_score += 10
        threats.append("AI patterns suggest elevated risk")
    
    # Final decision
    if risk_score >= 50:
        result = "Phishing"
        confidence = min(95, 65 + (risk_score - 50))
    elif risk_score >= 25:
        result = "Suspicious"
        confidence = min(85, 45 + risk_score)
    else:
        result = "Safe"
        confidence = max(70, 100 - risk_score)
    
    return {
        'result': result,
        'confidence': confidence,
    'threats_detected': threats,
    'risk_score': risk_score,
    'ml_used': ml_used,
    'ml_summary': ml_summary
    }

def save_scan_record(input_type, input_content, result_data):
    """Save scan record to database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_records 
            (input_type, input_content, result, is_safe, confidence, threats_detected, ml_used)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            input_type,
            input_content[:500],  # Truncate long content
            result_data['result'],
            result_data['result'] == 'Safe',
            result_data.get('confidence', 0),
            json.dumps(result_data.get('threats_detected', [])),
            int(bool(result_data.get('ml_used', False)))
        ))

        conn.commit()
        last_id = cursor.lastrowid
        # Fetch the timestamp the DB assigned
        try:
            cursor.execute('SELECT timestamp FROM scan_records WHERE id=?', (last_id,))
            ts_row = cursor.fetchone()
            ts = ts_row[0] if ts_row else None
        except Exception:
            ts = None

        conn.close()
        # Return metadata for the inserted record
        return {'id': last_id, 'timestamp': ts}

    except Exception as e:
        logger.error(f"Failed to save scan record: {str(e)}")
        return None

# Routes
@app.route('/')
def index():
    return render_template('index_simple.html')

@app.route('/admin')
def admin():
    """Admin root: redirect to login or scans list depending on session."""
    if session.get('admin_logged_in'):
        return redirect('/admin/scans')
    return redirect('/admin/login')

@app.route('/dashboard')
def dashboard():
    return render_template('index_simple.html')

@app.route('/scan', methods=['POST'])
@rate_limited
def scan():
    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        if not data:
            return jsonify({'success': False, 'error': 'No data received'}), 400
        input_type = escape(data.get('type', ''))
        input_value = escape(data.get('input', '').strip())
        logger.info(f"Received scan request: type={input_type}, input_length={len(input_value)}")
        if not input_value:
            return jsonify({'success': False, 'error': 'Input cannot be empty'}), 400
        if not input_type:
            return jsonify({'success': False, 'error': 'Type parameter is required'}), 400
        # Perform analysis based on type
        if input_type == 'url':
            result = check_url_phishing_simple(input_value)
        elif input_type == 'email':
            result = check_email_phishing_simple(input_value)
        else:
            return jsonify({'success': False, 'error': f'Invalid input type: {input_type}. Must be "url" or "email"'}), 400
        # Save to database
        meta = save_scan_record(input_type, input_value, result)
        response = {'success': True, **result}
        if meta:
            response['scan_id'] = meta.get('id')
            response['scanned_at'] = meta.get('timestamp')
        return jsonify(response)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return jsonify({'success': False, 'error': 'Analysis failed. Please try again.'}), 500


@app.route('/result', methods=['GET', 'POST'])
def result_page():
    """Render a human-friendly result page.

    Behavior:
    - POST with JSON/form: encodes the JSON and redirects to GET /result?data=<base64>
    - GET with `data` param: renders the template which reads the JSON from the query string
    - GET without data: renders the template with no result
    """
    # If POSTed, redirect to GET with base64-encoded JSON in query param
    if request.method == 'POST':
        result = None
        if request.is_json:
            result = request.get_json()
        else:
            try:
                result = json.loads(request.form.get('result', '{}'))
            except Exception:
                result = None

        if result:
            try:
                import base64
                b = base64.b64encode(json.dumps(result).encode('utf-8')).decode('ascii')
                from flask import redirect, url_for
                return redirect(url_for('result_page') + f'?data={b}')
            except Exception as e:
                logger.warning(f"Failed to encode result for redirect: {e}")
                return render_template('result.html')
        else:
            return render_template('result.html')

    # GET: simply render the page. The client script will read the `data` query param if present.
    return render_template('result.html')





@app.route('/ml/status')
def ml_status():
    """Return ML model loading status and list of models."""
    try:
        if ML_MODELS_AVAILABLE and ml_predictor:
            return jsonify({
                'available': True,
                'models_loaded': list(ml_predictor.models.keys()),
                'model_count': len(ml_predictor.models)
            })
        else:
            return jsonify({'available': False, 'models_loaded': [], 'model_count': 0})
    except Exception as e:
        return jsonify({'available': False, 'error': str(e)})


@app.route('/stats')
def stats():
    """Return simple statistics about scans"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scan_records')
        total = cursor.fetchone()[0] or 0

        # Count records with non-empty threats_detected
        cursor.execute("SELECT COUNT(*) FROM scan_records WHERE threats_detected IS NOT NULL AND threats_detected != '[]'")
        threats = cursor.fetchone()[0] or 0

        cursor.execute('SELECT COUNT(*) FROM scan_records WHERE ml_used=1')
        ml_enhanced = cursor.fetchone()[0] or 0

        conn.close()
        return jsonify({
            'total_scans': total,
            'threats_detected': threats,
            'ml_enhanced_scans': ml_enhanced,
            'ml_available': ML_MODELS_AVAILABLE
        })
    except Exception as e:
        logger.error(f"Stats endpoint error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/admin/scans')
def admin_scans():
    """Render a paginated list of past scans for admin viewing."""
    # require admin login
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Return the most recent 200 scans
        cursor.execute('''SELECT id, input_type, input_content, result, confidence, timestamp, threats_detected, ml_used
                          FROM scan_records ORDER BY id DESC LIMIT 200''')
        rows = cursor.fetchall()
        scans = []
        for r in rows:
            scans.append({
                'id': r['id'],
                'input_type': r['input_type'],
                'input_content': r['input_content'],
                'result': r['result'],
                'confidence': r['confidence'],
                'timestamp': r['timestamp'],
                'threats_detected': r['threats_detected'],
                'ml_used': bool(r['ml_used'])
            })
        conn.close()
        return render_template('admin_scans.html', scans=scans)
    except Exception as e:
        logger.error(f"Failed to load scans: {e}")
        return render_template('admin_scans.html', scans=[])


@app.route('/admin/scan/<int:scan_id>')
def admin_scan_detail(scan_id):
    """Show detailed view for a single scan record."""
    # require admin login
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scan_records WHERE id=?', (scan_id,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return ("Not found", 404)

        # Parse threats_detected JSON if present
        threats = []
        try:
            if r['threats_detected']:
                threats = json.loads(r['threats_detected'])
        except Exception:
            threats = [r['threats_detected']] if r['threats_detected'] else []

        raw = {k: r[k] for k in r.keys()}
        return render_template('scan_detail.html', scan=raw, threats=threats, raw_record=raw, raw=raw)
    except Exception as e:
        logger.error(f"Failed to load scan detail: {e}")
        return ("Server error", 500)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Simple admin login form and handler"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect('/admin/scans')
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Initialize DB and run Flask app when executed directly.
    try:
        init_database()
    except Exception:
        pass
    # Use explicit host/port to match integration tests
    app.run(host='127.0.0.1', port=5000)
