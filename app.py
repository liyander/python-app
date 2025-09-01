from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import re
import urllib.parse
import logging
import requests
import base64
import time
import sqlite3
import json
from datetime import datetime
import os

app = Flask(__name__)
# Secret key for sessions (allow override via environment)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')

# Simple admin credentials (override with env vars in production)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'thiru')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '_THIRU@4690')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration
DATABASE_PATH = 'phishing_detector.db'

# API Configuration
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your actual API key
PHISHTANK_API_KEY = "YOUR_PHISHTANK_API_KEY"  # Replace with your actual API key

# API URLs
VT_URL = "https://www.virustotal.com/api/v3/urls"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"

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
        
        # Create indexes for better query performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_records(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_input_type ON scan_records(input_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_safe ON scan_records(is_safe)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_ip ON scan_records(user_ip)')
        
        # Create statistics table for analytics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE NOT NULL,
                total_scans INTEGER DEFAULT 0,
                url_scans INTEGER DEFAULT 0,
                email_scans INTEGER DEFAULT 0,
                safe_results INTEGER DEFAULT 0,
                suspicious_results INTEGER DEFAULT 0,
                avg_confidence REAL DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(date)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise


def require_admin(view_func):
    """Decorator to require admin login via session or HTTP Basic Auth."""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        # Session-based login first
        if session.get('admin_logged_in'):
            return view_func(*args, **kwargs)

        # Fallback to HTTP Basic Auth header
        auth = request.headers.get('Authorization')
        if auth and auth.startswith('Basic '):
            try:
                import base64
                creds = base64.b64decode(auth.split(None, 1)[1]).decode('utf-8')
                user, pwd = creds.split(':', 1)
                if user == ADMIN_USERNAME and pwd == ADMIN_PASSWORD:
                    # mark session for convenience
                    session['admin_logged_in'] = True
                    return view_func(*args, **kwargs)
            except Exception:
                pass

        # If client accepts HTML, redirect to login form; otherwise send 401 for API clients
        if request.accept_mimetypes.accept_html:
            return redirect('/admin/login')
        return ('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Admin Area"'})

    return wrapper

def save_scan_record(input_type, input_content, result, user_ip, processing_time=0.0, external_apis=None):
    """Save scan record to database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Prepare data for insertion
        details_json = json.dumps(result.get('details', []))
        external_apis_json = json.dumps(external_apis) if external_apis else None
        
        # Insert scan record
        cursor.execute('''
            INSERT INTO scan_records (
                input_type, input_content, result, is_safe, confidence, 
                details, external_apis, user_ip, processing_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            input_type,
            input_content[:1000],  # Limit content length for storage
            result.get('message', ''),
            result.get('is_safe', False),
            result.get('confidence', 0),
            details_json,
            external_apis_json,
            user_ip,
            processing_time
        ))
        
        record_id = cursor.lastrowid
        
        # Update daily statistics
        today = datetime.now().date()
        cursor.execute('''
            INSERT OR IGNORE INTO scan_statistics (date, total_scans, url_scans, email_scans, safe_results, suspicious_results)
            VALUES (?, 0, 0, 0, 0, 0)
        ''', (today,))
        
        # Update counters
        safe_increment = 1 if result.get('is_safe', False) else 0
        suspicious_increment = 1 if not result.get('is_safe', False) else 0
        url_increment = 1 if input_type == 'url' else 0
        email_increment = 1 if input_type == 'email' else 0
        
        cursor.execute('''
            UPDATE scan_statistics 
            SET total_scans = total_scans + 1,
                url_scans = url_scans + ?,
                email_scans = email_scans + ?,
                safe_results = safe_results + ?,
                suspicious_results = suspicious_results + ?,
                avg_confidence = (
                    SELECT AVG(confidence) FROM scan_records 
                    WHERE DATE(timestamp) = ?
                )
            WHERE date = ?
        ''', (url_increment, email_increment, safe_increment, suspicious_increment, today, today))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Scan record saved with ID: {record_id}")
        return record_id
        
    except sqlite3.Error as e:
        logger.error(f"Database save error: {e}")
        return None

def get_scan_history(limit=100, input_type=None):
    """Retrieve scan history from database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        if input_type:
            cursor.execute('''
                SELECT id, input_type, input_content, result, is_safe, confidence, timestamp
                FROM scan_records 
                WHERE input_type = ?
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (input_type, limit))
        else:
            cursor.execute('''
                SELECT id, input_type, input_content, result, is_safe, confidence, timestamp
                FROM scan_records 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        
        records = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        history = []
        for record in records:
            history.append({
                'id': record[0],
                'input_type': record[1],
                'input_content': record[2][:50] + '...' if len(record[2]) > 50 else record[2],
                'result': record[3],
                'is_safe': record[4],
                'confidence': record[5],
                'timestamp': record[6]
            })
        
        return history
        
    except sqlite3.Error as e:
        logger.error(f"Database query error: {e}")
        return []

def get_scan_statistics():
    """Get scan statistics from database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get overall statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN input_type = 'url' THEN 1 ELSE 0 END) as url_scans,
                SUM(CASE WHEN input_type = 'email' THEN 1 ELSE 0 END) as email_scans,
                SUM(CASE WHEN is_safe = 1 THEN 1 ELSE 0 END) as safe_results,
                SUM(CASE WHEN is_safe = 0 THEN 1 ELSE 0 END) as suspicious_results,
                AVG(confidence) as avg_confidence,
                AVG(processing_time) as avg_processing_time
            FROM scan_records
        ''')
        
        overall_stats = cursor.fetchone()
        
        # Get daily statistics for the last 30 days
        cursor.execute('''
            SELECT date, total_scans, safe_results, suspicious_results, avg_confidence
            FROM scan_statistics 
            ORDER BY date DESC 
            LIMIT 30
        ''')
        
        daily_stats = cursor.fetchall()
        conn.close()
        
        return {
            'overall': {
                'total_scans': overall_stats[0] or 0,
                'url_scans': overall_stats[1] or 0,
                'email_scans': overall_stats[2] or 0,
                'safe_results': overall_stats[3] or 0,
                'suspicious_results': overall_stats[4] or 0,
                'avg_confidence': round(overall_stats[5] or 0, 2),
                'avg_processing_time': round(overall_stats[6] or 0, 4)
            },
            'daily': [
                {
                    'date': day[0],
                    'total_scans': day[1],
                    'safe_results': day[2],
                    'suspicious_results': day[3],
                    'avg_confidence': round(day[4] or 0, 2)
                } for day in daily_stats
            ]
        }
        
    except sqlite3.Error as e:
        logger.error(f"Statistics query error: {e}")
        return {'overall': {}, 'daily': []}

def check_virustotal(url):
    """Check URL against VirusTotal API"""
    try:
        if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
            return {
                'available': False,
                'message': 'VirusTotal API key not configured',
                'malicious': 0,
                'suspicious': 0,
                'total_scans': 0
            }
        
        # Encode URL for VirusTotal
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "x-apikey": VT_API_KEY
        }
        
        logger.info(f"Checking URL with VirusTotal: {url}")
        response = requests.get(f"{VT_URL}/{url_id}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'available': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total_scans': sum(stats.values()) if stats else 0,
                'scan_date': attributes.get('last_analysis_date', 'Unknown')
            }
        elif response.status_code == 404:
            return {
                'available': True,
                'message': 'URL not found in VirusTotal database',
                'malicious': 0,
                'suspicious': 0,
                'total_scans': 0
            }
        else:
            logger.error(f"VirusTotal API error: {response.status_code}")
            return {
                'available': False,
                'message': f'VirusTotal API error: {response.status_code}',
                'malicious': 0,
                'suspicious': 0,
                'total_scans': 0
            }
            
    except requests.exceptions.Timeout:
        logger.error("VirusTotal API timeout")
        return {
            'available': False,
            'message': 'VirusTotal API timeout',
            'malicious': 0,
            'suspicious': 0,
            'total_scans': 0
        }
    except Exception as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return {
            'available': False,
            'message': f'VirusTotal API error: {str(e)}',
            'malicious': 0,
            'suspicious': 0,
            'total_scans': 0
        }

def check_phishtank(url):
    """Check URL against PhishTank API"""
    try:
        if PHISHTANK_API_KEY == "YOUR_PHISHTANK_API_KEY":
            return {
                'available': False,
                'message': 'PhishTank API key not configured',
                'is_phish': False
            }
        
        params = {
            'url': url,
            'format': 'json',
            'app_key': PHISHTANK_API_KEY
        }
        
        logger.info(f"Checking URL with PhishTank: {url}")
        response = requests.post(PHISHTANK_URL, data=params, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                results = data.get('results', {})
                
                return {
                    'available': True,
                    'is_phish': results.get('in_database', False),
                    'phish_id': results.get('phish_id', None),
                    'verified': results.get('verified', False),
                    'submission_time': results.get('submission_time', 'Unknown')
                }
            except ValueError:
                # Response is not JSON, might be rate limited or error
                return {
                    'available': False,
                    'message': 'PhishTank API returned non-JSON response',
                    'is_phish': False
                }
        else:
            logger.error(f"PhishTank API error: {response.status_code}")
            return {
                'available': False,
                'message': f'PhishTank API error: {response.status_code}',
                'is_phish': False
            }
            
    except requests.exceptions.Timeout:
        logger.error("PhishTank API timeout")
        return {
            'available': False,
            'message': 'PhishTank API timeout',
            'is_phish': False
        }
    except Exception as e:
        logger.error(f"PhishTank API error: {str(e)}")
        return {
            'available': False,
            'message': f'PhishTank API error: {str(e)}',
            'is_phish': False
        }

# ML Dataset Integration
try:
    from ml_dataset_prep import PhishingDatasetPreparator
    ML_AVAILABLE = True
    logger.info("✅ ML Dataset Preparator imported successfully")
except ImportError as e:
    PhishingDatasetPreparator = None
    ML_AVAILABLE = False
    logger.warning(f"⚠️ ML Dataset Preparator not available: {str(e)}")
except Exception as e:
    PhishingDatasetPreparator = None
    ML_AVAILABLE = False
    logger.error(f"❌ Error importing ML Dataset Preparator: {str(e)}")

# Global dataset preparator instance
def initialize_ml_components():
    """Initialize ML dataset preparation components"""
    global dataset_preparator
    try:
        if ML_AVAILABLE and PhishingDatasetPreparator is not None:
            dataset_preparator = PhishingDatasetPreparator()
            logger.info("✅ ML Dataset Preparator initialized")
            return True
        else:
            logger.warning("ML components not available")
            return False
    except Exception as e:
        logger.error(f"❌ Failed to initialize ML components: {str(e)}")
        return False
        logger.error(f"❌ Failed to initialize ML components: {str(e)}")
        return False

def get_ml_dataset_status():
    """Get status of ML datasets"""
    global dataset_preparator
    
    if not ML_AVAILABLE:
        return {"status": "not_available", "message": "ML components not installed"}
    
    if dataset_preparator is None:
        return {"status": "not_initialized", "message": "ML components not initialized"}
    
    try:
        stats = dataset_preparator.get_dataset_statistics()
        
        # Check if datasets exist
        data_dir = "data"
        
        dataset_files = {
            "combined_dataset": os.path.exists(os.path.join(data_dir, "combined_phishing_dataset.csv")),
            "feature_dataset": os.path.exists(os.path.join(data_dir, "feature_dataset.csv")),
            "train_dataset": os.path.exists(os.path.join(data_dir, "train_dataset.csv")),
            "test_dataset": os.path.exists(os.path.join(data_dir, "test_dataset.csv"))
        }
        
        return {
            "status": "ready",
            "statistics": stats,
            "files": dataset_files,
            "datasets_ready": all(dataset_files.values())
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def prepare_ml_datasets():
    """Prepare ML datasets (download, preprocess, extract features)"""
    global dataset_preparator
    
    if not ML_AVAILABLE:
        return {"status": "error", "message": "ML components not available"}
    
    if dataset_preparator is None:
        initialize_ml_components()
    
    try:
        logger.info("🚀 Starting ML dataset preparation...")
        
        # Download datasets
        downloaded_files = dataset_preparator.download_datasets()
        
        # Load datasets
        datasets = dataset_preparator.load_datasets()
        
        # Preprocess datasets
        combined_df = dataset_preparator.preprocess_datasets()
        
        if combined_df is not None:
            # Extract features
            feature_df = dataset_preparator.extract_features(combined_df)
            
            # Create train/test split
            X_train, X_test, y_train, y_test = dataset_preparator.create_train_test_split()
            
            if X_train is not None:
                stats = dataset_preparator.get_dataset_statistics()
                
                return {
                    "status": "success",
                    "message": "ML datasets prepared successfully",
                    "statistics": stats,
                    "files_created": [
                        "data/combined_phishing_dataset.csv",
                        "data/feature_dataset.csv", 
                        "data/train_dataset.csv",
                        "data/test_dataset.csv"
                    ]
                }
            else:
                return {"status": "error", "message": "Failed to create train/test split"}
        else:
            return {"status": "error", "message": "Failed to preprocess datasets"}
            
    except Exception as e:
        logger.error(f"❌ ML dataset preparation failed: {str(e)}")
        return {"status": "error", "message": str(e)}

def check_url_phishing(url, include_external_apis=True):
    """Check if URL is potentially phishing with advanced pattern matching and external APIs"""
    url_lower = url.lower()
    
    # Advanced IP-based URL detection patterns
    ip_patterns = [
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # Standard IPv4
        r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',  # Valid IPv4 ranges
        r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # HTTP(S) with IP
        r'[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}',  # IPv6
        r'::1|::ffff:|fe80::|2001:db8:',  # Common IPv6 patterns
    ]
    
    # Hex-encoded character detection patterns
    hex_patterns = [
        r'%[0-9a-fA-F]{2}',  # URL-encoded hex characters
        r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
        r'&#x[0-9a-fA-F]+;',  # HTML hex entities
        r'\\u[0-9a-fA-F]{4}',  # Unicode hex escapes
        r'0x[0-9a-fA-F]+',  # Hex literals
        r'%u[0-9a-fA-F]{4}',  # Unicode URL encoding
    ]
    
    # Known suspicious domain patterns
    suspicious_domain_patterns = [
        r'[a-zA-Z0-9]+-[a-zA-Z0-9]+\.(tk|ml|ga|cf|pw|buzz)',  # Free TLD abuse
        r'(amazon|paypal|microsoft|google|apple|facebook|instagram|twitter|linkedin|netflix|spotify|dropbox|adobe|oracle|salesforce|slack|zoom|teams|skype|whatsapp|telegram|discord|reddit|youtube|gmail|outlook|yahoo|hotmail|banking|bank|secure|login|account|verify|update|confirm|support|help|service|customer|billing|payment|wallet|crypto|bitcoin|eth|nft|web3|metaverse|blockchain).*\.(tk|ml|ga|cf|pw|buzz|click|download|stream|online|site|website|web|net|biz|info|org|cc|tv|me|io|co|xyz|top|club|pro|shop|store|market|trade|exchange|invest|finance|money|cash|loan|credit|card|visa|mastercard|paypal|stripe|square|venmo|cashapp|zelle)',
        r'[0-9]{5,}[a-zA-Z]+\.(com|net|org)',  # Domains with many numbers
        r'(secure|login|account|verify|update|confirm)-[a-zA-Z0-9]+\.(com|net|org|tk|ml|ga|cf)',
        r'[a-zA-Z]+(amazon|paypal|microsoft|google|apple|facebook|instagram|twitter|linkedin|netflix|spotify|dropbox|adobe|oracle|salesforce|slack|zoom|teams|skype|whatsapp|telegram|discord|reddit|youtube|gmail|outlook|yahoo|hotmail|banking|bank)[a-zA-Z]*\.(com|net|org|tk|ml|ga|cf)',
    ]
    
    # URL shortener patterns (expanded)
    url_shortener_patterns = [
        r'bit\.ly|tinyurl|t\.co|short\.link|goo\.gl|ow\.ly|buff\.ly|adf\.ly|bl\.ink|rebrand\.ly|tiny\.cc|is\.gd|v\.gd|tr\.im|lnk\.to|s\.id|u\.to|clc\.to|x\.co|po\.st|soo\.gd|s2r\.co|scrnch\.me|filoops\.info|bc\.vc|zip\.net|shrtfly\.com|ay\.gy|linktr\.ee',
    ]
    
    # Combined suspicious patterns
    general_suspicious_patterns = [
        r'secure.*update|verify.*account|suspended.*account|account.*verification',
        r'(paypal|amazon|microsoft|google|apple|facebook|netflix|spotify|adobe).*verification',
        r'(security|urgent|immediate|action|required|expires|limited|time|offer)',
        r'click.*here|download.*now|update.*immediately|verify.*now|confirm.*account',
        r'[a-zA-Z]{20,}\.com',  # Very long domain names
        r'[0-9]{8,}\.com',  # Numeric domains
        r'[a-zA-Z0-9]{50,}',  # Extremely long strings
    ]
    
    suspicious_keywords = [
        'urgent', 'immediate', 'verify', 'suspend', 'limited', 'expires',
        'confirm', 'update', 'secure', 'account', 'billing', 'payment',
        'click here', 'act now', 'limited time', 'login', 'signin', 'password',
        'reset', 'locked', 'compromised', 'unauthorized', 'suspended', 'frozen'
    ]
    
    risk_score = 0
    details = []
    
    # Check for IP-based URLs (High Risk)
    ip_detected = False
    for pattern in ip_patterns:
        if re.search(pattern, url):
            risk_score += 40
            details.append("⚠️ Contains IP address instead of domain name")
            ip_detected = True
            break
    
    # Check for hex-encoded characters (Medium Risk)
    hex_count = 0
    for pattern in hex_patterns:
        matches = re.findall(pattern, url)
        hex_count += len(matches)
    
    if hex_count > 0:
        risk_score += min(30, hex_count * 5)
        details.append(f"🔍 Contains {hex_count} hex-encoded characters")
    
    # Check for suspicious domain patterns (High Risk)
    suspicious_domain_detected = False
    for pattern in suspicious_domain_patterns:
        if re.search(pattern, url_lower):
            risk_score += 35
            details.append("🚨 Matches known suspicious domain pattern")
            suspicious_domain_detected = True
            break
    
    # Check for URL shorteners (Medium Risk)
    for pattern in url_shortener_patterns:
        if re.search(pattern, url_lower):
            risk_score += 20
            details.append("🔗 Uses URL shortening service")
            break
    
    # Check general suspicious patterns (Medium Risk)
    pattern_matches = 0
    for pattern in general_suspicious_patterns:
        if re.search(pattern, url_lower):
            pattern_matches += 1
            
    if pattern_matches > 0:
        risk_score += pattern_matches * 15
        details.append(f"⚡ Contains {pattern_matches} suspicious pattern(s)")
    
    # Check keywords
    keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    if keyword_count >= 2:
        risk_score += 25
        details.append(f"Contains {keyword_count} suspicious keywords")
    
    # Check URL length
    if len(url) > 100:
        risk_score += 15
        details.append("URL is unusually long")
    
    # Check for HTTPS
    if not url.startswith('https://'):
        risk_score += 10
        details.append("Not using secure HTTPS protocol")
    
    # Check for subdomain count
    try:
        parsed_url = urllib.parse.urlparse(url)
        subdomain_count = len(parsed_url.netloc.split('.')) - 2
        if subdomain_count > 2:
            risk_score += 15
            details.append("Has multiple suspicious subdomains")
    except:
        risk_score += 20
        details.append("Invalid URL format")
    
    if risk_score == 0:
        details.append("No suspicious patterns detected")
        details.append("URL structure appears normal")
    
    # External API Integration
    external_results = {}
    if include_external_apis:
        # Check VirusTotal
        vt_result = check_virustotal(url)
        external_results['virustotal'] = vt_result
        
        if vt_result['available']:
            if vt_result['malicious'] > 0:
                risk_score += 50
                details.append(f"🦠 VirusTotal: {vt_result['malicious']} engines detected malicious content")
            elif vt_result['suspicious'] > 0:
                risk_score += 25
                details.append(f"⚠️ VirusTotal: {vt_result['suspicious']} engines flagged as suspicious")
            elif vt_result.get('total_scans', 0) > 0:
                details.append(f"✅ VirusTotal: Clean ({vt_result['harmless']} engines)")
        
        # Check PhishTank
        pt_result = check_phishtank(url)
        external_results['phishtank'] = pt_result
        
        if pt_result['available']:
            if pt_result['is_phish']:
                risk_score += 60
                details.append("🎣 PhishTank: URL found in phishing database")
                if pt_result.get('verified'):
                    details.append("🔍 PhishTank: Verified phishing site")
            else:
                details.append("✅ PhishTank: URL not in phishing database")
    
    is_safe = risk_score < 30
    confidence = max(10, min(95, 100 - risk_score))
    
    result = {
        'is_safe': is_safe,
        'confidence': confidence,
        'message': 'URL appears to be safe' if is_safe else 'URL may be suspicious',
        'details': details,
        'risk_score': risk_score
    }
    
    # Add external API results if available
    if include_external_apis:
        result['external_apis'] = external_results
    
    return result

def check_email_phishing(email_content):
    """Check if email content is potentially phishing with advanced pattern matching"""
    content_lower = email_content.lower()
    
    # Advanced phishing phrase patterns
    advanced_phishing_phrases = [
        r'verify\s+your\s+account|account\s+verification|verify\s+identity',
        r'suspend(ed)?\s+account|account\s+suspend(ed)?|temporary\s+suspension',
        r'urgent\s+action\s+required|immediate\s+action|act\s+immediately',
        r'click\s+here\s+(immediately|now|today)|download\s+(immediately|now)',
        r'confirm\s+your\s+identity|identity\s+verification|confirm\s+account',
        r'update\s+(payment|billing|card|information)|payment\s+update',
        r'security\s+alert|security\s+breach|unauthorized\s+access',
        r'expires?\s+(today|soon|in\s+\d+\s+hours?)|expir(ing|ation)\s+notice',
        r'limited\s+time\s+offer|offer\s+expires|time\s+sensitive',
        r'congratulations.*won|winner.*selected|prize.*awarded',
        r'refund\s+(pending|available|processing)|claim\s+refund',
        r'tax\s+(refund|return|issue)|irs\s+(notice|refund|audit)'
    ]
    
    # Hex-encoded content patterns for emails
    email_hex_patterns = [
        r'%[0-9a-fA-F]{2}',  # URL-encoded in email links
        r'&#x[0-9a-fA-F]+;',  # HTML hex entities
        r'=\?[^?]*\?[BQ]\?[A-Za-z0-9+/=]+\?=',  # MIME encoded headers
        r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
    ]
    
    # Suspicious sender/domain patterns
    suspicious_sender_patterns = [
        r'(no-?reply|noreply|do-?not-?reply)@[^@]+\.(tk|ml|ga|cf|pw|buzz)',
        r'(support|security|billing|account|service|help|notice|alert|update|verify|confirm).*@[^@]+\.(tk|ml|ga|cf|pw|buzz)',
        r'[a-zA-Z0-9]+(amazon|paypal|microsoft|google|apple|facebook|netflix|spotify|adobe|bank|secure)[a-zA-Z0-9]*@',
        r'@[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # Email from IP address
        r'[a-zA-Z0-9]{20,}@',  # Very long username
    ]
    
    # URL patterns commonly found in phishing emails
    suspicious_url_patterns = [
        r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP-based URLs
        r'bit\.ly|tinyurl|t\.co|goo\.gl|short\.link',  # URL shorteners
        r'[a-zA-Z0-9]+-[a-zA-Z0-9]+\.(tk|ml|ga|cf|pw|buzz)',
        r'(secure|login|account|verify|update|confirm)-[a-zA-Z0-9]+\.(com|net|org)',
    ]
    
    suspicious_elements = [
        'dear customer', 'dear user', 'dear sir/madam', 'valued customer',
        'click here', 'download attachment', 'update now', 'login now',
        'verify immediately', 'confirm now', 'act fast', 'don\'t delay'
    ]
    
    risk_score = 0
    details = []
    
    # Check for advanced phishing phrases using regex
    advanced_phrase_matches = 0
    for pattern in advanced_phishing_phrases:
        matches = re.findall(pattern, content_lower)
        advanced_phrase_matches += len(matches)
    
    if advanced_phrase_matches > 0:
        risk_score += advanced_phrase_matches * 25
        details.append(f"🚨 Contains {advanced_phrase_matches} advanced phishing phrase pattern(s)")
    
    # Check for hex-encoded content
    hex_content_count = 0
    for pattern in email_hex_patterns:
        matches = re.findall(pattern, email_content)  # Use original case for hex detection
        hex_content_count += len(matches)
    
    if hex_content_count > 0:
        risk_score += min(25, hex_content_count * 3)
        details.append(f"🔍 Contains {hex_content_count} hex-encoded elements")
    
    # Check for suspicious sender patterns
    sender_suspicious = False
    for pattern in suspicious_sender_patterns:
        if re.search(pattern, email_content, re.IGNORECASE):
            risk_score += 30
            details.append("📧 Suspicious sender domain pattern detected")
            sender_suspicious = True
            break
    
    # Check for suspicious URLs in email content
    suspicious_url_count = 0
    for pattern in suspicious_url_patterns:
        matches = re.findall(pattern, email_content, re.IGNORECASE)
        suspicious_url_count += len(matches)
    
    if suspicious_url_count > 0:
        risk_score += min(35, suspicious_url_count * 15)
        details.append(f"🔗 Contains {suspicious_url_count} suspicious URL(s)")
    
    # Check for suspicious elements
    element_count = sum(1 for element in suspicious_elements if element in content_lower)
    if element_count > 2:
        risk_score += 15
        details.append("Contains multiple suspicious elements")
    
    # Check for urgency indicators
    urgency_words = ['urgent', 'immediate', 'expires', 'deadline', 'asap']
    urgency_count = sum(1 for word in urgency_words if word in content_lower)
    if urgency_count > 1:
        risk_score += 10
        details.append("Uses urgent language tactics")
    
    # Check for poor grammar (simple check)
    if 'recieve' in content_lower or 'loose' in content_lower:
        risk_score += 10
        details.append("Contains spelling errors")
    
    if risk_score == 0:
        details.append("No obvious phishing indicators found")
        details.append("Content appears legitimate")
    
    is_safe = risk_score < 25
    confidence = max(15, min(90, 100 - risk_score))
    
    return {
        'is_safe': is_safe,
        'confidence': confidence,
        'message': 'Email appears to be safe' if is_safe else 'Email may be suspicious',
        'details': details
    }

def analyze_patterns(text, analysis_type="url"):
    """Analyze text for specific pattern types and return detailed breakdown"""
    patterns_found = {
        'ip_addresses': [],
        'hex_encoded': [],
        'suspicious_domains': [],
        'url_shorteners': [],
        'phishing_phrases': []
    }
    
    if analysis_type == "url":
        # IP address detection
        ip_patterns = [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            r'[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}'
        ]
        
        for pattern in ip_patterns:
            matches = re.findall(pattern, text)
            patterns_found['ip_addresses'].extend(matches)
        
        # Hex encoding detection
        hex_patterns = [r'%[0-9a-fA-F]{2}', r'\\x[0-9a-fA-F]{2}', r'&#x[0-9a-fA-F]+;']
        for pattern in hex_patterns:
            matches = re.findall(pattern, text)
            patterns_found['hex_encoded'].extend(matches)
            
        # URL shorteners
        shortener_pattern = r'bit\.ly|tinyurl|t\.co|goo\.gl|short\.link'
        matches = re.findall(shortener_pattern, text, re.IGNORECASE)
        patterns_found['url_shorteners'].extend(matches)
        
        # Suspicious domains
        suspicious_pattern = r'[a-zA-Z0-9]+-[a-zA-Z0-9]+\.(tk|ml|ga|cf|pw|buzz)'
        matches = re.findall(suspicious_pattern, text, re.IGNORECASE)
        patterns_found['suspicious_domains'].extend(matches)
    
    elif analysis_type == "email":
        # Phishing phrases for emails
        phishing_patterns = [
            r'verify\s+your\s+account',
            r'urgent\s+action\s+required',
            r'click\s+here\s+(immediately|now)',
            r'account\s+suspended?',
            r'security\s+alert'
        ]
        
        for pattern in phishing_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            patterns_found['phishing_phrases'].extend(matches)
    
    return patterns_found

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/external-scan', methods=['POST'])
def external_scan():
    """Endpoint specifically for testing external API integrations"""
    try:
        logger.info(f"Received external scan request from {request.remote_addr}")
        
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        logger.info(f"Testing external APIs for URL: {url}")
        
        # Test VirusTotal
        vt_result = check_virustotal(url)
        
        # Test PhishTank
        pt_result = check_phishtank(url)
        
        response = {
            'url': url,
            'timestamp': time.time(),
            'virustotal': vt_result,
            'phishtank': pt_result,
            'summary': {
                'apis_available': sum([vt_result['available'], pt_result['available']]),
                'total_apis': 2,
                'threat_detected': (
                    (vt_result.get('malicious', 0) > 0 or vt_result.get('suspicious', 0) > 0) or 
                    pt_result.get('is_phish', False)
                )
            }
        }
        
        logger.info(f"External API scan completed - VT: {vt_result['available']}, PT: {pt_result['available']}")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in external scan: {str(e)}", exc_info=True)
        return jsonify({'error': f'External scan failed: {str(e)}'}), 500

@app.route('/analyze-patterns', methods=['POST'])
def analyze_patterns_route():
    """Endpoint to analyze and demonstrate pattern matching capabilities"""
    try:
        logger.info(f"Received pattern analysis request from {request.remote_addr}")
        
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.get_json()
        text = data.get('text', '')
        analysis_type = data.get('type', 'url')
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        patterns = analyze_patterns(text, analysis_type)
        
        # Count total patterns found
        total_patterns = sum(len(v) for v in patterns.values())
        
        response = {
            'text_analyzed': text[:100] + '...' if len(text) > 100 else text,
            'analysis_type': analysis_type,
            'patterns_found': patterns,
            'total_patterns': total_patterns,
            'risk_assessment': {
                'low': total_patterns <= 2,
                'medium': 3 <= total_patterns <= 5,
                'high': total_patterns > 5
            }
        }
        
        logger.info(f"Pattern analysis completed - Total patterns: {total_patterns}")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in pattern analysis: {str(e)}", exc_info=True)
        return jsonify({'error': 'Analysis failed'}), 500

@app.route('/test-patterns')
def test_patterns():
    """Test page to demonstrate pattern matching"""
    test_cases = {
        'suspicious_urls': [
            'http://192.168.1.1/secure-update-account',
            'https://paypal-verification.tk/login',
            'http://bit.ly/urgent-action',
            'https://amazon%2Esecurity%2Eupdate.com',
            'http://microsoft-security-alert.ml/verify'
        ],
        'safe_urls': [
            'https://www.google.com',
            'https://github.com/user/repo',
            'https://stackoverflow.com/questions',
            'https://docs.python.org',
            'https://www.wikipedia.org'
        ],
        'suspicious_emails': [
            'Your account has been suspended. Click here immediately to verify your identity.',
            'Urgent action required: Update your payment information now or lose access.',
            'Security alert: Unauthorized access detected. Confirm your account immediately.',
            'Congratulations! You have won $1000. Click here to claim your prize.',
            'IRS Notice: Tax refund pending. Verify your information to receive payment.'
        ],
        'safe_emails': [
            'Thank you for your recent purchase. Your order will be shipped soon.',
            'Welcome to our newsletter. We appreciate your subscription.',
            'Your monthly statement is now available in your account.',
            'Meeting reminder: Team standup tomorrow at 10 AM.',
            'System maintenance scheduled for this weekend.'
        ]
    }
    
    return jsonify({
        'message': 'Pattern Matching Test Cases',
        'test_cases': test_cases,
        'instructions': {
            'analyze_url': 'POST to /analyze-patterns with {"text": "url", "type": "url"}',
            'analyze_email': 'POST to /analyze-patterns with {"text": "email_content", "type": "email"}',
            'scan_phishing': 'POST to /scan with {"value": "content", "type": "url|email"}'
        }
    })

@app.route('/scan', methods=['POST'])
def scan():
    start_time = time.time()
    try:
        # Log incoming request
        logger.info(f"Received scan request from {request.remote_addr}")

        # Validate request content type
        if not request.is_json:
            logger.error("Request is not JSON")
            return jsonify({
                'is_safe': False,
                'confidence': 0,
                'message': 'Request must be JSON',
                'details': ['Invalid content type']
            }), 400

        data = request.get_json()

        # Validate required fields
        if not data:
            logger.error("Empty request data")
            return jsonify({
                'is_safe': False,
                'confidence': 0,
                'message': 'Empty request data',
                'details': ['No data provided']
            }), 400

        # Accept both 'value' and legacy 'input' keys from older clients/tests
        input_type = data.get('type')
        input_value = data.get('value') or data.get('input')
        include_external = data.get('include_external', False)  # Optional external API integration

        if not input_type or not input_value:
            logger.error(f"Missing required fields - type: {input_type}, value: {bool(input_value)}")
            return jsonify({
                'is_safe': False,
                'confidence': 0,
                'message': 'Missing required fields',
                'details': ['Both type and value are required']
            }), 400

        logger.info(f"Processing scan - Type: {input_type}, Value length: {len(input_value)}, External APIs: {include_external}")

        # Perform the scan
        external_api_results = None
        if input_type == 'url':
            result = check_url_phishing(input_value, include_external_apis=include_external)
            if include_external:
                external_api_results = {
                    'virustotal': check_virustotal(input_value),
                    'phishtank': check_phishtank(input_value)
                }
            logger.info(f"URL scan completed - Safe: {result['is_safe']}, Confidence: {result['confidence']}%")
        elif input_type == 'email':
            result = check_email_phishing(input_value)
            logger.info(f"Email scan completed - Safe: {result['is_safe']}, Confidence: {result['confidence']}%")
        else:
            logger.error(f"Invalid input type: {input_type}")
            result = {
                'is_safe': False,
                'confidence': 0,
                'message': 'Invalid input type',
                'details': ['Supported types: url, email']
            }

        # Calculate processing time
        processing_time = time.time() - start_time

        # Save to database
        record_id = save_scan_record(
            input_type=input_type,
            input_content=input_value,
            result=result,
            user_ip=request.remote_addr,
            processing_time=processing_time,
            external_apis=external_api_results
        )

        # Add database record ID to response
        result['record_id'] = record_id
        result['processing_time'] = round(processing_time, 4)

        logger.info(f"Scan completed and saved to database with ID: {record_id}")

        # Return a compatibility wrapper expected by integration tests
        response = {'success': True}
        response.update(result)
        return jsonify(response)

    except Exception as e:
        logger.error(f"Error in scan route: {str(e)}", exc_info=True)
        return jsonify({
            'is_safe': False,
            'confidence': 0,
            'message': 'Internal server error occurred',
            'details': ['Please try again later']
        }), 500

@app.route('/history')
def scan_history():
    """Get scan history"""
    try:
        limit = request.args.get('limit', 100, type=int)
        input_type = request.args.get('type', None)
        
        history = get_scan_history(limit=limit, input_type=input_type)
        
        return jsonify({
            'success': True,
            'count': len(history),
            'history': history
        })
        
    except Exception as e:
        logger.error(f"Error retrieving history: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scan history'}), 500

@app.route('/statistics')
def scan_statistics():
    """Get scan statistics and analytics"""
    try:
        stats = get_scan_statistics()
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error retrieving statistics: {str(e)}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

@app.route('/admin')
@require_admin
def admin_dashboard():
    """Admin dashboard to view statistics"""
    # Require login
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')
    return render_template('admin.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Only allow the hardcoded credentials
        if username == 'thiru' and password == '_THIRU@4690':
            session['admin_logged_in'] = True
            return redirect('/admin')
        return render_template('admin_login.html', error='Invalid credentials')
    return render_template('admin_login.html')


@app.route('/admin/logout')
@require_admin
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/')

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

@app.route('/api/ml/initialize', methods=['POST'])
def ml_initialize_api():
    """API endpoint to initialize ML components"""
    try:
        success = initialize_ml_components()
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'ML components initialized successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to initialize ML components'
            }), 400
            
    except Exception as e:
        logger.error(f"Error initializing ML components: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/ml-dashboard')
@require_admin
def ml_dashboard():
    """ML Dashboard for dataset management and preparation"""
    # Hide ML dashboard from public; require admin login.
    # If not logged in, redirect to admin login. If logged in, redirect to the admin dashboard
    # so the ML UI is effectively hidden and only accessible via internal tools if needed.
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')
    return redirect('/admin')

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
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'total_records': total_records,
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
    logger.info("Starting Flask application with SQLite database integration")
    
    # Initialize ML components
    logger.info("Initializing ML dataset preparation components...")
    ml_init_success = initialize_ml_components()
    
    if ml_init_success:
        logger.info("✅ ML components initialized successfully")
    else:
        logger.warning("⚠️ ML components initialization failed - some features may not be available")
    
    # When running under a debugger (VS Code / debugpy) the Flask auto-reloader
    # can cause the process to exit with SystemExit: 3 because it spawns a
    # child process. Disable the reloader when debugging to avoid that.
    app.run(debug=True, use_reloader=False)