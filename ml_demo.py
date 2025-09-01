#!/usr/bin/env python3
"""
Standalone ML Dataset Preparation Demo
This script demonstrates the ML dataset preparation capabilities
without requiring the full Flask application
"""

import os
import sys
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_datasets():
    """Create sample datasets for demonstration"""
    logger.info("🚀 Creating sample ML datasets for phishing detection...")
    
    # Create data directory
    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)
    
    # Sample phishing and legitimate URLs with labels
    sample_data = [
        # Phishing URLs (label = 1)
        ("http://192.168.1.1/secure-login", 1, "ip_based"),
        ("https://paypal-verify.tk/account", 1, "suspicious_tld"),
        ("http://amazon-security.ml/update", 1, "brand_impersonation"),
        ("https://microsoft-alert.ga/verify", 1, "suspicious_tld"),
        ("http://bit.ly/urgent-action", 1, "url_shortener"),
        ("https://apple%2did%2dsuspended.cf/unlock", 1, "url_encoding"),
        ("http://facebook-security.pw/confirm", 1, "brand_impersonation"),
        ("https://google-account-verify.buzz/login", 1, "suspicious_tld"),
        ("http://netflix-billing.click/update", 1, "suspicious_tld"),
        ("https://spotify-premium.download/free", 1, "suspicious_tld"),
        ("http://bank-secure-login.tk/verify", 1, "financial_phishing"),
        ("https://crypto-wallet-urgent.ml/update", 1, "crypto_phishing"),
        ("http://amazon123456.com/signin", 1, "typosquatting"),
        ("https://paypaI.com/login", 1, "homograph_attack"),  # Note: capital i instead of lowercase l
        ("http://secure-banking.cf/account", 1, "financial_phishing"),
        
        # Legitimate URLs (label = 0)
        ("https://www.google.com", 0, "legitimate"),
        ("https://www.facebook.com", 0, "legitimate"),
        ("https://www.amazon.com", 0, "legitimate"),
        ("https://www.microsoft.com", 0, "legitimate"),
        ("https://www.apple.com", 0, "legitimate"),
        ("https://www.netflix.com", 0, "legitimate"),
        ("https://www.spotify.com", 0, "legitimate"),
        ("https://www.github.com", 0, "legitimate"),
        ("https://www.stackoverflow.com", 0, "legitimate"),
        ("https://www.wikipedia.org", 0, "legitimate"),
        ("https://www.paypal.com", 0, "legitimate"),
        ("https://www.linkedin.com", 0, "legitimate"),
        ("https://www.twitter.com", 0, "legitimate"),
        ("https://www.reddit.com", 0, "legitimate"),
        ("https://www.youtube.com", 0, "legitimate"),
    ]
    
    # Create combined dataset CSV
    csv_content = "url,label,source,category\n"
    for url, label, category in sample_data:
        csv_content += f'"{url}",{label},sample,{category}\n'
    
    combined_file = os.path.join(data_dir, "combined_phishing_dataset.csv")
    with open(combined_file, 'w', encoding='utf-8') as f:
        f.write(csv_content)
    
    logger.info(f"✅ Created combined dataset: {combined_file} ({len(sample_data)} URLs)")
    
    return sample_data

def extract_basic_features(sample_data):
    """Extract basic features from URLs without heavy ML dependencies"""
    logger.info("🔍 Extracting basic features from URLs...")
    
    import re
    import urllib.parse
    
    features_data = []
    
    for url, label, category in sample_data:
        try:
            parsed_url = urllib.parse.urlparse(str(url))
            
            # Extract basic features
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
                
                # Label and metadata
                'label': label,
                'category': category,
                'url': url
            }
            
            features_data.append(features)
            
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {str(e)}")
    
    # Save feature dataset
    data_dir = "data"
    feature_file = os.path.join(data_dir, "feature_dataset.csv")
    
    if features_data:
        # Create CSV header
        headers = list(features_data[0].keys())
        csv_content = ",".join(headers) + "\n"
        
        # Add data rows
        for features in features_data:
            row = []
            for header in headers:
                value = features.get(header, '')
                if isinstance(value, str) and ',' in value:
                    value = f'"{value}"'
                row.append(str(value))
            csv_content += ",".join(row) + "\n"
        
        with open(feature_file, 'w', encoding='utf-8') as f:
            f.write(csv_content)
        
        logger.info(f"✅ Created feature dataset: {feature_file} ({len(features_data)} URLs, {len(headers)} features)")
    
    return features_data

def create_train_test_split(features_data):
    """Create train/test split manually without sklearn"""
    logger.info("📊 Creating train/test split...")
    
    import random
    random.seed(42)  # For reproducible results
    
    # Separate by label for stratified split
    phishing_data = [f for f in features_data if f['label'] == 1]
    legitimate_data = [f for f in features_data if f['label'] == 0]
    
    # Shuffle data
    random.shuffle(phishing_data)
    random.shuffle(legitimate_data)
    
    # 80/20 split
    test_size = 0.2
    
    phishing_test_size = int(len(phishing_data) * test_size)
    legitimate_test_size = int(len(legitimate_data) * test_size)
    
    # Create splits
    phishing_train = phishing_data[phishing_test_size:]
    phishing_test = phishing_data[:phishing_test_size]
    
    legitimate_train = legitimate_data[legitimate_test_size:]
    legitimate_test = legitimate_data[:legitimate_test_size]
    
    # Combine and shuffle
    train_data = phishing_train + legitimate_train
    test_data = phishing_test + legitimate_test
    
    random.shuffle(train_data)
    random.shuffle(test_data)
    
    # Save splits
    data_dir = "data"
    
    def save_split(data, filename):
        if data:
            headers = list(data[0].keys())
            csv_content = ",".join(headers) + "\n"
            
            for features in data:
                row = []
                for header in headers:
                    value = features.get(header, '')
                    if isinstance(value, str) and ',' in value:
                        value = f'"{value}"'
                    row.append(str(value))
                csv_content += ",".join(row) + "\n"
            
            filepath = os.path.join(data_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(csv_content)
            
            logger.info(f"✅ Created {filename}: {len(data)} samples")
    
    save_split(train_data, "train_dataset.csv")
    save_split(test_data, "test_dataset.csv")
    
    return train_data, test_data

def generate_statistics(features_data, train_data, test_data):
    """Generate dataset statistics"""
    logger.info("📈 Generating dataset statistics...")
    
    total_urls = len(features_data)
    phishing_urls = len([f for f in features_data if f['label'] == 1])
    legitimate_urls = len([f for f in features_data if f['label'] == 0])
    
    # Feature analysis
    feature_names = [k for k in features_data[0].keys() if k not in ['label', 'category', 'url']]
    num_features = len(feature_names)
    
    # Training set stats
    train_phishing = len([f for f in train_data if f['label'] == 1])
    train_legitimate = len([f for f in train_data if f['label'] == 0])
    
    # Test set stats
    test_phishing = len([f for f in test_data if f['label'] == 1])
    test_legitimate = len([f for f in test_data if f['label'] == 0])
    
    stats = {
        'total_urls': total_urls,
        'phishing_urls': phishing_urls,
        'legitimate_urls': legitimate_urls,
        'phishing_percentage': round((phishing_urls / total_urls) * 100, 1),
        'legitimate_percentage': round((legitimate_urls / total_urls) * 100, 1),
        'features_extracted': num_features,
        'train_samples': len(train_data),
        'test_samples': len(test_data),
        'train_phishing': train_phishing,
        'train_legitimate': train_legitimate,
        'test_phishing': test_phishing,
        'test_legitimate': test_legitimate,
        'feature_names': feature_names,
        'generated_at': datetime.now().isoformat()
    }
    
    # Save statistics
    stats_file = os.path.join("data", "dataset_statistics.json")
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
    
    logger.info(f"✅ Statistics saved to: {stats_file}")
    
    return stats

def print_summary(stats):
    """Print a comprehensive summary of the dataset preparation"""
    print("\n" + "="*80)
    print("🤖 ML DATASET PREPARATION SUMMARY")
    print("="*80)
    
    print(f"\n📊 Dataset Overview:")
    print(f"   Total URLs: {stats['total_urls']}")
    print(f"   Phishing URLs: {stats['phishing_urls']} ({stats['phishing_percentage']}%)")
    print(f"   Legitimate URLs: {stats['legitimate_urls']} ({stats['legitimate_percentage']}%)")
    print(f"   Features Extracted: {stats['features_extracted']}")
    
    print(f"\n📚 Training/Test Split:")
    print(f"   Training Set: {stats['train_samples']} samples")
    print(f"     - Phishing: {stats['train_phishing']}")
    print(f"     - Legitimate: {stats['train_legitimate']}")
    print(f"   Test Set: {stats['test_samples']} samples")
    print(f"     - Phishing: {stats['test_phishing']}")
    print(f"     - Legitimate: {stats['test_legitimate']}")
    
    print(f"\n🔍 Feature Categories:")
    feature_categories = {
        'Basic': ['url_length', 'domain_length', 'path_length', 'query_length'],
        'Protocol': ['is_https', 'has_port'],
        'Domain': ['subdomain_count', 'domain_has_hyphen', 'domain_has_numbers'],
        'Security': ['is_ip_address', 'suspicious_tld', 'url_encoded_chars'],
        'Pattern': ['has_suspicious_words', 'brand_impersonation', 'is_shortened'],
        'Structure': ['path_depth', 'has_query', 'has_fragment'],
        'Character': ['special_char_count', 'hyphen_count', 'underscore_count', 'dot_count', 'slash_count']
    }
    
    for category, features in feature_categories.items():
        available_features = [f for f in features if f in stats['feature_names']]
        print(f"   {category}: {len(available_features)} features")
    
    print(f"\n📁 Files Created:")
    files = [
        "data/combined_phishing_dataset.csv - Raw dataset with labels",
        "data/feature_dataset.csv - Extracted features for ML",
        "data/train_dataset.csv - Training data (80%)",
        "data/test_dataset.csv - Test data (20%)",
        "data/dataset_statistics.json - Comprehensive statistics"
    ]
    
    for file_desc in files:
        print(f"   📄 {file_desc}")
    
    print(f"\n🎯 Next Steps:")
    print(f"   1. Train ML models using the feature dataset")
    print(f"   2. Evaluate model performance on test set")
    print(f"   3. Deploy trained model for real-time detection")
    print(f"   4. Integrate with Flask application for enhanced detection")
    
    print(f"\n⏰ Generated: {stats['generated_at']}")
    print("="*80)

def main():
    """Main function to run the ML dataset preparation demo"""
    try:
        print("🚀 Starting ML Dataset Preparation Demo")
        print("This demonstrates phishing detection dataset creation without heavy ML dependencies")
        print("-" * 80)
        
        # Step 1: Create sample datasets
        sample_data = create_sample_datasets()
        
        # Step 2: Extract features
        features_data = extract_basic_features(sample_data)
        
        if not features_data:
            logger.error("❌ No features extracted. Exiting.")
            return
        
        # Step 3: Create train/test split
        train_data, test_data = create_train_test_split(features_data)
        
        # Step 4: Generate statistics
        stats = generate_statistics(features_data, train_data, test_data)
        
        # Step 5: Print summary
        print_summary(stats)
        
        logger.info("✅ ML dataset preparation completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error during dataset preparation: {str(e)}")
        raise

if __name__ == "__main__":
    main()
