#!/usr/bin/env python3
"""
ML Dataset Preparation Module for Phishing Detection
Handles dataset downloading, preprocessing, and labeling
"""

import pandas as pd
import numpy as np
import os
import requests
import zipfile
import json
import re
import urllib.parse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import logging
from datetime import datetime
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingDatasetPreparator:
    """
    Comprehensive dataset preparation class for phishing detection ML
    """
    
    def __init__(self, data_dir="data", db_path="phishing_detector.db"):
        self.data_dir = data_dir
        self.db_path = db_path
        self.datasets = {}
        self.processed_features = None
        
        # Create data directory if it doesn't exist
        os.makedirs(data_dir, exist_ok=True)
        
        # Dataset URLs and configurations
        self.dataset_sources = {
            'phishing_urls_1': {
                'url': 'https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data.csv',
                'name': 'Malicious URLs Dataset',
                'label_column': 'type',
                'url_column': 'url'
            },
            'phishing_urls_2': {
                'url': 'https://raw.githubusercontent.com/incertum/cyber-matrix-ai/master/Malicious-URL-Detection-Deep-Learning/data/url_data.csv',
                'name': 'Cyber Matrix AI URLs',
                'label_column': 'label',
                'url_column': 'url'
            },
            'uci_phishing': {
                'url': 'https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff',
                'name': 'UCI Phishing Dataset',
                'format': 'arff'
            }
        }
    
    def download_datasets(self):
        """Download datasets from various sources"""
        logger.info("🔄 Starting dataset download process...")
        
        downloaded_files = []
        
        for dataset_id, config in self.dataset_sources.items():
            try:
                filename = f"{dataset_id}.csv"
                filepath = os.path.join(self.data_dir, filename)
                
                if os.path.exists(filepath):
                    logger.info(f"✅ Dataset {config['name']} already exists")
                    downloaded_files.append(filepath)
                    continue
                
                logger.info(f"⬇️ Downloading {config['name']}...")
                
                response = requests.get(config['url'], timeout=30)
                response.raise_for_status()
                
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"✅ Downloaded {config['name']} to {filepath}")
                downloaded_files.append(filepath)
                
            except Exception as e:
                logger.error(f"❌ Failed to download {config['name']}: {str(e)}")
                
                # Create a sample dataset if download fails
                sample_filepath = self.create_sample_dataset(dataset_id)
                if sample_filepath:
                    downloaded_files.append(sample_filepath)
        
        # Download additional phishing datasets
        self.download_phishtank_data()
        
        return downloaded_files
    
    def create_sample_dataset(self, dataset_id):
        """Create a sample dataset for testing if downloads fail"""
        logger.info(f"🔧 Creating sample dataset for {dataset_id}...")
        
        # Sample phishing and legitimate URLs
        sample_data = {
            'url': [
                # Phishing URLs (labeled as 1)
                'http://192.168.1.1/secure-login',
                'https://paypal-verify.tk/account',
                'http://amazon-security.ml/update',
                'https://microsoft-alert.ga/verify',
                'http://bit.ly/urgent-action',
                'https://apple%2did%2dsuspended.cf/unlock',
                'http://facebook-security.pw/confirm',
                'https://google-account-verify.buzz/login',
                'http://netflix-billing.click/update',
                'https://spotify-premium.download/free',
                
                # Legitimate URLs (labeled as 0)
                'https://www.google.com',
                'https://www.facebook.com',
                'https://www.amazon.com',
                'https://www.microsoft.com',
                'https://www.apple.com',
                'https://www.netflix.com',
                'https://www.spotify.com',
                'https://www.github.com',
                'https://www.stackoverflow.com',
                'https://www.wikipedia.org'
            ],
            'label': [1] * 10 + [0] * 10  # 1 for phishing, 0 for legitimate
        }
        
        df = pd.DataFrame(sample_data)
        
        filename = f"{dataset_id}_sample.csv"
        filepath = os.path.join(self.data_dir, filename)
        
        df.to_csv(filepath, index=False)
        logger.info(f"✅ Created sample dataset: {filepath}")
        
        return filepath
    
    def download_phishtank_data(self):
        """Download PhishTank verified phishing URLs"""
        try:
            logger.info("⬇️ Downloading PhishTank verified phishing URLs...")
            
            # PhishTank provides JSON format data
            phishtank_url = "http://data.phishtank.com/data/online-valid.json"
            
            filepath = os.path.join(self.data_dir, "phishtank_verified.json")
            
            if os.path.exists(filepath):
                logger.info("✅ PhishTank data already exists")
                return filepath
            
            response = requests.get(phishtank_url, timeout=60)
            response.raise_for_status()
            
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            # Convert JSON to CSV for easier processing
            csv_filepath = self.convert_phishtank_to_csv(filepath)
            
            logger.info(f"✅ Downloaded PhishTank data: {csv_filepath}")
            return csv_filepath
            
        except Exception as e:
            logger.error(f"❌ Failed to download PhishTank data: {str(e)}")
            return None
    
    def convert_phishtank_to_csv(self, json_filepath):
        """Convert PhishTank JSON data to CSV format"""
        try:
            with open(json_filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract URLs and create DataFrame
            urls = []
            for entry in data[:1000]:  # Limit to first 1000 entries
                if 'url' in entry:
                    urls.append({
                        'url': entry['url'],
                        'label': 1,  # All PhishTank URLs are phishing
                        'source': 'phishtank',
                        'verified': entry.get('verified', 'yes')
                    })
            
            df = pd.DataFrame(urls)
            
            csv_filepath = os.path.join(self.data_dir, "phishtank_verified.csv")
            df.to_csv(csv_filepath, index=False)
            
            logger.info(f"✅ Converted {len(urls)} PhishTank URLs to CSV")
            return csv_filepath
            
        except Exception as e:
            logger.error(f"❌ Failed to convert PhishTank data: {str(e)}")
            return None
    
    def load_datasets(self):
        """Load all available datasets"""
        logger.info("📂 Loading datasets...")
        
        dataset_files = []
        
        # Find all CSV files in data directory
        for filename in os.listdir(self.data_dir):
            if filename.endswith('.csv'):
                filepath = os.path.join(self.data_dir, filename)
                dataset_files.append(filepath)
        
        for filepath in dataset_files:
            try:
                df = pd.read_csv(filepath)
                dataset_name = os.path.splitext(os.path.basename(filepath))[0]
                self.datasets[dataset_name] = df
                
                logger.info(f"✅ Loaded {dataset_name}: {len(df)} records")
                
            except Exception as e:
                logger.error(f"❌ Failed to load {filepath}: {str(e)}")
        
        return self.datasets
    
    def preprocess_datasets(self):
        """Preprocess and standardize all datasets"""
        logger.info("🔧 Preprocessing datasets...")
        
        processed_datasets = []
        
        for name, df in self.datasets.items():
            try:
                processed_df = self.standardize_dataset(df, name)
                if processed_df is not None:
                    processed_datasets.append(processed_df)
                    logger.info(f"✅ Processed {name}: {len(processed_df)} records")
                
            except Exception as e:
                logger.error(f"❌ Failed to process {name}: {str(e)}")
        
        # Combine all processed datasets
        if processed_datasets:
            combined_df = pd.concat(processed_datasets, ignore_index=True)
            combined_df = self.clean_combined_dataset(combined_df)
            
            # Save combined dataset
            combined_filepath = os.path.join(self.data_dir, "combined_phishing_dataset.csv")
            combined_df.to_csv(combined_filepath, index=False)
            
            logger.info(f"✅ Created combined dataset: {len(combined_df)} records")
            return combined_df
        
        return None
    
    def standardize_dataset(self, df, dataset_name):
        """Standardize dataset format"""
        
        # Try to identify URL and label columns
        url_column = None
        label_column = None
        
        # Common column names for URLs
        url_candidates = ['url', 'URL', 'link', 'website', 'domain']
        for col in url_candidates:
            if col in df.columns:
                url_column = col
                break
        
        # Common column names for labels
        label_candidates = ['label', 'type', 'class', 'target', 'result', 'is_phishing']
        for col in label_candidates:
            if col in df.columns:
                label_column = col
                break
        
        if url_column is None:
            logger.warning(f"⚠️ No URL column found in {dataset_name}")
            return None
        
        # Create standardized DataFrame
        standardized_df = pd.DataFrame()
        standardized_df['url'] = df[url_column]
        
        if label_column is not None:
            # Standardize labels to 0 (legitimate) and 1 (phishing)
            labels = df[label_column]
            
            # Handle different label formats
            if labels.dtype == 'object':
                # String labels
                standardized_labels = []
                for label in labels:
                    label_str = str(label).lower()
                    if any(term in label_str for term in ['phishing', 'malicious', 'bad', 'suspicious', '1']):
                        standardized_labels.append(1)
                    else:
                        standardized_labels.append(0)
                standardized_df['label'] = standardized_labels
            else:
                # Numeric labels
                standardized_df['label'] = labels
        else:
            # If no label column, try to infer from URL patterns
            standardized_df['label'] = self.infer_labels_from_urls(standardized_df['url'])
        
        standardized_df['source'] = dataset_name
        
        return standardized_df
    
    def infer_labels_from_urls(self, urls):
        """Infer labels from URL patterns when labels are not available"""
        labels = []
        
        phishing_indicators = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'\.(tk|ml|ga|cf|pw|buzz)/',  # Suspicious TLDs
            r'(bit\.ly|tinyurl|t\.co)',  # URL shorteners
            r'(paypal|amazon|microsoft|google|apple|facebook)-',  # Brand impersonation
            r'(secure|login|account|verify|update|confirm).*\.(tk|ml|ga|cf)',
            r'%[0-9a-fA-F]{2}',  # URL encoding
        ]
        
        for url in urls:
            url_str = str(url).lower()
            is_suspicious = False
            
            for pattern in phishing_indicators:
                if re.search(pattern, url_str):
                    is_suspicious = True
                    break
            
            labels.append(1 if is_suspicious else 0)
        
        return labels
    
    def clean_combined_dataset(self, df):
        """Clean and validate combined dataset"""
        logger.info("🧹 Cleaning combined dataset...")
        
        # Remove duplicates
        initial_count = len(df)
        df = df.drop_duplicates(subset=['url'])
        logger.info(f"🗑️ Removed {initial_count - len(df)} duplicate URLs")
        
        # Remove invalid URLs
        valid_urls = []
        valid_labels = []
        valid_sources = []
        
        for idx, row in df.iterrows():
            url = str(row['url'])
            
            # Basic URL validation
            if (len(url) > 10 and 
                ('http' in url.lower() or 'www.' in url.lower()) and
                '.' in url):
                valid_urls.append(url)
                valid_labels.append(row['label'])
                valid_sources.append(row['source'])
        
        cleaned_df = pd.DataFrame({
            'url': valid_urls,
            'label': valid_labels,
            'source': valid_sources
        })
        
        logger.info(f"🧹 Cleaned dataset: {len(cleaned_df)} valid URLs")
        
        return cleaned_df
    
    def extract_features(self, df):
        """Extract features from URLs for ML training"""
        logger.info("🔍 Extracting features from URLs...")
        
        features = []
        
        for url in df['url']:
            url_features = self.extract_url_features(url)
            features.append(url_features)
        
        feature_df = pd.DataFrame(features)
        
        # Add labels
        feature_df['label'] = df['label'].values
        
        # Save feature dataset
        feature_filepath = os.path.join(self.data_dir, "feature_dataset.csv")
        feature_df.to_csv(feature_filepath, index=False)
        
        logger.info(f"✅ Extracted {len(feature_df.columns)-1} features for {len(feature_df)} URLs")
        
        self.processed_features = feature_df
        return feature_df
    
    def extract_url_features(self, url):
        """Extract comprehensive features from a single URL"""
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
                
                # Entropy (randomness measure)
                'domain_entropy': self.calculate_entropy(parsed_url.netloc),
                'path_entropy': self.calculate_entropy(parsed_url.path),
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from URL {url}: {str(e)}")
            return self.get_default_features()
    
    def calculate_entropy(self, text):
        """Calculate entropy of text (measure of randomness)"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy
    
    def get_default_features(self):
        """Return default feature values for error cases"""
        return {feature: 0 for feature in [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'is_https', 'has_port', 'subdomain_count', 'domain_has_hyphen',
            'domain_has_numbers', 'is_ip_address', 'suspicious_tld',
            'url_encoded_chars', 'has_suspicious_words', 'brand_impersonation',
            'is_shortened', 'path_depth', 'has_query', 'has_fragment',
            'special_char_count', 'hyphen_count', 'underscore_count',
            'dot_count', 'slash_count', 'domain_entropy', 'path_entropy'
        ]}
    
    def create_train_test_split(self, test_size=0.2, random_state=42):
        """Create train/test split of the feature dataset"""
        if self.processed_features is None or self.processed_features.empty:
            logger.error("❌ No processed features available for train/test split")
            return None, None, None, None
        
        # Separate features and labels
        X = self.processed_features.drop('label', axis=1)
        y = self.processed_features['label']
        
        # Create train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        logger.info(f"✅ Created train/test split:")
        logger.info(f"   📊 Training set: {len(X_train)} samples")
        logger.info(f"   📊 Test set: {len(X_test)} samples")
        logger.info(f"   📊 Features: {len(X.columns)}")
        
        # Save splits
        train_data = X_train.copy()
        train_data['label'] = y_train
        train_data.to_csv(os.path.join(self.data_dir, 'train_dataset.csv'), index=False)
        
        test_data = X_test.copy()
        test_data['label'] = y_test
        test_data.to_csv(os.path.join(self.data_dir, 'test_dataset.csv'), index=False)
        
        return X_train, X_test, y_train, y_test
    
    def get_dataset_statistics(self):
        """Get comprehensive statistics about the datasets"""
        stats = {
            'datasets_loaded': len(self.datasets),
            'total_urls': 0,
            'phishing_urls': 0,
            'legitimate_urls': 0,
            'features_extracted': 0,
            'dataset_breakdown': {}
        }
        
        if hasattr(self, 'processed_features') and self.processed_features is not None:
            df = self.processed_features
            stats['total_urls'] = len(df)
            stats['phishing_urls'] = len(df[df['label'] == 1])
            stats['legitimate_urls'] = len(df[df['label'] == 0])
            stats['features_extracted'] = len(df.columns) - 1  # Exclude label column
        
        for name, df in self.datasets.items():
            stats['dataset_breakdown'][name] = {
                'records': len(df),
                'columns': list(df.columns)
            }
        
        return stats

def main():
    """Main function to demonstrate dataset preparation"""
    print("🤖 ML Dataset Preparation for Phishing Detection")
    print("=" * 60)
    
    # Initialize preparator
    preparator = PhishingDatasetPreparator()
    
    # Step 1: Download datasets
    print("\n📥 Step 1: Downloading Datasets...")
    downloaded_files = preparator.download_datasets()
    print(f"✅ Downloaded {len(downloaded_files)} dataset files")
    
    # Step 2: Load datasets
    print("\n📂 Step 2: Loading Datasets...")
    datasets = preparator.load_datasets()
    print(f"✅ Loaded {len(datasets)} datasets")
    
    # Step 3: Preprocess datasets
    print("\n🔧 Step 3: Preprocessing Datasets...")
    combined_df = preparator.preprocess_datasets()
    
    if combined_df is not None:
        print(f"✅ Combined dataset created with {len(combined_df)} records")
        
        # Step 4: Extract features
        print("\n🔍 Step 4: Extracting Features...")
        feature_df = preparator.extract_features(combined_df)
        print(f"✅ Extracted features for {len(feature_df)} URLs")
        
        # Step 5: Create train/test split
        print("\n📊 Step 5: Creating Train/Test Split...")
        X_train, X_test, y_train, y_test = preparator.create_train_test_split()
        
        if X_train is not None:
            print("✅ Train/test split created successfully")
            
            # Step 6: Dataset statistics
            print("\n📈 Step 6: Dataset Statistics...")
            stats = preparator.get_dataset_statistics()
            
            print(f"📊 Dataset Summary:")
            print(f"   Total URLs: {stats['total_urls']}")
            print(f"   Phishing URLs: {stats['phishing_urls']} ({stats['phishing_urls']/stats['total_urls']*100:.1f}%)")
            print(f"   Legitimate URLs: {stats['legitimate_urls']} ({stats['legitimate_urls']/stats['total_urls']*100:.1f}%)")
            print(f"   Features Extracted: {stats['features_extracted']}")
            
            print(f"\n📁 Files Created:")
            print(f"   📄 Combined Dataset: data/combined_phishing_dataset.csv")
            print(f"   🔍 Feature Dataset: data/feature_dataset.csv")
            print(f"   📚 Training Set: data/train_dataset.csv")
            print(f"   🧪 Test Set: data/test_dataset.csv")
            
            print(f"\n🎯 Dataset is ready for ML model training!")
        
    else:
        print("❌ Failed to create combined dataset")

if __name__ == "__main__":
    main()
