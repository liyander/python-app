#!/usr/bin/env python3
"""
Day 13: ML Model Training & Serialization
Train and save phishing detection models using Random Forest and Logistic Regression
"""

import pandas as pd
import numpy as np
import joblib
import json
import os
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import logging
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PhishingModelTrainer:
    """
    Comprehensive ML model trainer for phishing detection
    Supports Random Forest and Logistic Regression with hyperparameter tuning
    """
    
    def __init__(self, data_dir="data", models_dir="models"):
        self.data_dir = data_dir
        self.models_dir = models_dir
        self.scaler = StandardScaler()
        
        # Create models directory
        os.makedirs(models_dir, exist_ok=True)
        
        # Model configurations
        self.models_config = {
            'random_forest': {
                'name': 'Random Forest',
                'class': RandomForestClassifier,
                'params': {
                    'n_estimators': [50, 100, 200],
                    'max_depth': [5, 10, 20, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4],
                    'random_state': [42]
                },
                'default_params': {
                    'n_estimators': 100,
                    'max_depth': 10,
                    'min_samples_split': 5,
                    'min_samples_leaf': 2,
                    'random_state': 42
                }
            },
            'logistic_regression': {
                'name': 'Logistic Regression',
                'class': LogisticRegression,
                'params': {
                    'C': [0.01, 0.1, 1, 10, 100],
                    'penalty': ['l1', 'l2'],
                    'solver': ['liblinear'],
                    'random_state': [42],
                    'max_iter': [1000]
                },
                'default_params': {
                    'C': 1.0,
                    'penalty': 'l2',
                    'solver': 'liblinear',
                    'random_state': 42,
                    'max_iter': 1000
                }
            }
        }
        
        self.trained_models = {}
        self.training_results = {}
        
    def load_data(self):
        """Load and prepare training data"""
        logger.info("📂 Loading training data...")
        
        try:
            # Try to load feature dataset first
            feature_file = os.path.join(self.data_dir, "feature_dataset.csv")
            if os.path.exists(feature_file):
                df = pd.read_csv(feature_file)
                logger.info(f"✅ Loaded feature dataset: {len(df)} samples")
            else:
                # Fallback to train dataset
                train_file = os.path.join(self.data_dir, "train_dataset.csv")
                test_file = os.path.join(self.data_dir, "test_dataset.csv")
                
                if os.path.exists(train_file) and os.path.exists(test_file):
                    train_df = pd.read_csv(train_file)
                    test_df = pd.read_csv(test_file)
                    df = pd.concat([train_df, test_df], ignore_index=True)
                    logger.info(f"✅ Loaded train/test datasets: {len(df)} samples")
                else:
                    raise FileNotFoundError("No training data found. Run ml_demo.py first to generate datasets.")
            
            # Separate features and labels
            if 'label' not in df.columns:
                raise ValueError("Dataset missing 'label' column")
            
            # Select feature columns (exclude metadata columns)
            exclude_cols = ['label', 'url', 'category', 'source']
            feature_cols = [col for col in df.columns if col not in exclude_cols]
            
            X = df[feature_cols]
            y = df['label']
            
            logger.info(f"📊 Dataset summary:")
            logger.info(f"   Features: {len(feature_cols)}")
            logger.info(f"   Samples: {len(X)}")
            logger.info(f"   Phishing: {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
            logger.info(f"   Legitimate: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.1f}%)")
            
            return X, y, feature_cols
            
        except Exception as e:
            logger.error(f"❌ Error loading data: {str(e)}")
            raise
    
    def prepare_data(self, X, y, test_size=0.2, random_state=42):
        """Prepare data for training with proper scaling"""
        logger.info("🔧 Preparing data for training...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Scale features for Logistic Regression
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        logger.info(f"📊 Data split:")
        logger.info(f"   Training: {len(X_train)} samples")
        logger.info(f"   Testing: {len(X_test)} samples")
        
        return X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled
    
    def train_model(self, model_type, X_train, y_train, use_scaling=False, tune_hyperparameters=True):
        """Train a specific model with optional hyperparameter tuning"""
        logger.info(f"🚀 Training {self.models_config[model_type]['name']}...")
        
        model_config = self.models_config[model_type]
        
        if tune_hyperparameters:
            logger.info("🔍 Performing hyperparameter tuning...")
            
            # Create model with default parameters for grid search
            model = model_config['class']()
            
            # Perform grid search
            grid_search = GridSearchCV(
                model, 
                model_config['params'], 
                cv=5, 
                scoring='f1',
                n_jobs=-1,
                verbose=0
            )
            
            grid_search.fit(X_train, y_train)
            
            best_model = grid_search.best_estimator_
            best_params = grid_search.best_params_
            
            logger.info(f"✅ Best parameters: {best_params}")
            
        else:
            # Use default parameters
            best_model = model_config['class'](**model_config['default_params'])
            best_model.fit(X_train, y_train)
            best_params = model_config['default_params']
        
        return best_model, best_params
    
    def evaluate_model(self, model, X_test, y_test, model_name):
        """Comprehensive model evaluation"""
        logger.info(f"📊 Evaluating {model_name}...")
        
        # Make predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else None
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # Classification report
        report = classification_report(y_test, y_pred, output_dict=True)
        
        results = {
            'metrics': metrics,
            'confusion_matrix': cm.tolist(),
            'classification_report': report,
            'predictions': {
                'y_true': y_test.tolist(),
                'y_pred': y_pred.tolist(),
                'y_pred_proba': y_pred_proba.tolist() if y_pred_proba is not None else None
            }
        }
        
        # Print results
        logger.info(f"📈 {model_name} Results:")
        logger.info(f"   Accuracy:  {metrics['accuracy']:.3f}")
        logger.info(f"   Precision: {metrics['precision']:.3f}")
        logger.info(f"   Recall:    {metrics['recall']:.3f}")
        logger.info(f"   F1-Score:  {metrics['f1_score']:.3f}")
        if metrics['roc_auc']:
            logger.info(f"   ROC-AUC:   {metrics['roc_auc']:.3f}")
        
        return results
    
    def save_model(self, model, model_name, feature_cols, scaler=None, metadata=None):
        """Save trained model with metadata"""
        logger.info(f"💾 Saving {model_name}...")
        
        # Create model package
        model_package = {
            'model': model,
            'model_name': model_name,
            'feature_columns': feature_cols,
            'scaler': scaler,
            'metadata': metadata or {},
            'created_at': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        # Save model
        model_filename = f"{model_name.lower().replace(' ', '_')}_model.joblib"
        model_path = os.path.join(self.models_dir, model_filename)
        
        joblib.dump(model_package, model_path)
        
        logger.info(f"✅ Model saved: {model_path}")
        return model_path
    
    def load_model(self, model_path):
        """Load saved model"""
        try:
            model_package = joblib.load(model_path)
            logger.info(f"✅ Loaded model: {model_package['model_name']}")
            return model_package
        except Exception as e:
            logger.error(f"❌ Error loading model: {str(e)}")
            raise
    
    def cross_validate_model(self, model, X, y, cv=5):
        """Perform cross-validation"""
        logger.info("🔄 Performing cross-validation...")
        
        scores = cross_val_score(model, X, y, cv=cv, scoring='f1')
        
        logger.info(f"📊 Cross-validation results:")
        logger.info(f"   F1 Scores: {scores}")
        logger.info(f"   Mean F1:   {scores.mean():.3f} (+/- {scores.std() * 2:.3f})")
        
        return scores
    
    def create_visualizations(self, results, model_name):
        """Create visualization plots for model performance"""
        logger.info(f"📊 Creating visualizations for {model_name}...")
        
        # Set up plot style
        plt.style.use('default')
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(f'{model_name} - Performance Analysis', fontsize=16, fontweight='bold')
        
        # 1. Confusion Matrix
        cm = np.array(results['confusion_matrix'])
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0,0])
        axes[0,0].set_title('Confusion Matrix')
        axes[0,0].set_xlabel('Predicted')
        axes[0,0].set_ylabel('Actual')
        axes[0,0].set_xticklabels(['Legitimate', 'Phishing'])
        axes[0,0].set_yticklabels(['Legitimate', 'Phishing'])
        
        # 2. Metrics Bar Chart
        metrics = results['metrics']
        metric_names = list(metrics.keys())
        metric_values = [metrics[name] for name in metric_names if metrics[name] is not None]
        metric_names = [name for name in metric_names if metrics[name] is not None]
        
        bars = axes[0,1].bar(metric_names, metric_values, color=['skyblue', 'lightgreen', 'lightcoral', 'gold', 'plum'])
        axes[0,1].set_title('Performance Metrics')
        axes[0,1].set_ylim(0, 1)
        axes[0,1].set_ylabel('Score')
        
        # Add value labels on bars
        for bar, value in zip(bars, metric_values):
            axes[0,1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                          f'{value:.3f}', ha='center', va='bottom')
        
        # 3. ROC Curve (if available)
        if results['predictions']['y_pred_proba'] is not None:
            y_true = results['predictions']['y_true']
            y_pred_proba = results['predictions']['y_pred_proba']
            
            fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
            
            axes[1,0].plot(fpr, tpr, color='darkorange', lw=2, 
                          label=f'ROC curve (AUC = {metrics["roc_auc"]:.3f})')
            axes[1,0].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            axes[1,0].set_xlim([0.0, 1.0])
            axes[1,0].set_ylim([0.0, 1.05])
            axes[1,0].set_xlabel('False Positive Rate')
            axes[1,0].set_ylabel('True Positive Rate')
            axes[1,0].set_title('ROC Curve')
            axes[1,0].legend(loc="lower right")
        else:
            axes[1,0].text(0.5, 0.5, 'ROC Curve\nNot Available', 
                          ha='center', va='center', transform=axes[1,0].transAxes)
            axes[1,0].set_title('ROC Curve')
        
        # 4. Prediction Distribution
        y_pred = results['predictions']['y_pred']
        unique, counts = np.unique(y_pred, return_counts=True)
        
        colors = ['lightblue', 'lightcoral']
        labels = ['Legitimate', 'Phishing']
        
        axes[1,1].pie(counts, labels=[labels[i] for i in unique], autopct='%1.1f%%', 
                     colors=[colors[i] for i in unique])
        axes[1,1].set_title('Prediction Distribution')
        
        plt.tight_layout()
        
        # Save plot
        plot_filename = f"{model_name.lower().replace(' ', '_')}_performance.png"
        plot_path = os.path.join(self.models_dir, plot_filename)
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        
        logger.info(f"📊 Visualization saved: {plot_path}")
        plt.close()
        
        return plot_path
    
    def train_all_models(self, tune_hyperparameters=True, create_plots=True):
        """Train all configured models"""
        logger.info("🚀 Starting comprehensive model training...")
        
        # Load data
        X, y, feature_cols = self.load_data()
        
        # Prepare data
        X_train, X_test, y_train, y_test, X_train_scaled, X_test_scaled = self.prepare_data(X, y)
        
        # Train Random Forest
        logger.info("\n" + "="*60)
        logger.info("🌲 TRAINING RANDOM FOREST")
        logger.info("="*60)
        
        rf_model, rf_params = self.train_model('random_forest', X_train, y_train, 
                                             use_scaling=False, tune_hyperparameters=tune_hyperparameters)
        
        # Cross-validate Random Forest
        rf_cv_scores = self.cross_validate_model(rf_model, X_train, y_train)
        
        # Evaluate Random Forest
        rf_results = self.evaluate_model(rf_model, X_test, y_test, "Random Forest")
        rf_results['best_parameters'] = rf_params
        rf_results['cv_scores'] = rf_cv_scores.tolist()
        
        # Save Random Forest
        rf_path = self.save_model(rf_model, "Random Forest", feature_cols, 
                                metadata={'best_parameters': rf_params, 'cv_scores': rf_cv_scores.tolist()})
        
        # Create visualizations for Random Forest
        if create_plots:
            rf_plot_path = self.create_visualizations(rf_results, "Random Forest")
        
        # Train Logistic Regression
        logger.info("\n" + "="*60)
        logger.info("📈 TRAINING LOGISTIC REGRESSION")
        logger.info("="*60)
        
        lr_model, lr_params = self.train_model('logistic_regression', X_train_scaled, y_train, 
                                             use_scaling=True, tune_hyperparameters=tune_hyperparameters)
        
        # Cross-validate Logistic Regression
        lr_cv_scores = self.cross_validate_model(lr_model, X_train_scaled, y_train)
        
        # Evaluate Logistic Regression
        lr_results = self.evaluate_model(lr_model, X_test_scaled, y_test, "Logistic Regression")
        lr_results['best_parameters'] = lr_params
        lr_results['cv_scores'] = lr_cv_scores.tolist()
        
        # Save Logistic Regression
        lr_path = self.save_model(lr_model, "Logistic Regression", feature_cols, scaler=self.scaler,
                                metadata={'best_parameters': lr_params, 'cv_scores': lr_cv_scores.tolist()})
        
        # Create visualizations for Logistic Regression
        if create_plots:
            lr_plot_path = self.create_visualizations(lr_results, "Logistic Regression")
        
        # Store results
        self.trained_models = {
            'random_forest': {'model': rf_model, 'path': rf_path},
            'logistic_regression': {'model': lr_model, 'path': lr_path, 'scaler': self.scaler}
        }
        
        self.training_results = {
            'random_forest': rf_results,
            'logistic_regression': lr_results
        }
        
        # Save training summary
        self.save_training_summary(feature_cols)
        
        return self.training_results
    
    def save_training_summary(self, feature_cols):
        """Save comprehensive training summary"""
        logger.info("📋 Saving training summary...")
        
        summary = {
            'training_date': datetime.now().isoformat(),
            'dataset_info': {
                'total_features': len(feature_cols),
                'feature_names': feature_cols
            },
            'models': {}
        }
        
        for model_name, results in self.training_results.items():
            summary['models'][model_name] = {
                'metrics': results['metrics'],
                'best_parameters': results['best_parameters'],
                'cv_mean_f1': np.mean(results['cv_scores']),
                'cv_std_f1': np.std(results['cv_scores'])
            }
        
        # Save summary
        summary_path = os.path.join(self.models_dir, "training_summary.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"✅ Training summary saved: {summary_path}")
        
        return summary

def main():
    """Main function to run model training"""
    print("🤖 Day 13: ML Model Training & Serialization")
    print("=" * 60)
    
    # Initialize trainer
    trainer = PhishingModelTrainer()
    
    try:
        # Train all models
        results = trainer.train_all_models(tune_hyperparameters=True, create_plots=True)
        
        # Print final summary
        print("\n" + "🎯 TRAINING COMPLETE" + "\n" + "="*60)
        
        for model_name, result in results.items():
            metrics = result['metrics']
            print(f"\n🏆 {model_name.replace('_', ' ').title()}")
            print(f"   Accuracy:  {metrics['accuracy']:.3f}")
            print(f"   Precision: {metrics['precision']:.3f}")
            print(f"   Recall:    {metrics['recall']:.3f}")
            print(f"   F1-Score:  {metrics['f1_score']:.3f}")
            if metrics['roc_auc']:
                print(f"   ROC-AUC:   {metrics['roc_auc']:.3f}")
        
        # Determine best model
        rf_f1 = results['random_forest']['metrics']['f1_score']
        lr_f1 = results['logistic_regression']['metrics']['f1_score']
        
        best_model = "Random Forest" if rf_f1 > lr_f1 else "Logistic Regression"
        best_f1 = max(rf_f1, lr_f1)
        
        print(f"\n🥇 Best Model: {best_model} (F1-Score: {best_f1:.3f})")
        
        print(f"\n📁 Files Created:")
        print(f"   🤖 models/random_forest_model.joblib")
        print(f"   🤖 models/logistic_regression_model.joblib") 
        print(f"   📊 models/random_forest_performance.png")
        print(f"   📊 models/logistic_regression_performance.png")
        print(f"   📋 models/training_summary.json")
        
        print(f"\n🚀 Ready for deployment and integration!")
        
    except Exception as e:
        logger.error(f"❌ Training failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()
