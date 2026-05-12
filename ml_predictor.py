"""
Machine Learning Predictor - Load and use trained models for predictions
"""

import pickle
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression


class MLPredictor:
    """Machine Learning prediction engine"""
    
    def __init__(self):
        self.url_model = None
        self.email_model = None
        self.sms_model = None
        self.models_loaded = False
        
        # Try to load models
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            model_path = os.path.join(os.path.dirname(__file__), '..', 'model')
            
            # Load URL model
            url_model_path = os.path.join(model_path, 'url_model.pkl')
            if os.path.exists(url_model_path):
                with open(url_model_path, 'rb') as f:
                    self.url_model = pickle.load(f)
            else:
                # Create default model
                self.url_model = RandomForestClassifier(n_estimators=100, random_state=42)
            
            # Load Email model
            email_model_path = os.path.join(model_path, 'email_model.pkl')
            if os.path.exists(email_model_path):
                with open(email_model_path, 'rb') as f:
                    self.email_model = pickle.load(f)
            else:
                # Create default model
                self.email_model = RandomForestClassifier(n_estimators=100, random_state=42)
            
            # Load SMS model
            sms_model_path = os.path.join(model_path, 'sms_model.pkl')
            if os.path.exists(sms_model_path):
                with open(sms_model_path, 'rb') as f:
                    self.sms_model = pickle.load(f)
            else:
                # Create default model
                self.sms_model = RandomForestClassifier(n_estimators=100, random_state=42)
            
            self.models_loaded = True
            
        except Exception as e:
            print(f"Warning: Could not load ML models: {e}")
            # Create default models
            self.url_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.email_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.sms_model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    def predict_url(self, url_features):
        """
        Predict if URL is phishing
        
        Args:
            url_features: Dictionary of URL features
        
        Returns:
            dict: Prediction results with confidence
        """
        try:
            # Extract numerical features
            feature_vector = self._extract_url_vector(url_features)
            
            # Make prediction
            if hasattr(self.url_model, 'predict_proba'):
                # Model is trained
                feature_array = np.array(feature_vector).reshape(1, -1)
                prediction_proba = self.url_model.predict_proba(feature_array)[0]
                prediction = self.url_model.predict(feature_array)[0]
                
                # Get confidence (probability of predicted class)
                confidence = float(max(prediction_proba))
                
                return {
                    'prediction': 'Phishing' if prediction == 1 else 'Safe',
                    'confidence': confidence,
                    'phishing_probability': float(prediction_proba[1] if len(prediction_proba) > 1 else 0)
                }
            else:
                # Model not trained - use heuristic
                return self._heuristic_url_prediction(url_features)
                
        except Exception as e:
            print(f"URL prediction error: {e}")
            return self._heuristic_url_prediction(url_features)
    
    def predict_email(self, email_features):
        """
        Predict if email is phishing
        
        Args:
            email_features: Dictionary of email features
        
        Returns:
            dict: Prediction results with confidence
        """
        try:
            # Extract numerical features
            feature_vector = self._extract_email_vector(email_features)
            
            # Make prediction
            if hasattr(self.email_model, 'predict_proba'):
                feature_array = np.array(feature_vector).reshape(1, -1)
                prediction_proba = self.email_model.predict_proba(feature_array)[0]
                prediction = self.email_model.predict(feature_array)[0]
                
                confidence = float(max(prediction_proba))
                
                return {
                    'prediction': 'Phishing' if prediction == 1 else 'Safe',
                    'confidence': confidence,
                    'phishing_probability': float(prediction_proba[1] if len(prediction_proba) > 1 else 0)
                }
            else:
                return self._heuristic_email_prediction(email_features)
                
        except Exception as e:
            print(f"Email prediction error: {e}")
            return self._heuristic_email_prediction(email_features)
    
    def predict_sms(self, sms_features):
        """
        Predict if SMS is smishing
        
        Args:
            sms_features: Dictionary of SMS features
        
        Returns:
            dict: Prediction results with confidence
        """
        try:
            # Extract numerical features
            feature_vector = self._extract_sms_vector(sms_features)
            
            # Make prediction
            if hasattr(self.sms_model, 'predict_proba'):
                feature_array = np.array(feature_vector).reshape(1, -1)
                prediction_proba = self.sms_model.predict_proba(feature_array)[0]
                prediction = self.sms_model.predict(feature_array)[0]
                
                confidence = float(max(prediction_proba))
                
                return {
                    'prediction': 'Smishing' if prediction == 1 else 'Safe',
                    'confidence': confidence,
                    'phishing_probability': float(prediction_proba[1] if len(prediction_proba) > 1 else 0)
                }
            else:
                return self._heuristic_sms_prediction(sms_features)
                
        except Exception as e:
            print(f"SMS prediction error: {e}")
            return self._heuristic_sms_prediction(sms_features)
    
    def _extract_url_vector(self, features):
        """Extract numerical vector from URL features"""
        return [
            features.get('length', 0),
            features.get('num_dots', 0),
            features.get('num_hyphens', 0),
            features.get('num_underscores', 0),
            features.get('num_slashes', 0),
            features.get('num_question_marks', 0),
            features.get('num_equals', 0),
            features.get('num_at_symbols', 0),
            features.get('num_ampersands', 0),
            features.get('num_digits', 0),
            int(features.get('is_https', False)),
            features.get('domain_length', 0),
            features.get('num_subdomains', 0),
            int(features.get('has_ip_address', False)),
            int(features.get('has_suspicious_tld', False)),
            features.get('path_length', 0),
            features.get('num_path_segments', 0),
            int(features.get('has_suspicious_keywords', False)),
            features.get('num_suspicious_keywords', 0),
            int(features.get('has_double_slash', False)),
            int(features.get('has_redirect', False)),
            features.get('num_special_chars', 0),
            int(features.get('has_punycode', False)),
            int(features.get('is_long_url', False)),
            int(features.get('is_very_long_url', False)),
            int(features.get('has_numeric_domain', False)),
            features.get('domain_token_count', 0),
            features.get('brand_similarity', 0),
            features.get('url_entropy', 0),
            int(features.get('has_nonstandard_port', False))
        ]
    
    def _extract_email_vector(self, features):
        """Extract numerical vector from email features"""
        return [
            features.get('subject_length', 0),
            features.get('body_length', 0),
            features.get('num_links', 0),
            int(features.get('subject_has_urgency', False)),
            int(features.get('subject_has_fear', False)),
            int(features.get('subject_all_caps', False)),
            features.get('subject_num_exclamations', 0),
            int(features.get('body_has_urgency', False)),
            int(features.get('body_has_fear', False)),
            features.get('num_phishing_keywords', 0),
            int(features.get('sender_suspicious', False)),
            int(features.get('sender_free_email', False)),
            int(features.get('has_shortened_urls', False)),
            int(features.get('has_ip_links', False)),
            features.get('num_misspellings', 0),
            int(features.get('excessive_punctuation', False)),
            int(features.get('requests_personal_info', False)),
            int(features.get('requests_credentials', False)),
            int(features.get('requests_payment', False)),
            int(features.get('requests_click', False)),
            int(features.get('has_reward_claim', False)),
            int(features.get('impersonates_company', False)),
            features.get('num_html_tags', 0),
            features.get('num_special_chars', 0)
        ]
    
    def _extract_sms_vector(self, features):
        """Extract numerical vector from SMS features"""
        return [
            features.get('length', 0),
            int(features.get('has_url', False)),
            features.get('num_urls', 0),
            int(features.get('has_shortened_url', False)),
            int(features.get('has_ip_url', False)),
            features.get('num_smishing_keywords', 0),
            int(features.get('has_urgency', False)),
            int(features.get('requests_click', False)),
            int(features.get('requests_reply', False)),
            int(features.get('requests_call', False)),
            int(features.get('mentions_prize', False)),
            int(features.get('mentions_account', False)),
            int(features.get('mentions_delivery', False)),
            int(features.get('mentions_payment', False)),
            int(features.get('requests_personal_info', False)),
            int(features.get('sender_is_shortcode', False)),
            int(features.get('sender_suspicious', False)),
            int(features.get('all_caps', False)),
            features.get('num_exclamations', 0),
            int(features.get('has_phone_number', False)),
            int(features.get('has_amount', False)),
            int(features.get('has_code_pattern', False)),
            int(features.get('is_long', False))
        ]
    
    def _heuristic_url_prediction(self, features):
        """Heuristic-based URL prediction when model is not available"""
        risk_score = 0
        
        # Check various risk factors
        if features.get('has_ip_address'):
            risk_score += 30
        if features.get('has_suspicious_tld'):
            risk_score += 20
        if features.get('num_suspicious_keywords', 0) > 0:
            risk_score += 15 * features.get('num_suspicious_keywords', 0)
        if not features.get('is_https'):
            risk_score += 15
        if features.get('is_very_long_url'):
            risk_score += 10
        if features.get('brand_similarity', 0) > 0:
            risk_score += 25
        if features.get('has_redirect'):
            risk_score += 15
        
        risk_score = min(risk_score, 100)
        
        return {
            'prediction': 'Phishing' if risk_score > 50 else 'Safe',
            'confidence': risk_score / 100.0,
            'phishing_probability': risk_score / 100.0
        }
    
    def _heuristic_email_prediction(self, features):
        """Heuristic-based email prediction when model is not available"""
        risk_score = 0
        
        if features.get('subject_has_urgency') or features.get('body_has_urgency'):
            risk_score += 20
        if features.get('subject_has_fear') or features.get('body_has_fear'):
            risk_score += 25
        if features.get('requests_personal_info'):
            risk_score += 30
        if features.get('requests_credentials'):
            risk_score += 35
        if features.get('has_ip_links'):
            risk_score += 20
        if features.get('sender_suspicious'):
            risk_score += 15
        if features.get('num_phishing_keywords', 0) > 3:
            risk_score += 20
        
        risk_score = min(risk_score, 100)
        
        return {
            'prediction': 'Phishing' if risk_score > 50 else 'Safe',
            'confidence': risk_score / 100.0,
            'phishing_probability': risk_score / 100.0
        }
    
    def _heuristic_sms_prediction(self, features):
        """Heuristic-based SMS prediction when model is not available"""
        risk_score = 0
        
        if features.get('has_shortened_url'):
            risk_score += 30
        if features.get('mentions_prize'):
            risk_score += 25
        if features.get('requests_personal_info'):
            risk_score += 35
        if features.get('has_urgency'):
            risk_score += 20
        if features.get('mentions_account'):
            risk_score += 20
        if features.get('sender_suspicious'):
            risk_score += 15
        if features.get('num_smishing_keywords', 0) > 2:
            risk_score += 20
        
        risk_score = min(risk_score, 100)
        
        return {
            'prediction': 'Smishing' if risk_score > 50 else 'Safe',
            'confidence': risk_score / 100.0,
            'phishing_probability': risk_score / 100.0
        }