import os
from datetime import timedelta

class Config:
    """Application configuration"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Database configuration
    DATABASE_TYPE = os.environ.get('DATABASE_TYPE', 'sqlite')  # sqlite, mongodb, postgresql
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///phishing_detection.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # MongoDB configuration (if using MongoDB)
    MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/phishing_detection')
    
    # API Keys for Threat Intelligence
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    IPQUALITYSCORE_API_KEY = os.environ.get('IPQUALITYSCORE_API_KEY', '')
    URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY', '')
    
    # JWT configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per hour"
    
    # Model paths
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model')
    URL_MODEL_PATH = os.path.join(MODEL_PATH, 'url_model.pkl')
    EMAIL_MODEL_PATH = os.path.join(MODEL_PATH, 'email_model.pkl')
    SMS_MODEL_PATH = os.path.join(MODEL_PATH, 'sms_model.pkl')
    VECTORIZER_PATH = os.path.join(MODEL_PATH, 'vectorizer.pkl')
    
    # Dataset paths
    DATASET_PATH = os.path.join(os.path.dirname(__file__), 'dataset')
    
    # Risk score thresholds
    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 70
    DANGEROUS_THRESHOLD = 100
    
    # NLP configuration
    NLP_MODEL = 'en_core_web_sm'  # spaCy model
    
    # Feature extraction settings
    MAX_URL_LENGTH = 2048
    MAX_EMAIL_LENGTH = 10000
    MAX_SMS_LENGTH = 1000
    
    # Threat API settings
    API_TIMEOUT = 10  # seconds
    ENABLE_THREAT_APIS = os.environ.get('ENABLE_THREAT_APIS', 'True').lower() == 'true'
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'app.log')
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Production settings
    PRODUCTION = os.environ.get('PRODUCTION', 'False').lower() == 'true'