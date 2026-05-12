from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os
import sys

# Import custom modules
from utils.url_analyzer import URLAnalyzer
from utils.email_analyzer import EmailAnalyzer
from utils.sms_analyzer import SMSAnalyzer
from utils.ml_predictor import MLPredictor
from utils.nlp_engine import NLPEngine
from utils.threat_apis import ThreatAPIs
from utils.risk_scorer import RiskScorer
from database.db_manager import DatabaseManager
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize components
db_manager = DatabaseManager()
url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()
sms_analyzer = SMSAnalyzer()
ml_predictor = MLPredictor()
nlp_engine = NLPEngine()
threat_apis = ThreatAPIs()
risk_scorer = RiskScorer()


@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'message': 'AI Phishing Detection System',
        'version': '1.0.0',
        'author': 'Made by Virat - All Rights Reserved © 2026'
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'database': 'connected',
            'ml_model': 'loaded',
            'nlp_engine': 'ready',
            'threat_apis': 'configured'
        }
    })


@app.route('/api/check-url', methods=['POST'])
def check_url():
    """
    Check if a URL is phishing/malicious
    
    Request Body:
    {
        "url": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract URL features
        url_features = url_analyzer.extract_features(url)
        
        # Get ML prediction
        ml_prediction = ml_predictor.predict_url(url_features)
        
        # Analyze with NLP
        nlp_score = nlp_engine.analyze_url(url)
        
        # Check external threat APIs
        threat_intel = threat_apis.check_url(url)
        
        # Calculate risk score
        risk_analysis = risk_scorer.calculate_url_risk(
            url_features=url_features,
            ml_prediction=ml_prediction,
            nlp_score=nlp_score,
            threat_intel=threat_intel
        )
        
        # Log to database
        db_manager.log_scan({
            'input_type': 'url',
            'input_data': url,
            'prediction': risk_analysis['prediction'],
            'risk_score': risk_analysis['risk_score'],
            'confidence': risk_analysis['confidence'],
            'threat_type': risk_analysis['threat_type'],
            'timestamp': datetime.now().isoformat()
        })
        
        # Return comprehensive analysis
        return jsonify({
            'success': True,
            'url': url,
            'prediction': risk_analysis['prediction'],
            'confidence': risk_analysis['confidence'],
            'risk_score': risk_analysis['risk_score'],
            'threat_type': risk_analysis['threat_type'],
            'reason': risk_analysis['reason'],
            'details': {
                'url_features': url_features,
                'ml_confidence': ml_prediction['confidence'],
                'nlp_score': nlp_score,
                'threat_intelligence': threat_intel
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/check-email', methods=['POST'])
def check_email():
    """
    Check if an email is phishing
    
    Request Body:
    {
        "subject": "Email subject",
        "body": "Email body text",
        "sender": "sender@example.com",
        "links": ["url1", "url2"]
    }
    """
    try:
        data = request.get_json()
        
        subject = data.get('subject', '')
        body = data.get('body', '')
        sender = data.get('sender', '')
        links = data.get('links', [])
        
        if not body and not subject:
            return jsonify({'error': 'Email content is required'}), 400
        
        # Analyze email
        email_features = email_analyzer.extract_features(
            subject=subject,
            body=body,
            sender=sender,
            links=links
        )
        
        # Get ML prediction
        ml_prediction = ml_predictor.predict_email(email_features)
        
        # NLP analysis
        nlp_score = nlp_engine.analyze_email(subject, body)
        
        # Check links if present
        link_analysis = []
        if links:
            for link in links:
                link_threat = threat_apis.check_url(link)
                link_analysis.append({
                    'url': link,
                    'threat_score': link_threat.get('risk_score', 0)
                })
        
        # Calculate risk score
        risk_analysis = risk_scorer.calculate_email_risk(
            email_features=email_features,
            ml_prediction=ml_prediction,
            nlp_score=nlp_score,
            link_analysis=link_analysis
        )
        
        # Log to database
        db_manager.log_scan({
            'input_type': 'email',
            'input_data': f"Subject: {subject[:100]}",
            'prediction': risk_analysis['prediction'],
            'risk_score': risk_analysis['risk_score'],
            'confidence': risk_analysis['confidence'],
            'threat_type': risk_analysis['threat_type'],
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': True,
            'prediction': risk_analysis['prediction'],
            'confidence': risk_analysis['confidence'],
            'risk_score': risk_analysis['risk_score'],
            'threat_type': risk_analysis['threat_type'],
            'reason': risk_analysis['reason'],
            'details': {
                'email_features': email_features,
                'ml_confidence': ml_prediction['confidence'],
                'nlp_score': nlp_score,
                'suspicious_links': link_analysis
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/check-sms', methods=['POST'])
def check_sms():
    """
    Check if an SMS is smishing/phishing
    
    Request Body:
    {
        "message": "SMS text content",
        "sender": "Sender number/ID"
    }
    """
    try:
        data = request.get_json()
        
        message = data.get('message', '').strip()
        sender = data.get('sender', '')
        
        if not message:
            return jsonify({'error': 'SMS message is required'}), 400
        
        # Analyze SMS
        sms_features = sms_analyzer.extract_features(message, sender)
        
        # Get ML prediction
        ml_prediction = ml_predictor.predict_sms(sms_features)
        
        # NLP analysis
        nlp_score = nlp_engine.analyze_sms(message)
        
        # Extract and check URLs in SMS
        urls_in_sms = sms_analyzer.extract_urls(message)
        url_threats = []
        if urls_in_sms:
            for url in urls_in_sms:
                threat = threat_apis.check_url(url)
                url_threats.append({
                    'url': url,
                    'threat_score': threat.get('risk_score', 0)
                })
        
        # Calculate risk score
        risk_analysis = risk_scorer.calculate_sms_risk(
            sms_features=sms_features,
            ml_prediction=ml_prediction,
            nlp_score=nlp_score,
            url_threats=url_threats
        )
        
        # Log to database
        db_manager.log_scan({
            'input_type': 'sms',
            'input_data': message[:100],
            'prediction': risk_analysis['prediction'],
            'risk_score': risk_analysis['risk_score'],
            'confidence': risk_analysis['confidence'],
            'threat_type': risk_analysis['threat_type'],
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': True,
            'prediction': risk_analysis['prediction'],
            'confidence': risk_analysis['confidence'],
            'risk_score': risk_analysis['risk_score'],
            'threat_type': risk_analysis['threat_type'],
            'reason': risk_analysis['reason'],
            'details': {
                'sms_features': sms_features,
                'ml_confidence': ml_prediction['confidence'],
                'nlp_score': nlp_score,
                'suspicious_urls': url_threats
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        scan_type = request.args.get('type', None)
        
        history = db_manager.get_scan_history(limit=limit, scan_type=scan_type)
        
        return jsonify({
            'success': True,
            'count': len(history),
            'history': history
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    """Get dashboard analytics"""
    try:
        stats = db_manager.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback for incorrect predictions"""
    try:
        data = request.get_json()
        
        scan_id = data.get('scan_id')
        feedback = data.get('feedback')
        corrected_result = data.get('corrected_result')
        
        db_manager.save_feedback({
            'scan_id': scan_id,
            'user_feedback': feedback,
            'corrected_result': corrected_result,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/blacklist/add', methods=['POST'])
def add_to_blacklist():
    """Add URL to blacklist"""
    try:
        data = request.get_json()
        url = data.get('url')
        threat_type = data.get('threat_type', 'Phishing')
        source = data.get('source', 'Manual')
        
        db_manager.add_to_blacklist(url, threat_type, source)
        
        return jsonify({
            'success': True,
            'message': 'URL added to blacklist'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    """Get blacklist"""
    try:
        blacklist = db_manager.get_blacklist()
        
        return jsonify({
            'success': True,
            'count': len(blacklist),
            'blacklist': blacklist
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    # Initialize database
    db_manager.initialize()
    
    # Run Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)