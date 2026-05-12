import re
from datetime import datetime


class EmailAnalyzer:
    """Analyze emails and extract features for phishing detection"""
    
    def __init__(self):
        self.phishing_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'locked', 'confirm',
            'update', 'secure', 'click here', 'act now', 'limited time',
            'expire', 'password', 'credential', 'billing', 'payment',
            'winner', 'prize', 'congratulations', 'claim', 'refund',
            'social security', 'tax', 'irs', 'bank', 'invoice'
        ]
        
        self.urgency_words = [
            'urgent', 'immediately', 'asap', 'now', 'today', 'expire',
            'deadline', 'act fast', 'hurry', 'limited time', 'final notice'
        ]
        
        self.fear_tactics = [
            'suspended', 'locked', 'blocked', 'terminated', 'deactivated',
            'unauthorized', 'fraud', 'security breach', 'violation',
            'legal action', 'arrest', 'penalty'
        ]
    
    def extract_features(self, subject, body, sender, links):
        """
        Extract comprehensive features from email
        
        Args:
            subject: Email subject line
            body: Email body text
            sender: Sender email address
            links: List of links in email
        
        Returns:
            dict: Dictionary containing all extracted features
        """
        try:
            features = {
                # Basic info
                'subject': subject,
                'sender': sender,
                'num_links': len(links),
                
                # Length features
                'subject_length': len(subject),
                'body_length': len(body),
                'total_length': len(subject) + len(body),
                
                # Subject features
                'subject_has_urgency': self._has_urgency_words(subject),
                'subject_has_fear': self._has_fear_tactics(subject),
                'subject_all_caps': subject.isupper() if subject else False,
                'subject_has_re_fwd': self._has_re_fwd(subject),
                'subject_num_exclamations': subject.count('!'),
                
                # Body features
                'body_has_urgency': self._has_urgency_words(body),
                'body_has_fear': self._has_fear_tactics(body),
                'body_has_phishing_keywords': self._has_phishing_keywords(body),
                'num_phishing_keywords': self._count_phishing_keywords(body),
                
                # Sender features
                'sender_suspicious': self._is_sender_suspicious(sender),
                'sender_has_numbers': any(c.isdigit() for c in sender),
                'sender_free_email': self._is_free_email(sender),
                
                # Link features
                'has_links': len(links) > 0,
                'num_links': len(links),
                'num_external_links': len(links),  # Simplified
                'has_shortened_urls': self._has_shortened_urls(links),
                'has_ip_links': self._has_ip_links(links),
                
                # Grammar and formatting
                'num_misspellings': self._estimate_misspellings(body),
                'excessive_punctuation': self._has_excessive_punctuation(body),
                'mixed_case': self._has_mixed_case(body),
                
                # Request patterns
                'requests_personal_info': self._requests_personal_info(body),
                'requests_credentials': self._requests_credentials(body),
                'requests_payment': self._requests_payment(body),
                'requests_click': self._requests_click(body),
                
                # Suspicious patterns
                'has_attachment_reference': self._has_attachment_reference(body),
                'has_reward_claim': self._has_reward_claim(body),
                'impersonates_company': self._impersonates_company(body),
                
                # HTML features
                'has_html': '<html' in body.lower() or '<body' in body.lower(),
                'num_html_tags': self._count_html_tags(body),
                
                # Special characters
                'num_special_chars': self._count_special_chars(subject + body)
            }
            
            return features
            
        except Exception as e:
            return {
                'error': str(e),
                'subject': subject,
                'sender': sender
            }
    
    def _has_urgency_words(self, text):
        """Check for urgency words"""
        text_lower = text.lower()
        return any(word in text_lower for word in self.urgency_words)
    
    def _has_fear_tactics(self, text):
        """Check for fear tactics"""
        text_lower = text.lower()
        return any(tactic in text_lower for tactic in self.fear_tactics)
    
    def _has_phishing_keywords(self, text):
        """Check for phishing keywords"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in self.phishing_keywords)
    
    def _count_phishing_keywords(self, text):
        """Count phishing keywords"""
        text_lower = text.lower()
        return sum(1 for keyword in self.phishing_keywords if keyword in text_lower)
    
    def _has_re_fwd(self, subject):
        """Check for RE: or FWD: prefixes"""
        return subject.lower().startswith(('re:', 'fwd:', 'fw:'))
    
    def _is_sender_suspicious(self, sender):
        """Check if sender address is suspicious"""
        if not sender:
            return True
        
        suspicious_patterns = [
            r'noreply@',
            r'no-reply@',
            r'donotreply@',
            r'notification@',
            r'alert@',
            r'service@'
        ]
        
        sender_lower = sender.lower()
        return any(re.search(pattern, sender_lower) for pattern in suspicious_patterns)
    
    def _is_free_email(self, sender):
        """Check if sender uses free email service"""
        free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
        sender_lower = sender.lower()
        return any(domain in sender_lower for domain in free_domains)
    
    def _has_shortened_urls(self, links):
        """Check for shortened URLs"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        return any(any(short in link.lower() for short in shorteners) for link in links)
    
    def _has_ip_links(self, links):
        """Check for IP addresses in links"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return any(re.search(ip_pattern, link) for link in links)
    
    def _estimate_misspellings(self, text):
        """Estimate number of misspellings (simplified)"""
        # This is a basic implementation
        # In production, use a proper spell checker
        common_misspellings = [
            'recieve', 'beleive', 'occured', 'untill', 'sucessful',
            'seperate', 'definately', 'goverment', 'occassion'
        ]
        text_lower = text.lower()
        return sum(1 for word in common_misspellings if word in text_lower)
    
    def _has_excessive_punctuation(self, text):
        """Check for excessive punctuation"""
        return text.count('!') > 3 or text.count('?') > 3
    
    def _has_mixed_case(self, text):
        """Check for mixed case (e.g., random caps)"""
        # Check if there's unusual capitalization
        words = text.split()
        mixed_count = sum(1 for word in words if any(c.isupper() for c in word[1:]))
        return mixed_count > len(words) * 0.2
    
    def _requests_personal_info(self, text):
        """Check if email requests personal information"""
        patterns = [
            'social security', 'ssn', 'date of birth', 'mother\\'s maiden',
            'account number', 'credit card', 'debit card', 'pin code',
            'routing number', 'driver\\'s license'
        ]
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in patterns)
    
    def _requests_credentials(self, text):
        """Check if email requests credentials"""
        patterns = ['password', 'username', 'login', 'credentials', 'access code']
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in patterns)
    
    def _requests_payment(self, text):
        """Check if email requests payment"""
        patterns = ['send money', 'wire transfer', 'payment required', 'pay now', 'invoice attached']
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in patterns)
    
    def _requests_click(self, text):
        """Check if email urgently requests clicking"""
        patterns = ['click here', 'click now', 'click below', 'tap here', 'follow this link']
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in patterns)
    
    def _has_attachment_reference(self, text):
        """Check for attachment references"""
        patterns = ['see attached', 'attachment', 'attached file', 'open attachment']
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in patterns)
    
    def _has_reward_claim(self, text):
        """Check for reward/prize claims"""
        patterns = ['you won', 'winner', 'prize', 'claim your', 'free gift', 'reward']
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in patterns)
    
    def _impersonates_company(self, text):
        """Check for company impersonation"""
        companies = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'netflix', 'ebay', 'bank of america', 'chase', 'wells fargo'
        ]
        text_lower = text.lower()
        return any(company in text_lower for company in companies)
    
    def _count_html_tags(self, text):
        """Count HTML tags"""
        return len(re.findall(r'<[^>]+>', text))
    
    def _count_special_chars(self, text):
        """Count special characters"""
        special_chars = set('@#$%^&*()[]{}|\\<>;')
        return sum(1 for c in text if c in special_chars)
    
    def get_feature_vector(self, subject, body, sender, links):
        """
        Get numerical feature vector for ML model
        
        Returns:
            list: Feature vector for machine learning
        """
        features = self.extract_features(subject, body, sender, links)
        
        vector = [
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
        
        return vector