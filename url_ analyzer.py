"""
URL Analyzer - Extract features from URLs for ML prediction
"""

import re
from urllib.parse import urlparse
import tld
from datetime import datetime


class URLAnalyzer:
    """Analyze URLs and extract features for phishing detection"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'update', 'secure',
            'banking', 'paypal', 'amazon', 'ebay', 'apple', 'microsoft',
            'confirm', 'suspended', 'locked', 'urgent', 'click', 'password',
            'credential', 'validation', 'authenticate', 'security'
        ]
    
    def extract_features(self, url):
        """
        Extract comprehensive features from URL
        
        Returns:
            dict: Dictionary containing all extracted features
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            features = {
                # Basic features
                'url': url,
                'length': len(url),
                'domain': domain,
                'path': path,
                
                # URL structure features
                'num_dots': url.count('.'),
                'num_hyphens': url.count('-'),
                'num_underscores': url.count('_'),
                'num_slashes': url.count('/'),
                'num_question_marks': url.count('?'),
                'num_equals': url.count('='),
                'num_at_symbols': url.count('@'),
                'num_ampersands': url.count('&'),
                'num_digits': sum(c.isdigit() for c in url),
                
                # Protocol features
                'is_https': url.startswith('https://'),
                'has_http': 'http' in url.lower(),
                
                # Domain features
                'domain_length': len(domain),
                'num_subdomains': domain.count('.'),
                'has_ip_address': self._has_ip_address(domain),
                'has_suspicious_tld': self._has_suspicious_tld(domain),
                
                # Path features
                'path_length': len(path),
                'num_path_segments': len([p for p in path.split('/') if p]),
                
                # Suspicious patterns
                'has_suspicious_keywords': self._has_suspicious_keywords(url),
                'num_suspicious_keywords': self._count_suspicious_keywords(url),
                'has_double_slash': '//' in path,
                'has_redirect': self._has_redirect_pattern(url),
                
                # Special characters
                'num_special_chars': self._count_special_chars(url),
                'has_punycode': 'xn--' in url,
                
                # Length-based features
                'is_long_url': len(url) > 75,
                'is_very_long_url': len(url) > 150,
                
                # Domain-based features
                'has_numeric_domain': any(c.isdigit() for c in domain),
                'domain_token_count': len(domain.split('.')),
                
                # Brand impersonation detection
                'brand_similarity': self._check_brand_similarity(domain),
                
                # Entropy
                'url_entropy': self._calculate_entropy(url),
                
                # Port check
                'has_nonstandard_port': self._has_nonstandard_port(url)
            }
            
            return features
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'length': len(url),
                'is_valid': False
            }
    
    def _has_ip_address(self, domain):
        """Check if domain is an IP address"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return bool(re.match(ip_pattern, domain))
    
    def _has_suspicious_tld(self, domain):
        """Check for suspicious top-level domains"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        return any(domain.endswith(tld) for tld in suspicious_tlds)
    
    def _has_suspicious_keywords(self, url):
        """Check if URL contains suspicious keywords"""
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in self.suspicious_keywords)
    
    def _count_suspicious_keywords(self, url):
        """Count number of suspicious keywords"""
        url_lower = url.lower()
        return sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
    
    def _has_redirect_pattern(self, url):
        """Check for redirect patterns"""
        redirect_patterns = ['redirect', 'redir', 'r=', 'url=', 'continue=', 'next=']
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in redirect_patterns)
    
    def _count_special_chars(self, url):
        """Count special characters"""
        special_chars = set('@#$%^&*()[]{}|\\<>;')
        return sum(1 for c in url if c in special_chars)
    
    def _check_brand_similarity(self, domain):
        """Check for brand name similarity (basic implementation)"""
        famous_brands = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'netflix', 'ebay', 'bank', 'chase', 'wellsfargo', 'citi'
        ]
        domain_lower = domain.lower()
        
        # Check for exact matches
        for brand in famous_brands:
            if brand in domain_lower and brand != domain_lower:
                # Brand name in domain but not exact match (suspicious)
                return 1
        
        return 0
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        from math import log2
        
        if not text:
            return 0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * log2(probability)
        
        return entropy
    
    def _has_nonstandard_port(self, url):
        """Check for non-standard ports"""
        parsed = urlparse(url)
        if parsed.port:
            standard_ports = [80, 443, 8080]
            return parsed.port not in standard_ports
        return False
    
    def get_feature_vector(self, url):
        """
        Get numerical feature vector for ML model
        
        Returns:
            list: Feature vector for machine learning
        """
        features = self.extract_features(url)
        
        # Convert to numerical vector
        vector = [
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
        
        return vector