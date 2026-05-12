import sqlite3
from datetime import datetime

class Database:
    """Database helper class for phishing detection system"""
    
    def __init__(self, db_path='phishing.db'):
        self.db_path = db_path
        self.init_tables()
    
    def init_tables(self):
        """Initialize all database tables"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Logs table/g[]
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_data TEXT,
            input_type TEXT,
            prediction TEXT,
            risk_score INTEGER,
            confidence REAL,
            threat_type TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Feedback table
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            user_feedback TEXT,
            corrected_prediction TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Blacklist table
        c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            malicious_input TEXT,
            threat_type TEXT,
            source TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Stats table
        c.execute('''CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_scans INTEGER DEFAULT 0,
            phishing_detected INTEGER DEFAULT 0,
            suspicious_detected INTEGER DEFAULT 0,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Insert initial stats if empty
        c.execute('SELECT COUNT(*) FROM stats')
        if c.fetchone()[0] == 0:
            c.execute('INSERT INTO stats (total_scans, phishing_detected, suspicious_detected) VALUES (0, 0, 0)')
        
        conn.commit()
        conn.close()
        print("✅ Database tables initialized")
    
    def save_log(self, input_data, input_type, prediction, risk_score, confidence, threat_type, reason):
        """Save a scan log"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''INSERT INTO logs (input_data, input_type, prediction, risk_score, confidence, threat_type, reason)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (input_data, input_type, prediction, risk_score, confidence, threat_type, reason))
        
        log_id = c.lastrowid
        
        # Update stats
        c.execute('UPDATE stats SET total_scans = total_scans + 1, last_updated = CURRENT_TIMESTAMP')
        if prediction == "PHISHING":
            c.execute('UPDATE stats SET phishing_detected = phishing_detected + 1')
        elif prediction == "SUSPICIOUS":
            c.execute('UPDATE stats SET suspicious_detected = suspicious_detected + 1')
        
        conn.commit()
        conn.close()
        
        return log_id
    
    def get_history(self, limit=50):
        """Get scan history"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''SELECT id, input_data, input_type, prediction, risk_score, confidence, threat_type, timestamp
                     FROM logs ORDER BY timestamp DESC LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()
        
        history = []
        for row in rows:
            history.append({
                'id': row[0],
                'input_data': row[1],
                'input_type': row[2],
                'prediction': row[3],
                'risk_score': row[4],
                'confidence': row[5],
                'threat_type': row[6],
                'timestamp': row[7]
            })
        
        return history
    
    def get_stats(self):
        """Get statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT total_scans, phishing_detected, suspicious_detected FROM stats LIMIT 1')
        row = c.fetchone()
        conn.close()
        
        if row:
            total, phishing, suspicious = row
            return {
                'total_scans': total,
                'phishing_detected': phishing,
                'suspicious_detected': suspicious,
                'safe_detected': total - phishing - suspicious
            }
        return {
            'total_scans': 0,
            'phishing_detected': 0,
            'suspicious_detected': 0,
            'safe_detected': 0
        }
    
    def add_feedback(self, log_id, feedback, corrected_prediction):
        """Add user feedback"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO feedback (log_id, user_feedback, corrected_prediction)
                     VALUES (?, ?, ?)''', (log_id, feedback, corrected_prediction))
        conn.commit()
        conn.close()
    
    def add_to_blacklist(self, malicious_input, threat_type, source='user'):
        """Add URL to blacklist"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT OR IGNORE INTO blacklist (malicious_input, threat_type, source)
                     VALUES (?, ?, ?)''', (malicious_input, threat_type, source))
        conn.commit()
        conn.close()

# Singleton instance
db = Database()