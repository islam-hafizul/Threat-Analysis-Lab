import re
from datetime import datetime, timedelta
import json

class LogAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r"Failed password for root",
            r"Invalid user \w+ from",
            r"authentication failure",
            r"POSSIBLE BREAK-IN ATTEMPT"
        ]
        
    # Analyze auth logs for suspicious patterns
    def detect_suspicious_logins(self, log_file):
        alerts = []
        
        with open(log_file, 'r') as f:
            for line in f:
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, line):
                        alert = {
                            'timestamp': datetime.now(),
                            'log_line': line.strip(),
                            'pattern': pattern,
                            'severity': self._assign_severity(pattern)
                        }
                        alerts.append(alert)
        
        return alerts
    
    # Detect impossible travel/login from different locations
    def geo_anomaly_detection(self, logs, user):
        # Implement time-distance calculation
        pass