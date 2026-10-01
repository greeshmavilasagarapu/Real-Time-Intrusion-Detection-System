"""
Hybrid Correlation Engine
Correlates network alerts and system-log alerts that occur within a time window
and share common characteristics (host/IP, attack type compatibility).
"""

import time
from collections import deque


# Define which attack types are commonly correlated
# e.g., Brute Force network traffic often correlates with auth log failures
ATTACK_LOG_CORRELATION = {
    'Brute Force': ['auth', 'Failed password', 'Invalid user', 'authentication'],
    'Port Scanning': ['sshd', 'Connection refused', 'nmap', 'port'],
    'DDoS': ['kernel', 'connection', 'timeout', 'flood'],
    'DoS': ['kernel', 'connection', 'timeout', 'flood'],
    'Web Attacks': ['http', 'apache', 'nginx', '404', '500'],
    'Bots': ['botnet', 'c2', 'malware', 'suspicious'],
    'Normal Traffic': [],
}


class CorrelationEngine:
    """
    Correlates network and log events using:
    1. Time window (events must occur within N seconds)
    2. Host/IP matching (same source IP)
    3. Attack type compatibility (Brute Force + auth failures = correlated)
    """
    
    def __init__(self, time_window=60):
        self.time_window = time_window
        self.recent_events = deque(maxlen=200)  # Keep last 200 events
        self.correlated_incidents = []
        self.stats = {'total_correlated': 0, 'correlation_checks': 0}

    def add_event(self, event):
        """
        Add an event and check for correlations.
        Returns: correlation result dict or None if no correlation found.
        """
        self.recent_events.append(event)
        self.stats['correlation_checks'] += 1
        
        # Only try to correlate attack/anomaly events
        if event['severity'] == 'Normal':
            return None
        
        correlation = self._find_correlation(event)
        
        if correlation:
            self.correlated_incidents.append(correlation)
            self.stats['total_correlated'] += 1
        
        return correlation

    def _find_correlation(self, event):
        """Find correlated events for the given event."""
        current_time = time.time()
        event_type = event['correlation_key']['type']
        event_host = event['correlation_key']['host']
        event_attack = event['correlation_key']['attack_type']
        
        correlated = []
        
        for other in self.recent_events:
            # Skip self
            if other['correlation_key']['type'] == event_type and \
               other['correlation_key']['host'] == event_host and \
               other['correlation_key']['timestamp'] == event['correlation_key']['timestamp']:
                continue
            
            # Check time window
            time_diff = abs(current_time - other['correlation_key']['timestamp'])
            if time_diff > self.time_window:
                continue
            
            # Check host match (same IP)
            host_match = (other['correlation_key']['host'] == event_host)
            
            # Check attack type compatibility
            other_type = other['correlation_key']['type']
            other_attack = other['correlation_key']['attack_type']
            
            # Cross-type correlation (network + log)
            if event_type != other_type:
                if self._is_compatible(event_attack, other_attack):
                    correlated.append({
                        'event': other,
                        'time_diff': round(time_diff, 2),
                        'host_match': host_match,
                        'reason': f"Cross-type: {event_type} '{event_attack}' + {other_type} '{other_attack}' within {time_diff:.1f}s"
                    })
            
            # Same-type correlation (multiple alerts same host)
            elif host_match and other_attack != 'Normal':
                correlated.append({
                    'event': other,
                    'time_diff': round(time_diff, 2),
                    'host_match': True,
                    'reason': f"Same-type repeat: {other_attack} from {event_host} within {time_diff:.1f}s"
                })
        
        if not correlated:
            return None
        
        # Build correlation result
        correlation = {
            'correlated': True,
            'primary_event': event,
            'related_events': correlated,
            'correlation_count': len(correlated),
            'summary': self._build_summary(event, correlated),
            'severity': self._calculate_severity(event, correlated),
            'timestamp': current_time,
        }
        
        return correlation

    def _is_compatible(self, attack_type, other_type):
        """Check if a network attack type is compatible with a log anomaly."""
        # Network attacks correlate with log keywords
        log_keywords = ATTACK_LOG_CORRELATION.get(attack_type, [])
        
        # For log events, check if any keyword matches the attack type
        if other_type and ('Log' in str(other_type) or 'Normal' not in str(other_type)):
            # Network attack + log anomaly from same time = potentially correlated
            return True
        
        return False

    def _build_summary(self, event, correlated):
        """Build a human-readable correlation summary."""
        parts = [f"Primary: {event['attack_type']} from {event['host']} ({event['confidence']:.1%})"]
        
        for c in correlated[:3]:  # Show top 3
            other = c['event']
            parts.append(f"Related: {other['attack_type']} from {other['host']} ({c['time_diff']}s apart)")
        
        return ' | '.join(parts)

    def _calculate_severity(self, event, correlated):
        """Calculate combined severity for correlated incidents."""
        base_severity = event['severity']
        
        # Escalate if multiple correlated events
        if len(correlated) >= 3:
            return 'Critical'
        elif len(correlated) >= 2:
            if base_severity == 'High':
                return 'Critical'
            return 'High'
        
        return base_severity
