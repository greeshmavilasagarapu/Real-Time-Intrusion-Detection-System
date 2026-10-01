"""
Live System Log Monitor: Tails system logs in real-time, maintains a rolling
sequence window, and classifies with the trained CNN-LSTM model.
"""

import time
import threading
import os
import re
import subprocess
import numpy as np
import tensorflow as tf


class RollingLogWindow:
    """Maintains a rolling window of recent log lines for CNN-LSTM input."""
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.lines = []
        self.lock = threading.Lock()
    
    def add_line(self, line):
        """Add a log line to the window. Returns the full window."""
        with self.lock:
            self.lines.append(line)
            if len(self.lines) > self.window_size:
                self.lines = self.lines[-self.window_size:]
            return list(self.lines)
    
    def get_window(self):
        """Get current window as a single string."""
        with self.lock:
            return '\n'.join(self.lines)


class LiveLogMonitor:
    def __init__(self, engine, callback=None):
        self.engine = engine
        self.callback = callback
        self.running = False
        self._thread = None
        self.window = RollingLogWindow(window_size=100)
        self.stats = {'lines_processed': 0, 'anomalies_detected': 0, 'errors': 0}
        self._log_sources = self._discover_logs()

    def _discover_logs(self):
        """Find available system log files."""
        sources = []
        candidates = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/kern.log',
            '/var/log/messages',
        ]
        for path in candidates:
            if os.path.exists(path) and os.access(path, os.R_OK):
                sources.append(('file', path))
        
        # Check journalctl
        try:
            subprocess.run(['journalctl', '--version'], capture_output=True, check=True, timeout=2)
            sources.append(('journalctl', 'journalctl'))
        except:
            pass
        
        if not sources:
            print("[LOG MON] No system logs found - will use /dev/null simulation")
        return sources

    def _tail_file(self, filepath):
        """Tail a file, yielding new lines."""
        try:
            with open(filepath, 'r', errors='replace') as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if line:
                        yield line.rstrip('\n')
                    else:
                        time.sleep(0.3)
        except Exception as e:
            print(f"[LOG MON] Error tailing {filepath}: {e}")

    def _tail_journal(self):
        """Tail journalctl."""
        try:
            proc = subprocess.Popen(
                ['journalctl', '-f', '-n', '0', '--no-pager', '-o', 'short'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            while self.running:
                line = proc.stdout.readline()
                if line:
                    yield line.rstrip('\n')
                else:
                    time.sleep(0.3)
            proc.terminate()
        except Exception as e:
            print(f"[LOG MON] journalctl error: {e}")

    def _process_log_line(self, line, source_name):
        """Process a single log line: window it, classify, emit event."""
        if not line or len(line.strip()) < 5:
            return
        
        self.stats['lines_processed'] += 1
        window_text = self.window.add_line(line)
        
        # Classify using CNN-LSTM on the rolling window
        try:
            label, confidence, explanation = self.engine.predict_log(window_text)
            if label is None:
                return
        except Exception as e:
            self.stats['errors'] += 1
            return
        
        is_anomaly = label == 'Anomaly'
        if is_anomaly:
            self.stats['anomalies_detected'] += 1
        
        # Extract source IP if present
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        source_ip = ip_match.group(1) if ip_match else 'localhost'
        
        severity = 'High' if is_anomaly else 'Normal'
        
        event = {
            'source': 'Live System Log',
            'attack_type': 'Log Anomaly' if is_anomaly else 'Normal Log',
            'confidence': round(confidence, 4),
            'severity': severity,
            'host': source_ip,
            'explanation': {
                'lime': explanation,
                'log_line': line[:300],
                'window_size': len(window_text.split('\n')),
            },
            'flow_info': {
                'src_ip': source_ip,
                'dst_ip': 'localhost',
                'protocol': 'LOG',
                'packets': 1,
                'bytes': len(line),
                'log_source': source_name,
            },
            'correlation_key': {
                'type': 'log',
                'host': source_ip,
                'attack_type': label,
                'timestamp': time.time(),
            }
        }
        
        if self.callback:
            self.callback(event)

    def _monitor_loop(self):
        """Main monitoring loop for all log sources."""
        print(f"[LOG MON] Monitoring {len(self._log_sources)} sources")
        
        threads = []
        for source_type, source_path in self._log_sources:
            if source_type == 'journalctl':
                def _run():
                    for line in self._tail_journal():
                        if not self.running:
                            break
                        self._process_log_line(line, 'journalctl')
                t = threading.Thread(target=_run, daemon=True)
            else:
                def _run(path=source_path):
                    for line in self._tail_file(path):
                        if not self.running:
                            break
                        self._process_log_line(line, os.path.basename(path))
                t = threading.Thread(target=_run, daemon=True)
            
            threads.append(t)
            t.start()
        
        while self.running:
            time.sleep(1)

    def start(self):
        """Start log monitoring."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[LOG MON] Started")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        print(f"[LOG MON] Stopped. Lines: {self.stats['lines_processed']}, Anomalies: {self.stats['anomalies_detected']}")
