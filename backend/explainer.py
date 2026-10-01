"""
Async Explainer: Runs SHAP/LIME in background threads to avoid blocking
the real-time monitoring loop.
"""

import time
import threading
from queue import Queue


class AsyncExplainer:
    def __init__(self, engine):
        self.engine = engine
        self.queue = Queue()
        self.results = {}
        self.running = False
        self._thread = None
        self.stats = {'explanations_generated': 0, 'queue_size': 0}

    def start(self):
        """Start the background explanation worker."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        print("[EXPLAINER] Background explanation worker started")

    def stop(self):
        """Stop the worker."""
        self.running = False
        print(f"[EXPLAINER] Stopped. Generated: {self.stats['explanations_generated']}")

    def request_explanation(self, event_id, event_data):
        """Queue an explanation request. Returns immediately."""
        self.queue.put({
            'event_id': event_id,
            'event_data': event_data,
            'timestamp': time.time()
        })
        self.stats['queue_size'] = self.queue.qsize()

    def get_explanation(self, event_id):
        """Get cached explanation for an event."""
        return self.results.get(event_id)

    def _worker(self):
        """Background worker that processes explanation requests."""
        while self.running:
            try:
                request = self.queue.get(timeout=1)
                event_id = request['event_id']
                event_data = request['event_data']
                
                explanation = self._compute_explanation(event_data)
                
                if explanation:
                    self.results[event_id] = explanation
                    self.stats['explanations_generated'] += 1
                    self.stats['queue_size'] = self.queue.qsize()
                
            except Exception:
                continue

    def _compute_explanation(self, event):
        """Compute SHAP/LIME explanation for an event."""
        try:
            source = event.get('source', '')
            
            # Network events already have SHAP from the prediction
            if 'Live Network' in source or 'Network' in source:
                shap_data = event.get('explanation', {}).get('shap', {})
                if shap_data:
                    return {
                        'type': 'SHAP',
                        'data': shap_data,
                        'summary': self._summarize_shap(shap_data)
                    }
            
            # Log events already have LIME from the prediction
            if 'Log' in source:
                lime_data = event.get('explanation', {}).get('lime', '')
                if lime_data:
                    return {
                        'type': 'LIME',
                        'data': lime_data,
                        'summary': lime_data
                    }
            
            return None
            
        except Exception as e:
            print(f"[EXPLAINER] Error: {e}")
            return None

    def _summarize_shap(self, shap_dict):
        """Create a human-readable summary from SHAP values."""
        if not shap_dict:
            return "No SHAP data available"
        
        items = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
        parts = []
        for feature, value in items:
            direction = "increases" if value > 0 else "decreases"
            parts.append(f"{feature} {direction} attack probability by {abs(value):.4f}")
        
        return '; '.join(parts)
