"""
Incident Store: SQLite database for historical incident storage and retrieval.
Provides KNN-style similarity search using cosine similarity on incident features.
"""

import sqlite3
import os
import time
import json
import numpy as np
from datetime import datetime


DB_PATH = os.path.join(os.path.dirname(__file__), 'incidents.db')


class IncidentStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                datetime TEXT,
                source TEXT,
                attack_type TEXT,
                confidence REAL,
                severity TEXT,
                host TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                packets INTEGER,
                bytes INTEGER,
                shap_data TEXT,
                lime_data TEXT,
                correlation_summary TEXT,
                correlation_count INTEGER,
                feature_vector TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_features (
                incident_id INTEGER,
                feature_name TEXT,
                feature_value REAL,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        ''')
        conn.commit()
        conn.close()
        print(f"[STORE] Database initialized: {self.db_path}")

    def store_incident(self, event, correlation=None):
        """Store an incident in the database. Returns incident ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        flow_info = event.get('flow_info', {})
        explanation = event.get('explanation', {})
        
        # Build feature vector for similarity search
        feature_vector = self._build_feature_vector(event)
        
        cursor.execute('''
            INSERT INTO incidents 
            (timestamp, datetime, source, attack_type, confidence, severity,
             host, src_ip, dst_ip, dst_port, protocol, packets, bytes,
             shap_data, lime_data, correlation_summary, correlation_count, feature_vector)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            time.time(),
            datetime.now().isoformat(),
            event.get('source', ''),
            event.get('attack_type', ''),
            event.get('confidence', 0),
            event.get('severity', ''),
            event.get('host', ''),
            flow_info.get('src_ip', ''),
            flow_info.get('dst_ip', ''),
            flow_info.get('dst_port', 0),
            flow_info.get('protocol', ''),
            flow_info.get('packets', 0),
            flow_info.get('bytes', 0),
            json.dumps(explanation.get('shap', {})),
            json.dumps(explanation.get('lime', '')),
            correlation.get('summary', '') if correlation else '',
            correlation.get('correlation_count', 0) if correlation else 0,
            json.dumps(feature_vector),
        ))
        
        incident_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return incident_id

    def _build_feature_vector(self, event):
        """Build a feature vector for similarity search."""
        flow_info = event.get('flow_info', {})
        return {
            'confidence': event.get('confidence', 0),
            'packets': flow_info.get('packets', 0),
            'bytes': flow_info.get('bytes', 0),
            'dst_port': flow_info.get('dst_port', 0),
        }

    def find_similar_incidents(self, event, top_k=3):
        """Find similar past incidents using cosine similarity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get current event features
        current = self._build_feature_vector(event)
        current_vec = np.array([
            current['confidence'],
            current['packets'] / 1000.0,
            current['bytes'] / 10000.0,
            current['dst_port'] / 65535.0,
        ])
        
        # Get all past incidents
        cursor.execute('''
            SELECT id, datetime, attack_type, confidence, severity, 
                   src_ip, dst_ip, dst_port, packets, bytes, feature_vector
            FROM incidents
            WHERE attack_type != 'Normal' AND attack_type != 'Normal Log'
            ORDER BY timestamp DESC
            LIMIT 100
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return []
        
        # Calculate cosine similarity
        similarities = []
        for row in rows:
            feat_json = json.loads(row[10]) if row[10] else {}
            past_vec = np.array([
                feat_json.get('confidence', 0),
                feat_json.get('packets', 0) / 1000.0,
                feat_json.get('bytes', 0) / 10000.0,
                feat_json.get('dst_port', 0) / 65535.0,
            ])
            
            # Cosine similarity
            dot = np.dot(current_vec, past_vec)
            norm = np.linalg.norm(current_vec) * np.linalg.norm(past_vec)
            similarity = dot / norm if norm > 0 else 0
            
            # Boost if same attack type
            if row[2] == event.get('attack_type', ''):
                similarity += 0.3
            
            similarities.append((similarity, row))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[0], reverse=True)
        
        results = []
        for sim, row in similarities[:top_k]:
            results.append({
                'similarity': round(sim, 3),
                'incident_id': row[0],
                'datetime': row[1],
                'attack_type': row[2],
                'confidence': row[3],
                'severity': row[4],
                'src_ip': row[5],
                'dst_ip': row[6],
                'dst_port': row[7],
            })
        
        return results

    def get_incident_count(self):
        """Get total number of stored incidents."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE attack_type NOT LIKE 'Normal%'")
        count = cursor.fetchone()[0]
        conn.close()
        return count
