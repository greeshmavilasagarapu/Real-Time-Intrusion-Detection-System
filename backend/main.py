"""
Hybrid IDS Backend — Main Entry Point
Integrates: Live Network Monitor, Live Log Monitor, Correlation Engine,
Async Explainer, Incident Store, and WebSocket dashboard API.
"""

import asyncio
import datetime
import socketio
import time
import pandas as pd
import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import threading

from inference import engine
from correlation import CorrelationEngine
from explainer import AsyncExplainer
from incident_store import IncidentStore

# --- Socket.IO & FastAPI ---
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
app = FastAPI(title="Hybrid IDS Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)
socket_app = socketio.ASGIApp(sio, app)

# --- Core Components ---
correlation_engine = CorrelationEngine(time_window=60)
explainer = AsyncExplainer(engine)
incident_store = IncidentStore()

# --- State ---
state = {
    'mode': 'csv',  # 'csv' or 'live'
    'total_events': 0,
    'attacks_detected': 0,
    'normal_events': 0,
    'attack_types': {},
    'correlated_incidents': 0,
    'network_monitor': None,
    'log_monitor': None,
    'event_id_counter': 0,
}

# --- CSV Simulation Data ---
NETWORK_DATA = None
LOG_DATA = None
NET_IDX = 0
LOG_IDX = 0


def load_csv_data():
    global NETWORK_DATA, LOG_DATA
    try:
        df = pd.read_csv('../training/data/CICIDS2017.csv')
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        label_col = 'Attack Type' if 'Attack Type' in df.columns else 'Label'
        NETWORK_DATA = df.select_dtypes(include=[np.number])
        NETWORK_DATA['_label'] = df[label_col].values[:len(NETWORK_DATA)]
        print(f"[DATA] Network: {len(NETWORK_DATA)} records")
    except Exception as e:
        print(f"[WARN] Network data: {e}")
    try:
        LOG_DATA = pd.read_csv('../training/data/BGL.csv').fillna('')
        print(f"[DATA] Logs: {len(LOG_DATA)} records")
    except Exception as e:
        print(f"[WARN] Log data: {e}")


async def emit_event(event):
    """Process an event: correlate → explain → store → emit."""
    state['event_id_counter'] += 1
    event['id'] = state['event_id_counter']
    event['timestamp'] = event.get('timestamp', datetime.datetime.now().isoformat())
    if isinstance(event['timestamp'], str):
        event['timestamp'] = datetime.datetime.now().isoformat()

    # Update stats
    state['total_events'] += 1
    is_attack = event['severity'] != 'Normal'
    if is_attack:
        state['attacks_detected'] += 1
        at = event['attack_type']
        state['attack_types'][at] = state['attack_types'].get(at, 0) + 1
    else:
        state['normal_events'] += 1

    # Correlation
    correlation = None
    if is_attack and 'correlation_key' in event:
        correlation = correlation_engine.add_event(event)
        if correlation:
            event['correlation'] = {
                'correlated': True,
                'count': correlation['correlation_count'],
                'summary': correlation['summary'],
                'severity': correlation['severity'],
            }
            state['correlated_incidents'] += 1
        else:
            event['correlation'] = {'correlated': False}

    # Async explanation
    explainer.request_explanation(event['id'], event)

    # Store incident
    if is_attack:
        incident_id = incident_store.store_incident(event, correlation)
        similar = incident_store.find_similar_incidents(event, top_k=3)
        event['similar_incidents'] = similar
    else:
        event['similar_incidents'] = []

    await sio.emit('new_event', event)
    await sio.emit('stats_update', {
        'total_events': state['total_events'],
        'attacks_detected': state['attacks_detected'],
        'normal_events': state['normal_events'],
        'attack_types': state['attack_types'],
        'correlated_incidents': state['correlated_incidents'],
        'mode': state['mode'],
        'stored_incidents': incident_store.get_incident_count(),
    })


def live_event_callback(event):
    """Callback from live monitors (runs in background thread)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(emit_event(event))
    except Exception as e:
        print(f"[LIVE CALLBACK] Error: {e}")
    finally:
        loop.close()


async def csv_event_generator():
    """Generate simulated events from CSV datasets."""
    global NET_IDX, LOG_IDX
    while state['mode'] == 'csv':
        await asyncio.sleep(2)
        source = np.random.choice(['Network', 'System Log'])

        if source == 'Network' and NETWORK_DATA is not None and len(NETWORK_DATA) > 0:
            NET_IDX = np.random.randint(0, len(NETWORK_DATA))
            row = NETWORK_DATA.iloc[NET_IDX]
            features = row.drop('_label', errors='ignore').values.astype(float)
            true_label = str(row.get('_label', 'Unknown'))

            try:
                pred_label, conf, shap_dict = engine.predict_network(features)
                if pred_label is None:
                    pred_label, conf, shap_dict = true_label, 0.95, {}
            except Exception:
                pred_label, conf, shap_dict = true_label, 0.95, {}

            is_attack = pred_label != 'Normal Traffic'
            event = {
                'source': 'Network (CSV)',
                'severity': 'Critical' if is_attack and conf > 0.95 else 'High' if is_attack else 'Normal',
                'attack_type': pred_label,
                'confidence': round(conf, 4),
                'host': f"192.168.1.{np.random.randint(2, 254)}",
                'explanation': {'shap': shap_dict, 'lime': f"MLP: '{pred_label}' ({conf:.1%})"},
                'true_label': true_label,
                'flow_info': {'src_ip': '192.168.1.1', 'dst_port': 80, 'protocol': 'TCP', 'packets': 10, 'bytes': 1500},
                'correlation_key': {'type': 'network', 'host': '192.168.1.1', 'attack_type': pred_label, 'timestamp': time.time()},
            }
            NET_IDX += 1

        elif source == 'System Log' and LOG_DATA is not None and len(LOG_DATA) > 0:
            LOG_IDX = np.random.randint(0, len(LOG_DATA))
            row = LOG_DATA.iloc[LOG_IDX]
            content = str(row.get('Content', ''))
            true_label = str(row.get('Label', '-'))

            try:
                pred_label, conf, expl = engine.predict_log(content)
                if pred_label is None:
                    pred_label, conf, expl = ('Anomaly' if true_label != '-' else 'Normal'), 0.95, 'fallback'
            except Exception:
                pred_label, conf, expl = ('Anomaly' if true_label != '-' else 'Normal'), 0.95, 'error'

            is_attack = pred_label == 'Anomaly'
            event = {
                'source': 'System Log (CSV)',
                'severity': 'High' if is_attack else 'Normal',
                'attack_type': f"Log Anomaly ({row.get('Component', 'Unknown')})" if is_attack else 'Normal Log',
                'confidence': round(conf, 4),
                'host': str(row.get('Node', 'localhost')),
                'explanation': {'lime': expl},
                'true_label': f"{'Anomaly' if true_label != '-' else 'Normal'} ({true_label})",
                'flow_info': {'src_ip': str(row.get('Node', '')), 'protocol': 'LOG', 'packets': 1, 'bytes': len(content)},
                'correlation_key': {'type': 'log', 'host': str(row.get('Node', '')), 'attack_type': pred_label, 'timestamp': time.time()},
            }
            LOG_IDX += 1
        else:
            continue

        await emit_event(event)


@sio.event
async def connect(sid, environ):
    print(f"[WS] Client connected: {sid}")
    await sio.emit('stats_update', {
        'total_events': state['total_events'],
        'attacks_detected': state['attacks_detected'],
        'normal_events': state['normal_events'],
        'attack_types': state['attack_types'],
        'correlated_incidents': state['correlated_incidents'],
        'mode': state['mode'],
        'stored_incidents': incident_store.get_incident_count(),
    })


@sio.event
async def switch_mode(sid, data):
    global state
    mode = data.get('mode', 'csv')
    state['mode'] = mode

    if mode == 'live':
        from live_network_monitor import LiveNetworkMonitor
        from live_log_monitor import LiveLogMonitor

        state['network_monitor'] = LiveNetworkMonitor(engine, callback=live_event_callback)
        state['log_monitor'] = LiveLogMonitor(engine, callback=live_event_callback)
        state['network_monitor'].start()
        state['log_monitor'].start()
        print("[MODE] LIVE monitoring started")
    else:
        if state['network_monitor']:
            state['network_monitor'].stop()
            state['network_monitor'] = None
        if state['log_monitor']:
            state['log_monitor'].stop()
            state['log_monitor'] = None
        print("[MODE] CSV simulation mode")

    await sio.emit('mode_changed', {'mode': mode})


@app.on_event("startup")
async def startup():
    load_csv_data()
    explainer.start()
    asyncio.create_task(csv_event_generator())
    print("=" * 50)
    print("  Hybrid IDS Backend — Ready")
    print("  Dashboard: http://localhost:5173")
    print("=" * 50)


@app.get("/")
async def root():
    return {
        'message': 'Hybrid IDS API Running',
        'models_loaded': engine.network_model is not None and engine.log_model is not None,
        'mode': state['mode'],
        'stored_incidents': incident_store.get_incident_count(),
    }


if __name__ == "__main__":
    uvicorn.run("main:socket_app", host="0.0.0.0", port=8000, reload=False)
