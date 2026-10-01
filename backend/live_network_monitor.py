"""
Live Network Monitor: Captures real packets via Scapy, aggregates into flows,
extracts CICIDS2017 features, and classifies with the trained MLP model.
Requires root/sudo for packet capture.
"""

import time
import threading
import queue
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
from feature_extractor import FlowRecord, extract_features


class LiveNetworkMonitor:
    def __init__(self, engine, callback=None, interface=None, flow_timeout=10):
        self.engine = engine
        self.callback = callback
        self.interface = interface
        self.flow_timeout = flow_timeout
        self.flows = {}  # flow_key -> FlowRecord
        self.lock = threading.Lock()
        self.running = False
        self._sniffer_thread = None
        self._processor_thread = None
        self.stats = {'packets_captured': 0, 'flows_classified': 0, 'errors': 0}

    def _get_flow_key(self, pkt):
        """Extract flow key from packet."""
        if IP not in pkt:
            return None
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        sport = 0
        dport = 0
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        return (src, dst, sport, dport, proto)

    def _packet_handler(self, pkt):
        """Process each captured packet."""
        if not self.running:
            return

        key = self._get_flow_key(pkt)
        if key is None:
            return

        pkt_len = len(pkt)
        now = time.time()
        
        # Determine if this is forward or backward
        is_fwd = True
        tcp_flags = None
        
        if TCP in pkt:
            tcp_flags = int(pkt[TCP].flags)
        
        with self.lock:
            if key not in self.flows:
                self.flows[key] = FlowRecord(key[0], key[1], key[2], key[3], key[4])
            
            self.flows[key].add_packet(pkt_len, is_fwd, now, tcp_flags)
            self.stats['packets_captured'] += 1

    def _process_expired_flows(self):
        """Periodically classify expired flows."""
        while self.running:
            time.sleep(3)
            
            now = time.time()
            expired = []
            
            with self.lock:
                expired_keys = []
                for key, flow in self.flows.items():
                    if now - flow.last_time > self.flow_timeout:
                        expired.append((key, flow))
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.flows[key]
            
            for key, flow in expired:
                # Skip tiny flows (need at least 2 packets)
                if flow.total_packets < 2:
                    continue
                
                try:
                    features = extract_features(flow)
                    label, confidence, shap_dict = self.engine.predict_network(features)
                    
                    if label is None:
                        continue
                    
                    self.stats['flows_classified'] += 1
                    
                    is_attack = label != 'Normal Traffic'
                    severity = 'Critical' if is_attack and confidence > 0.95 else 'High' if is_attack else 'Normal'
                    
                    event = {
                        'source': 'Live Network',
                        'attack_type': label,
                        'confidence': round(confidence, 4),
                        'severity': severity,
                        'host': flow.src_ip,
                        'explanation': {
                            'shap': shap_dict,
                            'lime': (
                                f"Flow from {flow.src_ip}:{flow.sport} to {flow.dst_ip}:{flow.dport} "
                                f"({flow.total_packets} packets, {int(flow.duration*1000)}ms) "
                                f"classified as '{label}' with {confidence:.1%} confidence."
                            )
                        },
                        'flow_info': {
                            'src_ip': flow.src_ip,
                            'dst_ip': flow.dst_ip,
                            'src_port': flow.sport,
                            'dst_port': flow.dport,
                            'protocol': 'TCP' if flow.protocol == 6 else 'UDP' if flow.protocol == 17 else str(flow.protocol),
                            'packets': flow.total_packets,
                            'bytes': sum(flow.fwd_lengths + flow.bwd_lengths),
                            'duration_ms': round(flow.duration * 1000, 2),
                        },
                        'correlation_key': {
                            'type': 'network',
                            'host': flow.src_ip,
                            'attack_type': label,
                            'timestamp': time.time(),
                        }
                    }
                    
                    if self.callback:
                        self.callback(event)
                    
                except Exception as e:
                    self.stats['errors'] += 1
                    print(f"[LIVE NET] Classification error: {e}")

    def _sniff_loop(self):
        """Main packet capture loop."""
        try:
            sniff(
                prn=self._packet_handler,
                iface=self.interface,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except PermissionError:
            print("[LIVE NET] ERROR: Need root/sudo for packet capture!")
            self.running = False
        except Exception as e:
            print(f"[LIVE NET] Sniffer error: {e}")
            self.running = False

    def start(self):
        """Start live network monitoring."""
        if self.running:
            return
        
        self.running = True
        self._processor_thread = threading.Thread(target=self._process_expired_flows, daemon=True)
        self._processor_thread.start()
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniffer_thread.start()
        print(f"[LIVE NET] Monitoring on interface: {self.interface or 'default'}")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        print(f"[LIVE NET] Stopped. Captured: {self.stats['packets_captured']}, Classified: {self.stats['flows_classified']}")
