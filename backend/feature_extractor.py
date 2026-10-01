"""
Feature Extractor: Converts live network flows into 52 CICIDS2017-compatible features.
Feature order MUST match network_scaler.feature_names_in_ (the trained model's expected input).
"""

import numpy as np
import time


# The 52 feature names from the trained model (confirmed via scaler inspection)
CICIDS_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'Average Packet Size', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Max', 'Idle Min',
]


class FlowRecord:
    """Accumulates packets belonging to a single network flow."""
    
    def __init__(self, src_ip, dst_ip, sport, dport, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_time = self.start_time
        
        # Packet tracking
        self.fwd_lengths = []
        self.bwd_lengths = []
        self.fwd_iat = []  # inter-arrival times forward
        self.bwd_iat = []  # inter-arrival times backward
        self.all_iat = []
        
        self.last_fwd_time = None
        self.last_bwd_time = None
        
        # Flags
        self.fin_count = 0
        self.psh_count = 0
        self.ack_count = 0
        
        # Direction tracking (first packet determines direction)
        self.direction = None  # 'fwd' or 'bwd'
        
        # Active/Idle tracking
        self.active_periods = []
        self.idle_periods = []
        self.last_active_start = None
        self.last_activity_time = self.start_time

    def add_packet(self, pkt_len, is_forward, timestamp, tcp_flags=None):
        """Add a packet to this flow record."""
        now = timestamp
        
        if self.direction is None:
            self.direction = 'fwd' if is_forward else 'bwd'
        
        actual_fwd = (self.direction == 'fwd') == is_forward
        
        # Track packet lengths
        if actual_fwd:
            if self.last_fwd_time is not None:
                self.fwd_iat.append(now - self.last_fwd_time)
            self.last_fwd_time = now
            self.fwd_lengths.append(pkt_len)
        else:
            if self.last_bwd_time is not None:
                self.bwd_iat.append(now - self.last_bwd_time)
            self.last_bwd_time = now
            self.bwd_lengths.append(pkt_len)
        
        # Track all IAT
        if self.all_iat:
            self.all_iat.append(now - self.last_time)
        
        # Track active/idle periods
        gap = now - self.last_activity_time
        if gap > 1.0:  # >1s gap = idle period
            if self.active_periods:
                self.active_periods.append(now - self.last_active_start)
            self.idle_periods.append(gap)
            self.last_active_start = now
        elif self.last_active_start is None:
            self.last_active_start = now
        
        self.last_activity_time = now
        self.last_time = now
        
        # Track TCP flags
        if tcp_flags:
            if tcp_flags & 0x01: self.fin_count += 1
            if tcp_flags & 0x08: self.psh_count += 1
            if tcp_flags & 0x10: self.ack_count += 1

    @property
    def total_fwd_packets(self):
        return len(self.fwd_lengths)

    @property
    def total_bwd_packets(self):
        return len(self.bwd_lengths)

    @property
    def total_packets(self):
        return self.total_fwd_packets + self.total_bwd_packets

    @property
    def duration(self):
        return max(self.last_time - self.start_time, 0.000001)


def safe_stats(values):
    """Return (min, max, mean, std) safely handling empty lists."""
    if not values:
        return 0, 0, 0, 0
    return min(values), max(values), np.mean(values), (np.std(values) if len(values) > 1 else 0)


def extract_features(flow: FlowRecord) -> np.ndarray:
    """
    Extract 52 CICIDS2017 features from a FlowRecord.
    Returns numpy array of shape (52,) in the EXACT order expected by the trained model.
    """
    duration = flow.duration
    total_fwd = flow.total_fwd_packets
    total_bwd = flow.total_bwd_packets
    total_pkts = total_fwd + total_bwd
    
    fwd_min, fwd_max, fwd_mean, fwd_std = safe_stats(flow.fwd_lengths)
    bwd_min, bwd_max, bwd_mean, bwd_std = safe_stats(flow.bwd_lengths)
    all_lengths = flow.fwd_lengths + flow.bwd_lengths
    pkt_min, pkt_max, pkt_mean, pkt_std = safe_stats(all_lengths)
    pkt_var = np.var(all_lengths) if len(all_lengths) > 1 else 0
    
    fwd_iat_total = sum(flow.fwd_iat) if flow.fwd_iat else 0
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = (
        np.mean(flow.fwd_iat), np.std(flow.fwd_iat) if len(flow.fwd_iat) > 1 else 0,
        max(flow.fwd_iat) if flow.fwd_iat else 0, min(flow.fwd_iat) if flow.fwd_iat else 0
    ) if flow.fwd_iat else (0, 0, 0, 0)
    
    bwd_iat_total = sum(flow.bwd_iat) if flow.bwd_iat else 0
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = (
        np.mean(flow.bwd_iat), np.std(flow.bwd_iat) if len(flow.bwd_iat) > 1 else 0,
        max(flow.bwd_iat) if flow.bwd_iat else 0, min(flow.bwd_iat) if flow.bwd_iat else 0
    ) if flow.bwd_iat else (0, 0, 0, 0)
    
    flow_iat_total = sum(flow.all_iat) if flow.all_iat else duration
    flow_iat_mean = np.mean(flow.all_iat) if flow.all_iat else duration / max(total_pkts, 1)
    flow_iat_std = np.std(flow.all_iat) if len(flow.all_iat) > 1 else 0
    flow_iat_max = max(flow.all_iat) if flow.all_iat else duration
    flow_iat_min = min(flow.all_iat) if flow.all_iat else 0
    
    active_mean = np.mean(flow.active_periods) if flow.active_periods else 0
    active_max = max(flow.active_periods) if flow.active_periods else 0
    active_min = min(flow.active_periods) if flow.active_periods else 0
    idle_mean = np.mean(flow.idle_periods) if flow.idle_periods else 0
    idle_max = max(flow.idle_periods) if flow.idle_periods else 0
    idle_min = min(flow.idle_periods) if flow.idle_periods else 0
    
    # Header lengths (assume 20 bytes for TCP/UDP, adjust for real captures)
    header_len = 20
    fwd_header = header_len * total_fwd
    bwd_header = header_len * total_bwd
    
    features = np.array([
        float(flow.dport),                          # 0: Destination Port
        duration * 1000,                             # 1: Flow Duration (microseconds→ms approximation)
        float(total_fwd),                            # 2: Total Fwd Packets
        float(sum(flow.fwd_lengths)),                # 3: Total Length of Fwd Packets
        float(fwd_max),                              # 4: Fwd Packet Length Max
        float(fwd_min),                              # 5: Fwd Packet Length Min
        float(fwd_mean),                             # 6: Fwd Packet Length Mean
        float(fwd_std),                              # 7: Fwd Packet Length Std
        float(bwd_max),                              # 8: Bwd Packet Length Max
        float(bwd_min),                              # 9: Bwd Packet Length Min
        float(bwd_mean),                             # 10: Bwd Packet Length Mean
        float(bwd_std),                              # 11: Bwd Packet Length Std
        sum(all_lengths) / duration,                 # 12: Flow Bytes/s
        total_pkts / duration,                       # 13: Flow Packets/s
        float(flow_iat_mean),                        # 14: Flow IAT Mean
        float(flow_iat_std),                         # 15: Flow IAT Std
        float(flow_iat_max),                         # 16: Flow IAT Max
        float(flow_iat_min),                         # 17: Flow IAT Min
        float(fwd_iat_total),                        # 18: Fwd IAT Total
        float(fwd_iat_mean),                         # 19: Fwd IAT Mean
        float(fwd_iat_std),                          # 20: Fwd IAT Std
        float(fwd_iat_max),                          # 21: Fwd IAT Max
        float(fwd_iat_min),                          # 22: Fwd IAT Min
        float(bwd_iat_total),                        # 23: Bwd IAT Total
        float(bwd_iat_mean),                         # 24: Bwd IAT Mean
        float(bwd_iat_std),                          # 25: Bwd IAT Std
        float(bwd_iat_max),                          # 26: Bwd IAT Max
        float(bwd_iat_min),                          # 27: Bwd IAT Min
        float(fwd_header),                           # 28: Fwd Header Length
        float(bwd_header),                           # 29: Bwd Header Length
        total_fwd / duration,                        # 30: Fwd Packets/s
        total_bwd / duration,                        # 31: Bwd Packets/s
        float(pkt_min),                              # 32: Min Packet Length
        float(pkt_max),                              # 33: Max Packet Length
        float(pkt_mean),                             # 34: Packet Length Mean
        float(pkt_std),                              # 35: Packet Length Std
        float(pkt_var),                              # 36: Packet Length Variance
        float(flow.fin_count),                       # 37: FIN Flag Count
        float(flow.psh_count),                       # 38: PSH Flag Count
        float(flow.ack_count),                       # 39: ACK Flag Count
        float(pkt_mean),                             # 40: Average Packet Size
        float(sum(flow.fwd_lengths)),                # 41: Subflow Fwd Bytes
        0.0,                                         # 42: Init_Win_bytes_forward
        0.0,                                         # 43: Init_Win_bytes_backward
        float(total_fwd),                            # 44: act_data_pkt_fwd
        float(fwd_min),                              # 45: min_seg_size_forward
        float(active_mean),                          # 46: Active Mean
        float(active_max),                           # 47: Active Max
        float(active_min),                           # 48: Active Min
        float(idle_mean),                            # 49: Idle Mean
        float(idle_max),                             # 50: Idle Max
        float(idle_min),                             # 51: Idle Min
    ], dtype=np.float32)
    
    return features
