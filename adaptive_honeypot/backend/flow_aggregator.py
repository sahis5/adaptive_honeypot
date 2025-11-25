# backend/flow_aggregator.py
import time
from collections import deque, defaultdict

# sliding window size (seconds)
WINDOW_SECONDS = 30

_per_ip = defaultdict(lambda: deque())  # ip -> deque((ts, bytes))

def add_event(src_ip: str, payload: str):
    ts = time.time()
    size = len(payload) if payload else 0
    dq = _per_ip[src_ip]
    dq.append((ts, size))
    # drop old events
    while dq and (ts - dq[0][0]) > WINDOW_SECONDS:
        dq.popleft()

def compute_aggregates(src_ip: str):
    """
    Returns approximated flow-level features aligned with training FEATURES.
    Keys exactly match feature names in feature_order.json
    """
    dq = _per_ip[src_ip]
    n = len(dq)
    if n == 0:
        return {
            "Flow Duration": 0.0,
            "Total Fwd Packets": 0.0,
            "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": 0.0,
            "Total Length of Bwd Packets": 0.0,
            "Fwd Packet Length Mean": 0.0,
            "Bwd Packet Length Mean": 0.0,
            "Flow Bytes/s": 0.0,
            "Flow Packets/s": 0.0,
            "Fwd IAT Mean": 0.0,
            "Bwd IAT Mean": 0.0,
            "Packet Length Mean": 0.0
        }
    times = [t for t,_ in dq]
    sizes = [s for _,s in dq]
    duration = times[-1] - times[0] if len(times) > 1 else 0.0
    total_bytes = sum(sizes)
    pkt_count = n
    flow_bytes_s = total_bytes / duration if duration > 0 else float(total_bytes)
    flow_pkts_s = pkt_count / duration if duration > 0 else float(pkt_count)
    iats = [t2 - t1 for t1,t2 in zip(times[:-1], times[1:])] if len(times) > 1 else [0.0]
    fwd_iat_mean = sum(iats)/len(iats) if len(iats) > 0 else 0.0
    bwd_iat_mean = fwd_iat_mean
    pkt_mean = sum(sizes)/len(sizes) if len(sizes) > 0 else 0.0

    return {
        "Flow Duration": float(duration),
        "Total Fwd Packets": float(pkt_count),
        "Total Backward Packets": float(0.0),
        "Total Length of Fwd Packets": float(total_bytes),
        "Total Length of Bwd Packets": float(0.0),
        "Fwd Packet Length Mean": float(pkt_mean),
        "Bwd Packet Length Mean": float(0.0),
        "Flow Bytes/s": float(flow_bytes_s),
        "Flow Packets/s": float(flow_pkts_s),
        "Fwd IAT Mean": float(fwd_iat_mean),
        "Bwd IAT Mean": float(bwd_iat_mean),
        "Packet Length Mean": float(pkt_mean)
    }
