# backend/metrics.py
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from flask import Response
import time

# Counters: label by route (normal/honeypot) and action
HP_REQUESTS = Counter("honeypot_requests_total", "Total honeypot simulate_traffic requests", ['route', 'action'])
HP_LATENCY = Histogram("honeypot_request_latency_seconds", "Latency for simulate_traffic requests")

def observe_request(route_label, action_label, elapsed):
    try:
        HP_REQUESTS.labels(route_label, action_label).inc()
        HP_LATENCY.observe(elapsed)
    except Exception:
        # metrics must not crash service
        pass

def metrics_response():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
