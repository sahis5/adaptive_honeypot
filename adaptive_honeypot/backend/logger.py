# backend/logger.py
import json
import time
import os

LOGFILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'honeypot_events.jsonl')

def ensure_logfile():
    d = os.path.dirname(LOGFILE)
    if not os.path.exists(d):
        os.makedirs(d)
    if not os.path.exists(LOGFILE):
        open(LOGFILE, 'a').close()

def log_event(ev: dict):
    ensure_logfile()
    ev = ev.copy()
    if 'ts' not in ev:
        ev['ts'] = time.time()
    with open(LOGFILE, 'a') as f:
        f.write(json.dumps(ev) + '\n')

def read_last(n=200):
    ensure_logfile()
    with open(LOGFILE, 'r') as f:
        lines = f.read().strip().splitlines()[-n:]
    rows = []
    for l in lines:
        try:
            rows.append(json.loads(l))
        except:
            pass
    return rows
