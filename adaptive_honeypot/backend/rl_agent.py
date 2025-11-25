# backend/rl_agent.py
import os, json, threading
import joblib
from collections import defaultdict
from .model_loader import external_models_dir

_lock = threading.Lock()
Q = defaultdict(lambda: defaultdict(float))  # Q[state][action] = value

# hyperparams
ALPHA = 0.5      # learning rate
GAMMA = 0.9      # discount factor
EPSILON = 0.1    # exploration probability

Q_FILE = os.path.join(external_models_dir(), "q_table.pkl")

def save_q():
    with _lock:
        os.makedirs(os.path.dirname(Q_FILE), exist_ok=True)
        joblib.dump(dict(Q), Q_FILE)

def load_q():
    global Q
    if os.path.exists(Q_FILE):
        try:
            d = joblib.load(Q_FILE)
            Q = defaultdict(lambda: defaultdict(float), {k: defaultdict(float, v) for k, v in d.items()})
        except Exception:
            Q = defaultdict(lambda: defaultdict(float))

# utils
def get_actions():
    return ["redirect_honeypot","serve_fake_data","tarpit_slowdown","challenge_captcha","block","normal"]

def choose_action(state, epsilon=EPSILON):
    import random
    actions = get_actions()
    with _lock:
        # exploration
        if random.random() < epsilon:
            return random.choice(actions)
        # exploitation: choose highest Q
        vals = {a: Q[state].get(a, 0.0) for a in actions}
        best = max(vals.items(), key=lambda x: x[1])[0]
        return best

def update(state, action, reward, next_state):
    with _lock:
        q = Q[state].get(action, 0.0)
        # estimate best next value
        next_vals = Q[next_state] if next_state in Q else {}
        best_next = max(next_vals.values()) if next_vals else 0.0
        Q[state][action] = q + ALPHA * (reward + GAMMA * best_next - q)
    # small autosave
    save_q()

# load on import
load_q()
