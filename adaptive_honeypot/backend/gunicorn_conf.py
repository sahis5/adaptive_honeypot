# backend/gunicorn_conf.py
import multiprocessing
workers = max(2, multiprocessing.cpu_count() * 2 + 1)
bind = "0.0.0.0:5000"
timeout = 30
accesslog = '-'   # stdout
errorlog = '-'    # stderr
