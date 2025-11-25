import os
import sys

def resource_path(relative_path: str) -> str:
    base_path = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base_path, relative_path)

def appdata_folder(appname="AdaptiveHoneypot"):
    appdata = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    folder = os.path.join(appdata, appname)
    os.makedirs(folder, exist_ok=True)
    return folder