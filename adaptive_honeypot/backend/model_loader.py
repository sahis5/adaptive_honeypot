import os
import json
import joblib
from .utils import resource_path, appdata_folder

MODELS_DIRNAME = "models"  # external folder under APPDATA/AdaptiveHoneypot/models
DEFAULT_CONFIG_NAME = "config_default.json"


def external_models_dir():
    d = os.path.join(appdata_folder(), MODELS_DIRNAME)
    os.makedirs(d, exist_ok=True)
    return d


def get_model_path(filename: str) -> str:
    """
    Prefer an external model file in %APPDATA%/AdaptiveHoneypot/models,
    else fallback to packaged backend/ml_model/<filename>.
    Returns the full path to the file.
    """
    # external path
    ext = os.path.join(external_models_dir(), filename)
    if os.path.exists(ext):
        return ext
    # fallback to bundled ml_model (development)
    bundled = resource_path(os.path.join("ml_model", filename))
    return bundled


def load_pickle_model(filename: str):
    """
    Convenience: returns joblib.load(get_model_path(filename))
    Raises FileNotFoundError if file not present.
    """
    path = get_model_path(filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found: {path}")
    return joblib.load(path)


def load_config():
    """
    Load config.json from external appdata if present, otherwise fallback to packaged default.
    """
    cfg_path = os.path.join(appdata_folder(), "config.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    default_path = resource_path(DEFAULT_CONFIG_NAME)
    if os.path.exists(default_path):
        with open(default_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}