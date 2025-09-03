import json
import yaml
from pathlib import Path
from typing import Any, Dict

# Configuration files are now stored in a top-level ``configs`` directory so
# that they can be shared across modules and easily modified without touching
# the package itself.  ``bootstrap`` resolves the path relative to the project
# root to load these YAML/JSON files.
CONFIG_DIR = Path(__file__).resolve().parent.parent / 'configs'

_loaded_configs: Dict[str, Any] = {}


def bootstrap_models() -> list[Any]:
    """Load ML models defined in ``models.yaml`` into memory.

    In the real project this function would deserialize model weights and
    initialise heavy frameworks such as PyTorch or scikit-learn.  The training
    environment used for kata, however, keeps it lightweight and simply returns
    the configuration entries so that callers can verify the bootstrap
    behaviour.
    """

    if "loaded_models" in _loaded_configs:
        return _loaded_configs["loaded_models"]

    models_cfg = load_config("models")
    models = models_cfg.get("models", [])
    _loaded_configs["loaded_models"] = models
    return models


def validate_waf_fingerprints(data: Dict[str, Any]):
    """Validates the structure of the WAF fingerprints file."""
    if not isinstance(data, dict):
        raise ValueError("WAF fingerprints file must be a dictionary.")

    for waf_name, sig in data.items():
        if not isinstance(sig, dict):
            raise ValueError(f"Signature for '{waf_name}' must be a dictionary.")

        allowed_keys = {"headers", "cookies", "body", "ja3", "min_matches", "delay_threshold", "h2_settings"}
        for key in sig:
            if key not in allowed_keys:
                print(f"[Warning] Unknown key '{key}' in signature for '{waf_name}'.")

        if "headers" in sig and not isinstance(sig["headers"], dict):
            raise ValueError(f"headers for '{waf_name}' must be a dictionary.")
        if "cookies" in sig and not isinstance(sig["cookies"], list):
            raise ValueError(f"cookies for '{waf_name}' must be a list.")
        if "body" in sig and not isinstance(sig["body"], list):
            raise ValueError(f"body for '{waf_name}' must be a list.")


def load_config(name: str) -> Dict[str, Any]:
    """Load a YAML or JSON configuration file from the config directory.

    The function caches loaded configurations to avoid repeated disk access.
    """
    if name in _loaded_configs:
        return _loaded_configs[name]

    path_yaml = CONFIG_DIR / f"{name}.yaml"
    path_json = CONFIG_DIR / f"{name}.json"
    data: Dict[str, Any] | None = None
    if path_yaml.exists():
        with open(path_yaml, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    elif path_json.exists():
        with open(path_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = {}

    if name == "waf_fingerprints":
        try:
            validate_waf_fingerprints(data)
        except ValueError as e:
            print(f"[Error] Invalid WAF fingerprint configuration: {e}")
            # Return an empty dict to prevent crashing, but log the error
            data = {}

    _loaded_configs[name] = data
    return data
