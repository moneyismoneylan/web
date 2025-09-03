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
    _loaded_configs[name] = data
    return data
