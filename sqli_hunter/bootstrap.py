import json
import yaml
from pathlib import Path
from typing import Any, Dict

CONFIG_DIR = Path(__file__).parent / 'config'

_loaded_configs: Dict[str, Any] = {}


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
