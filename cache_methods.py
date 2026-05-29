import json
import os

def load_cache(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    else: return {}

def save_cache(filepath, cache):
    with open(filepath, "w") as f:
        json.dump(cache, f, indent=4)