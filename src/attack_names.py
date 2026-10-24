
import json, os
_P = os.path.join(os.path.dirname(__file__), "..", "data", "technique_names.json")
try:
    NAMES = json.load(open(_P, encoding="utf-8"))
except Exception:
    NAMES = {}

def name(tid):
    return NAMES.get(tid) or NAMES.get(tid.split(".")[0]) or tid
