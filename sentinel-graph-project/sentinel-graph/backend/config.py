import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / 'data/catalog.json').read_text())
HOSTS = {h['id']: h for h in CATALOG['hosts']}
USERS = {u['id']: u for u in CATALOG['users']}
SERVICES = {s['id']: s for s in CATALOG['services']}
SCENARIOS = {s['id']: s for s in CATALOG['scenarios']}
MODEL_DIR = ROOT / 'models'
