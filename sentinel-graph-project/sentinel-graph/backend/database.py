"""SQLite persistence. JSON payloads preserve complete, immutable incident evidence."""
import json, sqlite3, threading
from backend.config import ROOT, CATALOG
class Database:
    def __init__(self, path=None):
        self.path = str(path or ROOT / 'data/sentinel.db')
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')
        for table in ['users','hosts','services','events','alerts','defense_actions','attack_sessions','graph_edges','reports']:
            self.conn.execute(f'CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, timestamp TEXT, payload TEXT NOT NULL)')
        for table in ['users','hosts','services']:
            for value in CATALOG[table]: self.put(table, value['id'], value)
        self.conn.commit()
    def put(self, table, key, data):
        assert table in ['users','hosts','services','events','alerts','defense_actions','attack_sessions','graph_edges','reports']
        with self.lock:
            self.conn.execute(f'INSERT OR REPLACE INTO {table} VALUES (?,?,?)', (key,data.get('timestamp',''),json.dumps(data)))
            self.conn.commit()
    def all(self, table):
        assert table in ['events','alerts','defense_actions','attack_sessions','reports','graph_edges']
        with self.lock: return [json.loads(r[0]) for r in self.conn.execute(f'SELECT payload FROM {table} ORDER BY timestamp DESC')]
