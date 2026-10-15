from fastapi.testclient import TestClient
from backend.database import Database
from backend.engine import Engine
import backend.main as main
def test_api_persistence_errors_and_reports(tmp_path,monkeypatch):
    db=Database(tmp_path/'test.db');monkeypatch.setattr(main,'engine',Engine(db))
    with TestClient(main.app) as c:
        assert c.get('/api/health').json()['simulation']
        assert c.get('/api/attacks').json()==[]
        assert c.post('/api/attack/invalid',json={}).status_code==404
        assert c.post('/api/defense/isolate-host',json={'target':'bad'}).status_code==400
        assert c.post('/api/reports',json={'title':'Empty','incident_ids':[]}).status_code==422
        r=c.post('/api/attack/lateral-movement',json={'auto_defense':True});assert r.status_code==200
        incident=r.json();report=c.post('/api/reports',json={'title':'Evidence','incident_ids':[incident['id']],'notes':'Reviewed'}).json()
        assert report['incidents'][0]['id']==incident['id']
        c.post('/api/reset',json={});assert len(c.get('/api/attacks').json())==1
        assert c.get('/api/reports').json()[0]['notes']=='Reviewed'
    assert len(Database(tmp_path/'test.db').all('reports'))==1
