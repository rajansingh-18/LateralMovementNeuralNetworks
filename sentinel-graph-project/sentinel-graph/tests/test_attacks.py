import pytest
from backend.config import SCENARIOS
from backend.engine import Engine,observed_path
from backend.database import Database
from backend.simulation.attack_simulator import attack_events
from backend.simulation.event_generator import normal_events
from backend.detection.rules import evaluate
@pytest.mark.parametrize('kind',list(SCENARIOS))
def test_attacks_detect_contain_and_preserve_evidence(kind):
    e=Engine(Database(':memory:'));r=e.run(kind)
    assert r['detected'] and r['status']=='BLOCKED' and r['detectedAs']==kind
    assert r['explanations'] and r['actions'] and 0<=r['risk']<=100
    assert any(x['blocked'] for x in r['events'])
    assert all(not x['success'] for x in r['events'] if x['blocked'])
    assert len(e.db.all('attack_sessions'))==1
def test_disable_automatic_response():
    r=Engine(Database(':memory:')).run('brute-force',False)
    assert r['status']=='DETECTED' and not r['actions']
    assert not any(e['blocked'] for e in r['events'])
def test_reset_preserves_history():
    e=Engine(Database(':memory:'));e.run('lateral-movement');e.reset()
    assert not e.controls['hosts'] and len(e.db.all('attack_sessions'))==1
def test_path_does_not_invent_hops():
    ev=attack_events('privilege-escalation')
    assert observed_path(ev)==['WS-01','DC-01']
def test_normal_profile_is_benign():
    ev=normal_events(50,seed=51)
    assert len(ev)==50 and evaluate(ev)[0] is None
