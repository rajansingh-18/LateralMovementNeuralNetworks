from backend.detection.risk_engine import score
from backend.detection.feature_engineering import features,graph_inputs
from backend.simulation.attack_simulator import attack_events
from backend.config import SCENARIOS
from generate_dataset import generate
def test_risk_weighted_formula():
    f={'new_relationships':2,'failed_logins':8,'connection_frequency':.5,'hop_count':2,'privilege_anomaly':0,'off_hours':0,'destination_criticality':4}
    risk,sev,parts,method=score(f,True,.5)
    assert risk==80 and sev=='CRITICAL' and sum(parts.values())==80
def test_features_are_label_free_and_causal():
    ev=attack_events('brute-force');a=features(ev[:4]);b=features(ev[:8])
    assert a['failed_logins']==4 and b['failed_logins']==8
    assert not any(k in a for k in ['is_attack','label','scenario'])
    x,g=graph_inputs(ev);assert x.shape==(5,8) and g.shape==(5,5)
def test_dataset_reproducible_labels_separate():
    rows=generate(42,30,3)
    assert len(rows)==45
    assert len({e['id'] for e in rows})==45
    assert rows==sorted(rows,key=lambda e:e['events'][0]['timestamp'])
    assert all('label' not in event and 'scenario' not in event for episode in rows for event in episode['events'])
