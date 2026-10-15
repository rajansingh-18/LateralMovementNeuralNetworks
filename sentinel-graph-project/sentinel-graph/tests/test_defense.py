from backend.defense.response_engine import blank_controls,apply,blocked
from backend.simulation.event_generator import event
from backend.simulation.network import build_graph
def test_controls_reject_followup():
    c=blank_controls();e=event();assert blocked(c,e) is None
    apply(c,'HOST_ISOLATION','SERVER-01');assert blocked(c,e)=='Host isolated'
    c=blank_controls();apply(c,'ACCOUNT_LOCK','employee01');assert blocked(c,e)=='Account locked'
def test_heterogeneous_graph_evidence():
    g=build_graph([event()],blank_controls())
    assert {'User','Host','IP','Process','Service'}<=set(n['node_type'] for n in g['nodes'])
    assert {'CONNECTS_TO','USES_SERVICE','STARTS_PROCESS','ASSIGNED_TO'}<=set(e['type'] for e in g['edges'])
