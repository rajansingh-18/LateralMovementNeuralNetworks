from datetime import datetime, timezone, timedelta
import random
from backend.config import SCENARIOS
from backend.simulation.event_generator import event
def attack_events(kind, seed=None, start=None, variation=False):
    if kind not in SCENARIOS: raise ValueError('Unknown simulation scenario')
    rng=random.Random(seed); start=start or datetime.now(timezone.utc)
    # Demo event time is independent of the laptop clock: other scenarios must not
    # become credential-abuse cases merely because the examiner runs them at night.
    if not variation: start=start.replace(hour=14)
    # Synthetic off-hours timestamp is retained separately from the real run timestamp.
    if kind=='credential-abuse': start=start.replace(hour=2,minute=12)
    out=[]; elapsed=0.; source=rng.choice(['WS-01','WS-02']) if variation else 'WS-01'
    user='employee01' if source=='WS-01' else 'employee02'
    def add(dst,svc='LDAP',success=True,etype='AUTHENTICATES_TO',src=None,priv='USER'):
        nonlocal elapsed
        e=event(src or source,dst,svc,user,success,etype,start+timedelta(seconds=elapsed))
        elapsed+=rng.uniform(1,8) if variation else 2
        e['privilege']=priv;out.append(e)
    if kind=='credential-abuse':
        for dst in ['SERVER-01','DATABASE-01','DATABASE-01']:add(dst)
    elif kind=='brute-force':
        for _ in range(rng.randint(8,14) if variation else 10):add('SERVER-01','SSH',False)
        add('SERVER-01','SSH');add('SERVER-01','SSH')
    elif kind=='lateral-movement':
        add('SERVER-01','RDP',etype='CONNECTS_TO');add('DATABASE-01','SMB',etype='CONNECTS_TO',src='SERVER-01');add('DC-01','SMB',etype='CONNECTS_TO',src='DATABASE-01')
    elif kind=='privilege-escalation':
        add('SERVER-01','HTTP',etype='CONNECTS_TO');add('DC-01',etype='ROLE_CHANGE',priv='ADMIN');add('DC-01',priv='ADMIN')
    else:
        for dst in ['SERVER-01','DATABASE-01','DC-01','SERVER-01']:add(dst,'SMB',False,'CONNECTS_TO')
    return sorted(out,key=lambda e:e['timestamp'])
