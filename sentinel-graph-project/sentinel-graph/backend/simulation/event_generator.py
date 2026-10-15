"""Synthetic data only: no sockets, processes, OS accounts or firewall access."""
from datetime import datetime, timezone, timedelta
import random, uuid
from backend.config import HOSTS, SERVICES
def event(source='WS-01', destination='SERVER-01', service='HTTP', user='employee01', success=True, event_type='CONNECTS_TO', timestamp=None, **extra):
    return dict(event_id='EV-'+uuid.uuid4().hex[:12], timestamp=(timestamp or datetime.now(timezone.utc)).isoformat(), source=source, destination=destination, event_type=event_type, protocol='TCP', port=SERVICES[service]['port'], success=success, user=user, host=source, process='simulated-client', service=service, bytes=1024, session_duration=3.0, login_type='NETWORK', privilege='USER', source_ip=HOSTS[source]['ip'], **extra)
def normal_events(count=6, seed=None, start=None):
    rng=random.Random(seed); start=start or datetime.now(timezone.utc).replace(hour=10)
    patterns=[('WS-01','WS-01','LDAP','employee01','AUTHENTICATES_TO'),('WS-02','WS-02','LDAP','employee02','AUTHENTICATES_TO'),('WS-01','SERVER-01','HTTP','employee01','CONNECTS_TO'),('WS-02','SERVER-01','HTTP','employee02','CONNECTS_TO'),('SERVER-01','DATABASE-01','MYSQL','admin01','ACCESSES_DATABASE'),('WS-01','DC-01','LDAP','admin01','AUTHENTICATES_TO')]
    out=[]
    for i in range(count):
        s,d,v,u,t=rng.choice(patterns); e=event(s,d,v,u,rng.random()>.04,t,start+timedelta(seconds=i*rng.uniform(15,60)))
        e['privilege']='ADMIN' if u=='admin01' else 'USER'; e['bytes']=rng.randint(120,12000);out.append(e)
    return sorted(out,key=lambda e:e['timestamp'])
