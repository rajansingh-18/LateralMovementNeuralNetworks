"""Causal, trailing 5-minute features. Labels/scenario IDs never enter model inputs."""
from datetime import datetime
import numpy as np
from backend.config import HOSTS, USERS
FEATURE_NAMES=['failed_logins','successful_logins','unique_hosts','new_relationships','seconds_since_previous','connection_frequency','destination_criticality','remote_service_count','hop_count','off_hours','privilege_anomaly','events_last_10_minutes']
NORMAL_PAIRS={('WS-01','SERVER-01','HTTP'),('WS-02','SERVER-01','HTTP'),('SERVER-01','DATABASE-01','MYSQL')}
def novel(e):
    if e['user']=='admin01': return False
    if e['event_type']=='AUTHENTICATES_TO': return e['destination']!=USERS[e['user']]['host']
    return (e['source'],e['destination'],e['service']) not in NORMAL_PAIRS
def features(events):
    if not events: return {k:0. for k in FEATURE_NAMES}
    now=datetime.fromisoformat(events[-1]['timestamp']); user=events[-1]['user']
    history=[e for e in events if e['user']==user and 0 <= (now-datetime.fromisoformat(e['timestamp'])).total_seconds() <= 600 and not e.get('blocked')]
    win=[e for e in history if (now-datetime.fromisoformat(e['timestamp'])).total_seconds()<=300]
    remote=[e for e in win if e['service'] in ['SSH','SMB','RDP'] and e['success']]
    hops=0;previous=None
    for e in remote:
        hops=hops+1 if previous==e['source'] else 1
        previous=e['destination']
    delta=(now-datetime.fromisoformat(win[-2]['timestamp'])).total_seconds() if len(win)>1 else 300
    span=max(1,(now-datetime.fromisoformat(win[0]['timestamp'])).total_seconds()) if win else 1
    return dict(zip(FEATURE_NAMES,[sum(not e['success'] and e['event_type']=='AUTHENTICATES_TO' for e in win),sum(e['success'] for e in win),len(set(e['destination'] for e in win)),sum(novel(e) for e in win),delta,len(win)/span,max([HOSTS[e['destination']]['criticality'] for e in win] or [0]),len(remote),hops,int(now.hour<6 or now.hour>21),int(any(e['privilege']=='ADMIN' and USERS[e['user']]['role']!='ADMIN' for e in win)),len(history)]))
def vector(f): return np.array([f[k] for k in FEATURE_NAMES],dtype=np.float32)
def graph_inputs(events):
    # Host projection of the heterogeneous evidence graph. Exponentially decayed adjacency.
    ids=list(HOSTS);x=np.zeros((len(ids),8),np.float32);a=np.zeros((len(ids),len(ids)),np.float32)
    now=datetime.fromisoformat(events[-1]['timestamp'])
    for i,h in enumerate(ids): x[i,0]=HOSTS[h]['criticality']/4
    for e in events:
        age=(now-datetime.fromisoformat(e['timestamp'])).total_seconds()
        if age<0 or age>300 or e.get('blocked'):continue
        i,j=ids.index(e['source']),ids.index(e['destination']);w=np.exp(-age/120)
        a[j,i]+=w;a[i,j]+=w
        x[j,1]+=int(not e['success'])/10;x[j,2]+=int(novel(e))/5
        x[j,3]+=int(e['service'] in ['RDP','SMB','SSH'])/5;x[j,4]+=int(e['privilege']=='ADMIN' and e['user']!='admin01')
        x[j,5]+=w/5;x[i,6]+=1/5;x[j,7]=int(now.hour<6 or now.hour>21)
    return x,a
