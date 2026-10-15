"""Generate reproducible, independent synthetic episodes, with labels stored separately."""
import csv,json,random
from datetime import datetime,timezone,timedelta
from backend.config import ROOT,SCENARIOS
from backend.simulation.event_generator import normal_events
from backend.simulation.attack_simulator import attack_events
def generate(seed=42,normal_count=2200,attack_count=350):
    rng=random.Random(seed);kinds=['benign']*normal_count+[k for k in SCENARIOS for _ in range(attack_count)];rng.shuffle(kinds);episodes=[]
    for i,kind in enumerate(kinds):
        start=datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(hours=i)
        events=normal_events(rng.randint(3,14),seed+i,start.replace(hour=rng.randint(0,23))) if kind=='benign' else attack_events(kind,seed+i,start,variation=True)
        # Include realistic benign administrative remote sessions and occasional benign new destinations.
        if kind=='benign' and rng.random()<.3:
            service=rng.choice(['SSH','RDP'])
            for e in events[-2:]:e.update(user='admin01',privilege='ADMIN',service=service,port=22 if service=='SSH' else 3389)
        # Legitimate exception windows overlap attack behavior, so novelty is not a perfect label proxy.
        if kind=='benign' and rng.random()<.10:
            extra=attack_events(rng.choice(['credential-abuse','lateral-movement']),seed+i,start,variation=True)[:rng.randint(1,2)]
            events=sorted(events+extra,key=lambda e:e['timestamp'])
        if kind!='benign':
            attack_start=datetime.fromisoformat(events[0]['timestamp'])
            background=normal_events(rng.randint(0,6),seed+i,attack_start-timedelta(minutes=8))
            events=sorted(background+events,key=lambda e:e['timestamp'])
            onset=next(k for k,e in enumerate(events) if e not in background)
        else:onset=None
        episodes.append({'id':f'EP-{i:05d}','label':int(kind!='benign'),'scenario':kind,'attack_onset':onset,'events':events})
    return sorted(episodes,key=lambda e:e['events'][0]['timestamp'])
if __name__=='__main__':
    rows=generate();(ROOT/'data/dataset.json').write_text(json.dumps(rows));normal=sum(len(e['events']) for e in rows if not e['label']);attack=sum(len(e['events']) for e in rows if e['label'])
    print(f'Generated {len(rows)} independent episodes; {normal} benign events; {attack} attack events.')
