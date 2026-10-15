import time,uuid
from datetime import datetime,timezone
from backend.config import SCENARIOS
from backend.database import Database
from backend.simulation.attack_simulator import attack_events
from backend.simulation.event_generator import normal_events
from backend.simulation.network import build_graph
from backend.detection.rules import evaluate
from backend.detection.risk_engine import score
from backend.detection.models import Models
from backend.defense.response_engine import blank_controls,actions_for,apply,blocked
def observed_path(events):
    allowed=[e for e in events if not e.get('blocked')]
    if not allowed:return []
    path=[allowed[-1]['source'],allowed[-1]['destination']]
    for e in reversed(allowed[:-1]):
        if e['success'] and e['destination']==path[0] and e['source'] not in path:path.insert(0,e['source'])
    return list(dict.fromkeys(path))
class Engine:
    def __init__(self,db=None):
        self.db=db or Database();self.models=Models();self.controls=blank_controls();self.active_events=[]
        history=self.db.all('attack_sessions')
        if history:self.controls=history[0]['controls'];self.active_events=history[0]['events']
    def run(self,kind,auto_defense=True):
        # A new run is an independent sandbox. Prior incident/report records are immutable.
        self.controls=blank_controls();self.active_events=[]
        rid='LM-'+uuid.uuid4().hex[:8].upper();wall=datetime.now(timezone.utc).isoformat();start=time.perf_counter()
        found=None;reasons=[];peak=0;parts={};method='Rule-based fallback';actions=[];predictions={};severity='LOW';latency=None
        for e in attack_events(kind):
            why=blocked(self.controls,e);e.update(blocked=bool(why),block_reason=why)
            if why:e['success']=False
            self.active_events.append(e)
            if not why:
                detected,f,rs=evaluate(self.active_events);pred=self.models.predict(self.active_events);risk,sev,pt,m=score(f,bool(detected),pred['gnn'])
                if risk>=peak:peak,severity,parts,method,predictions=risk,sev,pt,m,pred
                if detected and not found:
                    found=detected;reasons=rs;latency=round((time.perf_counter()-start)*1000,3)
                    if auto_defense:
                        for action,target in actions_for(detected,e['user'],e['source']):
                            apply(self.controls,action,target);record={'id':'DF-'+uuid.uuid4().hex[:10],'attack_id':rid,'timestamp':datetime.now(timezone.utc).isoformat(),'action':action,'target':target,'status':'APPLIED'};actions.append(record);self.db.put('defense_actions',record['id'],record)
            self.db.put('events',e['event_id'],{**e,'attack_id':rid})
        meta=SCENARIOS[kind];status='BLOCKED' if actions and any(e['blocked'] for e in self.active_events) else 'CONTAINED' if actions else 'DETECTED' if found else 'MISSED'
        result={'id':rid,'timestamp':wall,'scenario':kind,'name':meta['name'],'source':'WS-01','destination':meta['destination'],'user':'employee01','service':meta['service'],'technique':meta['technique'],'techniqueName':meta['techniqueName'],'tactic':meta['tactic'],'techniqueUrl':meta['url'],'risk':peak,'severity':severity,'status':status,'detected':bool(found),'detectedAs':found,'explanations':reasons,'contributions':parts,'method':method,'modelScores':predictions,'events':self.active_events.copy(),'actions':actions,'controls':self.controls.copy(),'latencyMs':latency,'durationMs':round((time.perf_counter()-start)*1000,3),'path':list(dict.fromkeys([self.active_events[0]['source']]+[e['destination'] for e in self.active_events if not e['blocked']])),'simulated':True,'engine':'Python','notes':''}
        result['path']=observed_path(self.active_events)
        self.db.put('attack_sessions',rid,result)
        if found:self.db.put('alerts',rid,result)
        for edge in build_graph(self.active_events,self.controls)['edges']:self.db.put('graph_edges',edge['id'],edge)
        return result
    def normal(self):
        ev=normal_events(6)
        for e in ev:
            why=blocked(self.controls,e);e.update(blocked=bool(why),block_reason=why)
            if why:e['success']=False
            self.db.put('events',e['event_id'],e)
        self.active_events=ev;return ev
    def reset(self):self.controls=blank_controls();self.active_events=[]
    def state(self):return {'history':self.db.all('attack_sessions'),'reports':self.db.all('reports'),'controls':self.controls,'events':self.active_events,'models':{'trained':self.models.gnn is not None,'baselineTrained':self.models.baseline is not None,'metrics':self.models.metrics,'error':self.models.error},'network':build_graph(self.active_events,self.controls)}
