"""Local FastAPI service. Only loopback binding is used by the launch scripts."""
import asyncio,json,threading
from fastapi import FastAPI,HTTPException,WebSocket,WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
from backend.config import ROOT,CATALOG,SCENARIOS,HOSTS,USERS,SERVICES
from backend.engine import Engine
from backend.defense.response_engine import apply
app=FastAPI(title='Sentinel Graph simulation API',version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://127.0.0.1:5173','http://localhost:5173','http://127.0.0.1:8000','http://localhost:8000'],allow_methods=['GET','POST'],allow_headers=['Content-Type'])
engine=Engine();lock=threading.RLock();clients=set()
async def broadcast(data):
    for ws in list(clients):
        try:await ws.send_json(data)
        except Exception:clients.discard(ws)
class RunInput(BaseModel):auto_defense:bool=True
class ControlInput(BaseModel):target:str=Field(min_length=1,max_length=100)
class ReportInput(BaseModel):
    title:str=Field(min_length=1,max_length=120)
    incident_ids:list[str]=Field(min_length=1,max_length=1000)
    notes:str=Field(default='',max_length=4000)
@app.get('/api/health')
def health():return {'ok':True,'simulation':True,'service':'sentinel-graph'}
@app.get('/api/state')
def state():return engine.state()
@app.get('/api/network')
def network():return {**engine.state()['network'],'catalog':CATALOG}
@app.get('/api/attacks')
def attacks():return engine.db.all('attack_sessions')
@app.get('/api/events')
def events():return engine.db.all('events')
@app.get('/api/alerts')
def alerts():return engine.db.all('alerts')
@app.get('/api/metrics')
def metrics():return engine.state()['models']
@app.get('/api/defense/actions')
def defenses():return engine.db.all('defense_actions')
@app.post('/api/attack/{kind}')
async def run(kind:str,body:RunInput):
    if kind not in SCENARIOS:raise HTTPException(404,'Unknown attack scenario')
    with lock:result=engine.run(kind,body.auto_defense)
    for e in result['events']:
        await broadcast({'type':'event','event':e,'attackId':result['id']});await asyncio.sleep(.05)
    await broadcast({'type':'incident','incident':result});return result
@app.post('/api/normal')
async def normal():
    with lock:ev=engine.normal()
    for e in ev:await broadcast({'type':'event','event':e})
    return ev
@app.post('/api/reset')
def reset():
    with lock:engine.reset()
    return engine.state()
@app.post('/api/defense/{action}')
def control(action:str,body:ControlInput):
    mapping={'isolate-host':('HOST_ISOLATION',HOSTS),'block-ip':('IP_BLOCK',HOSTS),'lock-account':('ACCOUNT_LOCK',USERS),'terminate-session':('SESSION_TERMINATION',USERS)}
    if action not in mapping:raise HTTPException(404,'Unknown defense')
    key,allowed=mapping[action]
    if body.target not in allowed:raise HTTPException(400,'Unknown simulated target')
    with lock:apply(engine.controls,key,body.target)
    return {'controls':engine.controls}
@app.get('/api/reports')
def reports():return engine.db.all('reports')
@app.post('/api/reports')
def save_report(body:ReportInput):
    from uuid import uuid4
    from datetime import datetime,timezone
    lookup={a['id']:a for a in engine.db.all('attack_sessions')}
    if any(i not in lookup for i in body.incident_ids):raise HTTPException(400,'An incident no longer exists')
    value={'id':'RPT-'+uuid4().hex[:8].upper(),'title':body.title,'timestamp':datetime.now(timezone.utc).isoformat(),'notes':body.notes,'incidents':[lookup[i] for i in dict.fromkeys(body.incident_ids)]}
    engine.db.put('reports',value['id'],value);return value
@app.websocket('/ws/events')
async def socket(ws:WebSocket):
    await ws.accept();clients.add(ws)
    try:
        while True:await ws.receive_text()
    except WebSocketDisconnect:clients.discard(ws)
if (ROOT/'dist/index.html').exists():app.mount('/',StaticFiles(directory=ROOT/'dist',html=True),name='frontend')
