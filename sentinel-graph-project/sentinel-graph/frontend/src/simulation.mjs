import catalog from '../../data/catalog.json' with {type:'json'};
export {catalog};
export const uid=(prefix)=>prefix+'-'+(globalThis.crypto?.randomUUID?.()||Math.random().toString(36).slice(2)).slice(0,8).toUpperCase();
export const blankControls=()=>({accounts:[],ips:[],hosts:[],services:[],sessions:[],protected:[],watchlist:[],privileges:[]});
const host=Object.fromEntries(catalog.hosts.map(h=>[h.id,h])),users=Object.fromEntries(catalog.users.map(u=>[u.id,u]));
export const severityOf=n=>n>=80?'CRITICAL':n>=60?'HIGH':n>=30?'MEDIUM':'LOW';
const novelty=e=>e.user!=='admin01'&&(e.event_type==='AUTHENTICATES_TO'?e.destination!==users[e.user].host:!((['WS-01','WS-02'].includes(e.source)&&e.destination==='SERVER-01'&&e.service==='HTTP')||(e.source==='SERVER-01'&&e.destination==='DATABASE-01'&&e.service==='MYSQL')));
export function makeEvent(source,destination,service='LDAP',success=true,type='AUTHENTICATES_TO',index=0,extra={}){
 return {event_id:uid('EV'),timestamp:new Date(Date.now()+index*2000).toISOString(),source,destination,service,success,event_type:type,protocol:'TCP',port:catalog.services.find(s=>s.id===service).port,user:'employee01',host:source,source_ip:host[source].ip,process:'simulated-client',bytes:1024,session_duration:3,login_type:'NETWORK',privilege:'USER',...extra};
}
export function normalEvents(){return [makeEvent('WS-01','WS-01','LDAP',true,'AUTHENTICATES_TO',0),makeEvent('WS-02','WS-02','LDAP',true,'AUTHENTICATES_TO',0,{user:'employee02'}),makeEvent('WS-01','SERVER-01','HTTP',true,'CONNECTS_TO'),makeEvent('SERVER-01','DATABASE-01','MYSQL',true,'ACCESSES_DATABASE',0,{user:'admin01',privilege:'ADMIN'})];}
export function generateAttack(kind){
 const events=[];const add=(d,s='LDAP',ok=true,t='AUTHENTICATES_TO',src='WS-01',p='USER')=>events.push(makeEvent(src,d,s,ok,t,events.length,{privilege:p}));
 if(kind==='credential-abuse'){['SERVER-01','DATABASE-01','DATABASE-01'].forEach(d=>add(d));events.forEach(e=>{const d=new Date(e.timestamp);d.setUTCHours(2,12);e.timestamp=d.toISOString();});}
 else if(kind==='brute-force'){for(let i=0;i<10;i++)add('SERVER-01','SSH',false);add('SERVER-01','SSH');add('SERVER-01','SSH');}
 else if(kind==='lateral-movement'){add('SERVER-01','RDP',true,'CONNECTS_TO');add('DATABASE-01','SMB',true,'CONNECTS_TO','SERVER-01');add('DC-01','SMB',true,'CONNECTS_TO','DATABASE-01');}
 else if(kind==='privilege-escalation'){add('SERVER-01','HTTP',true,'CONNECTS_TO');add('DC-01','LDAP',true,'ROLE_CHANGE','WS-01','ADMIN');add('DC-01','LDAP',true,'AUTHENTICATES_TO','WS-01','ADMIN');}
 else if(kind==='reconnaissance'){['SERVER-01','DATABASE-01','DC-01','SERVER-01'].forEach(d=>add(d,'SMB',false,'CONNECTS_TO'));}
 else throw new Error('Unknown scenario');
 if(kind!=='credential-abuse')events.forEach(e=>{const d=new Date(e.timestamp);d.setUTCHours(14);e.timestamp=d.toISOString();});
 return events;
}
export function extractFeatures(events){
 const last=events.at(-1),now=Date.parse(last.timestamp);const w=events.filter(e=>e.user===last.user&&!e.blocked&&now-Date.parse(e.timestamp)>=0&&now-Date.parse(e.timestamp)<=300000);let hops=0,prev=null;
 w.filter(e=>['SSH','SMB','RDP'].includes(e.service)&&e.success).forEach(e=>{hops=prev===e.source?hops+1:1;prev=e.destination;});
 return {failed_logins:w.filter(e=>!e.success&&e.event_type==='AUTHENTICATES_TO').length,successful_logins:w.filter(e=>e.success).length,unique_hosts:new Set(w.map(e=>e.destination)).size,new_relationships:w.filter(novelty).length,connection_frequency:w.length/Math.max(1,(now-Date.parse(w[0]?.timestamp||last.timestamp))/1000),destination_criticality:Math.max(0,...w.map(e=>host[e.destination].criticality)),remote_service_count:w.filter(e=>['SSH','SMB','RDP'].includes(e.service)&&e.success).length,hop_count:hops,off_hours:new Date(now).getUTCHours()<6||new Date(now).getUTCHours()>21,privilege_anomaly:w.some(e=>e.privilege==='ADMIN'&&users[e.user].role!=='ADMIN')};
}
export function detect(events){
 const f=extractFeatures(events);let kind=null,reasons=[];
 if(f.privilege_anomaly){kind='privilege-escalation';reasons.push('Employee privilege changed to ADMIN without an authorized role.');}
 else if(f.failed_logins>=8){kind='brute-force';reasons.push(`${f.failed_logins} failed sign-ins occurred inside a five-minute window.`);}
 else if(f.hop_count>=2&&f.new_relationships>=2){kind='lateral-movement';reasons.push(`${f.hop_count} remote-service hops formed a temporal path across hosts.`);}
 else if(f.unique_hosts>=3&&f.connection_frequency>.1&&f.new_relationships>=3){kind='reconnaissance';reasons.push('Rapid connections contacted at least three unfamiliar destinations.');}
 else if(f.new_relationships&&f.off_hours){kind='credential-abuse';reasons.push('An employee accessed a new destination outside normal working hours.');}
 if(kind&&f.destination_criticality>=3)reasons.push('A high-value database or identity host was targeted.');
 if(kind&&f.new_relationships)reasons.push(`${f.new_relationships} events differ from the normal access profile.`);
 if(kind&&f.remote_service_count)reasons.push('Remote service activity appeared in the trailing event window.');
 const novel=Math.min(1,f.new_relationships/2),burst=Math.min(1,Math.max(f.failed_logins/8,f.connection_frequency/.5)),path=Math.min(1,f.hop_count/2);
 const rule=Math.min(1,.35*novel+.3*burst+.35*path+.6*f.privilege_anomaly+.4*f.off_hours);
 const contributions={'Behavioral rules':45*Math.max(rule,kind ? .8 : 0),'Novel relationships':20*novel,'Temporal burst':15*burst,'Graph path':10*path,'Critical destination':10*f.destination_criticality/4};
 const risk=Math.round(Math.min(100,Object.values(contributions).reduce((a,b)=>a+b,0)));
 return {kind,reasons,features:f,risk,severity:severityOf(risk),contributions};
}
const keys={ACCOUNT_LOCK:'accounts',IP_BLOCK:'ips',HOST_ISOLATION:'hosts',SERVICE_BLOCK:'services',SESSION_TERMINATION:'sessions',CRITICAL_HOST_PROTECTION:'protected',WATCHLIST_ADD:'watchlist',PRIVILEGE_REVOCATION:'privileges'};
export const applyControl=(c,a,t)=>{if(!c[keys[a]].includes(t))c[keys[a]].push(t);};
export function blockReason(c,e){return e.user&&c.accounts.includes(e.user)?'Account locked':c.ips.includes(e.source)?'Source blocked':c.hosts.includes(e.source)||c.hosts.includes(e.destination)?'Host isolated':c.services.includes(e.service)?'Service blocked':c.sessions.includes(e.user)?'Session terminated':c.protected.includes(e.destination)&&e.user!=='admin01'?'Critical host protected':null;}
export function response(kind,user='employee01',source='WS-01'){
 return {'credential-abuse':[['ACCOUNT_LOCK',user],['SESSION_TERMINATION',user],['WATCHLIST_ADD',user]],'brute-force':[['ACCOUNT_LOCK',user],['IP_BLOCK',source],['SESSION_TERMINATION',user]],'lateral-movement':[['HOST_ISOLATION','SERVER-01'],['SERVICE_BLOCK','RDP'],['SERVICE_BLOCK','SMB'],['SESSION_TERMINATION',user]],'privilege-escalation':[['PRIVILEGE_REVOCATION',user],['ACCOUNT_LOCK',user],['CRITICAL_HOST_PROTECTION','DC-01'],['SESSION_TERMINATION',user]],'reconnaissance':[['HOST_ISOLATION',source],['IP_BLOCK',source]]}[kind];
}
export function runSimulation(kind,autoDefense=true){
 const meta=catalog.scenarios.find(s=>s.id===kind);if(!meta)throw new Error('Unknown scenario');const start=performance.now(),id=uid('LM'),controls=blankControls(),events=[],actions=[];let found=null,peak=0,best={},reasons=[],latency=null;
 for(const raw of generateAttack(kind)){
  const reason=blockReason(controls,raw),e={...raw,blocked:!!reason,block_reason:reason};if(reason)e.success=false;events.push(e);
  if(!reason){const d=detect(events);if(d.risk>=peak){peak=d.risk;best=d;}
   if(d.kind&&!found){found=d.kind;reasons=d.reasons;latency=performance.now()-start;if(autoDefense)for(const [action,target] of response(d.kind,e.user,e.source)){applyControl(controls,action,target);actions.push({id:uid('DF'),attack_id:id,timestamp:new Date().toISOString(),action,target,status:'APPLIED'});}}}
 }
 return {id,timestamp:new Date().toISOString(),scenario:kind,name:meta.name,source:'WS-01',destination:meta.destination,user:'employee01',service:meta.service,technique:meta.technique,techniqueName:meta.techniqueName,tactic:meta.tactic,techniqueUrl:meta.url,risk:peak,severity:severityOf(peak),detected:!!found,detectedAs:found,status:actions.length?(events.some(e=>e.blocked)?'BLOCKED':'CONTAINED'):found?'DETECTED':'MISSED',explanations:reasons,contributions:best.contributions,method:'Rule-based fallback · model training required',modelScores:{gnn:null,random_forest:null,isolation_forest:null},events,actions,controls,latencyMs:latency,durationMs:performance.now()-start,path:observedPath(events),simulated:true,engine:'Browser',notes:''};
}
export function observedPath(events){const allowed=events.filter(e=>!e.blocked),last=allowed.at(-1);if(!last)return [];const path=[last.source,last.destination];for(const e of allowed.slice(0,-1).reverse()){if(e.success&&e.destination===path[0]&&!path.includes(e.source))path.unshift(e.source);}return [...new Set(path)];}
export const actionLabel=a=>a.toLowerCase().replaceAll('_',' ').replace(/^./,s=>s.toUpperCase());
