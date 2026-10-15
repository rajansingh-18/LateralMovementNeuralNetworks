from backend.config import CATALOG, HOSTS
def build_graph(events, controls):
    nodes={h['id']:{**h,'node_type':'Host','status':'isolated' if h['id'] in controls['hosts'] else 'protected' if h['id'] in controls['protected'] else 'normal'} for h in CATALOG['hosts']};edges=[]
    for e in events:
        for node,typ in [(e['user'],'User'),(e['source_ip'],'IP'),('service:'+e['service'],'Service'),('process:'+e['source']+':'+e['process'],'Process')]:nodes.setdefault(node,{'id':node,'node_type':typ})
        for src,dst,typ in [(e['user'],e['destination'],'AUTHENTICATES_TO' if e['event_type']=='AUTHENTICATES_TO' else 'PERFORMS'),(e['source'],e['destination'],e['event_type']),(e['source'],'service:'+e['service'],'USES_SERVICE'),(e['source'],'process:'+e['source']+':'+e['process'],'STARTS_PROCESS'),(e['source_ip'],e['source'],'ASSIGNED_TO')]:
            edges.append(dict(id=e['event_id']+':'+typ,source=src,target=dst,type=typ,timestamp=e['timestamp'],blocked=e.get('blocked',False)))
    return {'nodes':list(nodes.values()),'edges':edges}
