def score(f, detected=False, gnn_score=None):
    novelty=min(1,f['new_relationships']/2);burst=min(1,max(f['failed_logins']/8,f['connection_frequency']/0.5));path=min(1,f['hop_count']/2);mitre=float(detected)
    if gnn_score is not None:
        parts={'GNN anomaly':40*gnn_score,'Novel relationships':20*novelty,'Temporal burst':15*burst,'Graph path':15*path,'Technique evidence':10*mitre};method='Temporal GraphSAGE + behavioral evidence'
    else:
        rule=min(1, .35*novelty+.3*burst+.35*path+.6*f['privilege_anomaly']+.4*f['off_hours'])
        parts={'Behavioral rules':45*max(rule,.8 if detected else 0),'Novel relationships':20*novelty,'Temporal burst':15*burst,'Graph path':10*path,'Critical destination':10*f['destination_criticality']/4}
        method='Rule-based fallback · model training required'
    value=round(min(100,sum(parts.values())))
    return value,('CRITICAL' if value>=80 else 'HIGH' if value>=60 else 'MEDIUM' if value>=30 else 'LOW'),parts,method
