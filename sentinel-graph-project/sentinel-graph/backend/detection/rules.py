from backend.detection.feature_engineering import features
def evaluate(events):
    f=features(events);kind=None;reasons=[]
    if f['privilege_anomaly']:kind='privilege-escalation';reasons.append('Employee privilege changed to ADMIN without an authorized role.')
    elif f['failed_logins']>=8:kind='brute-force';reasons.append(f"{int(f['failed_logins'])} failed sign-ins occurred inside a five-minute window.")
    elif f['hop_count']>=2 and f['new_relationships']>=2:kind='lateral-movement';reasons.append(f"{int(f['hop_count'])} connected remote-service hops formed a temporal path.")
    elif f['unique_hosts']>=3 and f['connection_frequency']>.1 and f['new_relationships']>=3:kind='reconnaissance';reasons.append('Rapid connections contacted at least three unfamiliar destinations.')
    elif f['new_relationships'] and f['off_hours']:kind='credential-abuse';reasons.append('An employee accessed a new destination outside normal working hours.')
    if kind:
        if f['destination_criticality']>=3: reasons.append('The destination is a high-value database or identity host.')
        if f['new_relationships']:reasons.append(f"{int(f['new_relationships'])} events differ from the configured normal access profile.")
        if f['remote_service_count']:reasons.append('Remote service activity was observed in the trailing event window.')
    return kind,f,reasons
