"""Application-only access policy; enforced before every subsequent simulated event."""
def blank_controls():return dict(accounts=[],ips=[],hosts=[],services=[],sessions=[],protected=[],watchlist=[],privileges=[])
def actions_for(kind, user='employee01', source='WS-01'):
    common=[('SESSION_TERMINATION',user)]
    return {
      'credential-abuse':[('ACCOUNT_LOCK',user),*common,('WATCHLIST_ADD',user)],
      'brute-force':[('ACCOUNT_LOCK',user),('IP_BLOCK',source),*common],
      'lateral-movement':[('HOST_ISOLATION','SERVER-01'),('SERVICE_BLOCK','RDP'),('SERVICE_BLOCK','SMB'),*common],
      'privilege-escalation':[('PRIVILEGE_REVOCATION',user),('ACCOUNT_LOCK',user),('CRITICAL_HOST_PROTECTION','DC-01'),*common],
      'reconnaissance':[('HOST_ISOLATION',source),('IP_BLOCK',source)]
    }[kind]
KEYS={'ACCOUNT_LOCK':'accounts','IP_BLOCK':'ips','HOST_ISOLATION':'hosts','SERVICE_BLOCK':'services','SESSION_TERMINATION':'sessions','CRITICAL_HOST_PROTECTION':'protected','WATCHLIST_ADD':'watchlist','PRIVILEGE_REVOCATION':'privileges'}
def apply(controls,action,target):
    key=KEYS[action]
    if target not in controls[key]:controls[key].append(target)
def blocked(controls,e):
    tests=[(e['user'] in controls['accounts'],'Account locked'),(e['source'] in controls['ips'],'Source blocked'),(e['source'] in controls['hosts'] or e['destination'] in controls['hosts'],'Host isolated'),(e['service'] in controls['services'],'Service blocked'),(e['user'] in controls['sessions'],'Session terminated'),(e['destination'] in controls['protected'] and e['user']!='admin01','Critical host protected')]
    return next((reason for yes,reason in tests if yes),None)
