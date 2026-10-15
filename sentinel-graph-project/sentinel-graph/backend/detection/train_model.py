"""CPU training; chronological episode split 70/15/15, no shared episodes across splits.
Metrics are synthetic holdout measurements and do not establish enterprise efficacy.
"""
import argparse,copy,json,time
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier,IsolationForest
from sklearn.metrics import precision_score,recall_score,f1_score,roc_auc_score,average_precision_score,confusion_matrix
from backend.config import ROOT,MODEL_DIR
from backend.detection.feature_engineering import features,vector,graph_inputs,FEATURE_NAMES
from backend.detection.rules import evaluate
from generate_dataset import generate
def report(y,score,threshold=.5):
    pred=np.asarray(score)>=threshold
    return {'precision':float(precision_score(y,pred,zero_division=0)),'recall':float(recall_score(y,pred,zero_division=0)),'f1':float(f1_score(y,pred,zero_division=0)),'roc_auc':float(roc_auc_score(y,score)),'pr_auc':float(average_precision_score(y,score)),'confusion_matrix':confusion_matrix(y,pred,labels=[0,1]).tolist(),'threshold':float(threshold)}
def train(epochs=60,baseline_only=False):
    start=time.perf_counter();data=generate();n=len(data);i=int(n*.7);j=int(n*.85)
    # Prefix lengths vary by episode. Every prefix remains in its episode's split.
    rng=np.random.default_rng(42);windows=[d['events'][:int(rng.integers(max(1,len(d['events'])//2),len(d['events'])+1))] for d in data]
    v=np.stack([vector(features(e)) for e in windows]);y=np.array([int(d['label'] and len(w)>d['attack_onset']) for d,w in zip(data,windows)]);
    rf=RandomForestClassifier(n_estimators=120,max_depth=10,min_samples_leaf=3,class_weight='balanced',random_state=42,n_jobs=2).fit(v[:i],y[:i])
    iso=IsolationForest(n_estimators=100,contamination=.05,random_state=42,n_jobs=2).fit(v[:i][y[:i]==0])
    iso_val=-iso.decision_function(v[i:j]);thresholds=np.linspace(iso_val.min(),iso_val.max(),50);threshold=max(thresholds,key=lambda t:f1_score(y[i:j],iso_val>=t,zero_division=0))
    MODEL_DIR.mkdir(exist_ok=True);joblib.dump({'rf':rf,'iforest':iso,'features':FEATURE_NAMES},MODEL_DIR/'baseline.joblib')
    metrics={'scope':'Synthetic holdout episodes only; not real enterprise performance','split':{'train':i,'validation':j-i,'test':n-j,'method':'Chronological episode split; disjoint IDs'},'normal_events':sum(len(d['events']) for d in data if not d['label']),'attack_events':sum(len(d['events']) for d in data if d['label']),'seed':42,'models':{'Random Forest':report(y[j:],rf.predict_proba(v[j:])[:,1]),'Isolation Forest':report(y[j:],-iso.decision_function(v[j:]),threshold),'Behavioral rules':report(y[j:],[int(bool(evaluate(e)[0])) for e in windows[j:]])}}
    if not baseline_only:
        import torch
        from backend.detection.temporal_gnn import TemporalGraphSAGE
        torch.set_num_threads(2);torch.manual_seed(42)
        graphs=[graph_inputs(e) for e in windows];x=torch.tensor(np.stack([g[0] for g in graphs]));a=torch.tensor(np.stack([g[1] for g in graphs]));target=torch.tensor(y,dtype=torch.long)
        model=TemporalGraphSAGE();optim=torch.optim.Adam(model.parameters(),lr=.008,weight_decay=.0001);loss_fn=torch.nn.CrossEntropyLoss();best=1e9;best_state=None;best_epoch=0
        for epoch in range(epochs):
            model.train()
            for batch in torch.randperm(i).split(128):
                optim.zero_grad();loss=loss_fn(model(x[batch],a[batch]),target[batch]);loss.backward();optim.step()
            model.eval()
            with torch.no_grad():val=float(loss_fn(model(x[i:j],a[i:j]),target[i:j]))
            if val<best:best=val;best_state=copy.deepcopy(model.state_dict());best_epoch=epoch+1
        model.load_state_dict(best_state);model.eval()
        with torch.no_grad():prob=torch.softmax(model(x[j:],a[j:]),-1)[:,1].numpy()
        torch.save(model.state_dict(),MODEL_DIR/'temporal_graphsage.pt');metrics['models']['Temporal GraphSAGE']=report(y[j:],prob);metrics['best_epoch']=best_epoch
    metrics['training_seconds']=round(time.perf_counter()-start,2)
    from datetime import datetime,timezone
    metrics['trained_at']=datetime.now(timezone.utc).isoformat();(MODEL_DIR/'metrics.json').write_text(json.dumps(metrics,indent=2));print(json.dumps(metrics,indent=2))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--epochs',type=int,default=60);p.add_argument('--baseline-only',action='store_true');args=p.parse_args();train(args.epochs,args.baseline_only)
