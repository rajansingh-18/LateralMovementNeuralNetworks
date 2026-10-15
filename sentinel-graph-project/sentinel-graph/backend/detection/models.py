import json
import numpy as np
from backend.config import MODEL_DIR
from backend.detection.feature_engineering import features,vector,graph_inputs
class Models:
    def __init__(self):
        self.baseline=None;self.gnn=None;self.metrics=None;self.error=None
        try:
            if (MODEL_DIR/'baseline.joblib').exists():
                import joblib
                self.baseline=joblib.load(MODEL_DIR/'baseline.joblib')
            if (MODEL_DIR/'temporal_graphsage.pt').exists():
                import torch
                from backend.detection.temporal_gnn import TemporalGraphSAGE
                self.gnn=TemporalGraphSAGE();self.gnn.load_state_dict(torch.load(MODEL_DIR/'temporal_graphsage.pt',map_location='cpu',weights_only=True));self.gnn.eval()
            if (MODEL_DIR/'metrics.json').exists():self.metrics=json.loads((MODEL_DIR/'metrics.json').read_text())
        except (ImportError,RuntimeError,ValueError,OSError) as ex:self.error=str(ex)
    def predict(self,events):
        result={'gnn':None,'random_forest':None,'isolation_forest':None}
        if self.baseline:
            v=vector(features(events)).reshape(1,-1);result['random_forest']=float(self.baseline['rf'].predict_proba(v)[0,1]);result['isolation_forest']=float(self.baseline['iforest'].decision_function(v)[0])
        if self.gnn:
            import torch
            x,a=graph_inputs(events)
            with torch.no_grad():result['gnn']=float(torch.softmax(self.gnn(torch.tensor(x)[None],torch.tensor(a)[None]),dim=-1)[0,1])
        return result
