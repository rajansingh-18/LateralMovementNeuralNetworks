"""Simplified temporal GraphSAGE; not the memory-based TGN architecture.
Two trainable mean aggregation layers; temporal features and decayed adjacency.
Pure PyTorch operations avoid compiled PyG extension requirements on Windows.
"""
import torch
from torch import nn
class TemporalGraphSAGE(nn.Module):
    def __init__(self, input_dim=8, hidden=24):
        super().__init__();self.sage1=nn.Linear(input_dim*2,hidden);self.sage2=nn.Linear(hidden*2,hidden);self.head=nn.Linear(hidden,2)
    def forward(self,x,a):
        a=a/(a.sum(-1,keepdim=True).clamp(min=1))
        h=torch.relu(self.sage1(torch.cat([x,a@x],dim=-1)))
        h=torch.relu(self.sage2(torch.cat([h,a@h],dim=-1)))
        return self.head(h.mean(dim=-2))
