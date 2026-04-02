import os
import torch
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from dataset import MalwareGraphDataset

dataset = MalwareGraphDataset("extracted_data_augmented/dataset_manifest.csv")      # your actual path

broken = []
for data in dataset:
    name = getattr(data, "source", None) or getattr(data, "name", "")
    if data.num_nodes <= 5 or data.edge_index.shape[1] == 0:
        broken.append((name, data.num_nodes, data.edge_index.shape[1]))

print(f"\n{'='*60}")
print(f"BROKEN GRAPHS ({len(broken)} total)")
print(f"{'='*60}")
for name, n, e in sorted(broken):
    print(f"  {name:<55}")