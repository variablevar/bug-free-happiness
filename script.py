dataset_py = '''\
#!/usr/bin/env python3
"""
dataset.py
Loads all 30 graph.pkl files from the dataset manifest and converts
each NetworkX graph into a PyTorch Geometric Data object.

Usage:
    from dataset import MalwareGraphDataset
    dataset = MalwareGraphDataset("extracted_data/dataset_manifest.csv")
    data = dataset[0]   # PyG Data object
"""

import os, pickle
import pandas as pd
import numpy as np
import torch
from torch_geometric.data import Data, Dataset

# ── Node type vocabulary (all types seen across the dataset) ──────────────────
NODE_TYPES = [
    "process", "thread", "dll", "memory_region",
    "network_conn", "ip_address", "handle", "driver", "kernel"
]
NODE_TYPE_IDX = {t: i for i, t in enumerate(NODE_TYPES)}

EDGE_TYPES = [
    "spawned_by", "belongs_to", "loaded_into", "allocated_in",
    "injected_into", "connects_from", "connects_to",
    "owned_by", "points_to", "loaded_in_kernel"
]
EDGE_TYPE_IDX = {t: i for i, t in enumerate(EDGE_TYPES)}

# ── Numeric node attributes to extract (in fixed order) ──────────────────────
# These exist on process/thread/memory nodes — missing = 0
NUMERIC_ATTRS = [
    "pid", "ppid", "threads", "handles",
    "is_suspicious", "is_rwx", "has_mz_header",
    "private_memory", "commit_charge",
    "local_port", "foreign_port", "is_external",
    "size", "start",
    "load_count",
    "tid",
]

def node_features(data: dict) -> list:
    """
    Build a fixed-length float feature vector for one node:
      [one-hot node_type (9 dims)] + [numeric attrs (16 dims)] = 25 dims
    """
    # One-hot node type
    ntype = data.get("node_type", "kernel")
    oh = [0.0] * len(NODE_TYPES)
    oh[NODE_TYPE_IDX.get(ntype, len(NODE_TYPES) - 1)] = 1.0

    # Numeric attrs (cast bool/None/str to float safely)
    nums = []
    for attr in NUMERIC_ATTRS:
        v = data.get(attr, 0)
        try:
            nums.append(float(v))
        except (TypeError, ValueError):
            nums.append(0.0)

    return oh + nums


def nx_to_pyg(G, label: int) -> Data:
    """Convert a NetworkX DiGraph to a PyTorch Geometric Data object."""
    nodes = list(G.nodes(data=True))
    node_idx = {nid: i for i, (nid, _) in enumerate(nodes)}

    # Node feature matrix  [N x F]
    x = torch.tensor(
        [node_features(data) for _, data in nodes],
        dtype=torch.float
    )

    # Edge index  [2 x E]
    src_list, dst_list, edge_attr_list = [], [], []
    for u, v, edata in G.edges(data=True):
        if u in node_idx and v in node_idx:
            src_list.append(node_idx[u])
            dst_list.append(node_idx[v])
            etype = edata.get("edge_type", "spawned_by")
            edge_attr_list.append(EDGE_TYPE_IDX.get(etype, 0))

    if src_list:
        edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
        edge_attr  = torch.tensor(edge_attr_list, dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_attr  = torch.zeros(0, dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([label], dtype=torch.long),
        num_nodes=x.size(0),
    )


class MalwareGraphDataset(Dataset):
    """
    Reads dataset_manifest.csv, loads each graph.pkl,
    and returns PyG Data objects.
    """

    def __init__(self, manifest_csv: str, base_dir: str = None):
        super().__init__()
        self.manifest = pd.read_csv(manifest_csv)
        self.base_dir = base_dir or os.path.dirname(manifest_csv)
        self._data_list = []
        self._load_all()

    def _load_all(self):
        ok, fail = 0, 0
        for _, row in self.manifest.iterrows():
            name   = row["name"]
            label  = int(row["label"])
            family = row.get("family", "unknown")
            pkl    = os.path.join(self.base_dir, name, "graph.pkl")

            if not os.path.exists(pkl):
                print(f"  [SKIP] {name} — graph.pkl not found")
                fail += 1
                continue

            with open(pkl, "rb") as f:
                G = pickle.load(f)

            pyg = nx_to_pyg(G, label)
            pyg.name   = name
            pyg.family = family
            self._data_list.append(pyg)
            ok += 1

        print(f"[Dataset] Loaded {ok}/{ok+fail} graphs  "
              f"(label=1: {sum(d.y.item()==1 for d in self._data_list)}  "
              f"label=0: {sum(d.y.item()==0 for d in self._data_list)})")

    def len(self):
        return len(self._data_list)

    def get(self, idx):
        return self._data_list[idx]

    def labels(self):
        return [d.y.item() for d in self._data_list]

    def summary(self):
        print(f"\\nDataset summary ({len(self)} graphs):")
        print(f"  Node feature dim : {self._data_list[0].x.size(1)}")
        print(f"  Edge types       : {len(EDGE_TYPES)}")
        for d in self._data_list:
            print(f"  {d.name:<35} nodes={d.num_nodes:<6} "
                  f"edges={d.edge_index.size(1):<6} label={d.y.item()}")


if __name__ == "__main__":
    import sys
    manifest = sys.argv[1] if len(sys.argv) > 1 else "extracted_data/dataset_manifest.csv"
    ds = MalwareGraphDataset(manifest)
    ds.summary()
'''

model_py = '''\
#!/usr/bin/env python3
"""
model.py
GIN-based binary classifier for malware graph detection.
Also provides a GraphSAGE variant for comparison.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GINConv, SAGEConv, global_mean_pool, global_add_pool


# ── GIN Classifier (recommended) ─────────────────────────────────────────────
class GINMalwareClassifier(nn.Module):
    """
    Graph Isomorphism Network for binary malware classification.
    Strongest at distinguishing structurally different graphs.
    """

    def __init__(self, in_channels: int, hidden: int = 64, layers: int = 3, dropout: float = 0.3):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            mlp = nn.Sequential(
                nn.Linear(in_ch, hidden),
                nn.BatchNorm1d(hidden),
                nn.ReLU(),
                nn.Linear(hidden, hidden),
            )
            self.convs.append(GINConv(mlp, train_eps=True))
            self.bns.append(nn.BatchNorm1d(hidden))

        self.dropout = dropout
        self.classifier = nn.Sequential(
            nn.Linear(hidden * layers, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 2),
        )

    def forward(self, x, edge_index, batch):
        # Collect embeddings from every layer (jumping knowledge)
        layer_outs = []
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            layer_outs.append(global_add_pool(x, batch))

        # Concatenate all layer readouts → graph embedding
        graph_emb = torch.cat(layer_outs, dim=1)
        return self.classifier(graph_emb)


# ── GraphSAGE Classifier (alternative) ───────────────────────────────────────
class SAGEMalwareClassifier(nn.Module):
    """GraphSAGE variant — good for large heterogeneous graphs."""

    def __init__(self, in_channels: int, hidden: int = 64, layers: int = 3, dropout: float = 0.3):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self.dropout = dropout
        self.classifier = nn.Sequential(
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden // 2, 2),
        )

    def forward(self, x, edge_index, batch):
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
        graph_emb = global_mean_pool(x, batch)
        return self.classifier(graph_emb)
'''

train_py = '''\
#!/usr/bin/env python3
"""
train.py
5-fold cross-validation training + evaluation for malware GNN classifier.

Usage:
    python train.py extracted_data/dataset_manifest.csv
    python train.py extracted_data/dataset_manifest.csv --model sage
    python train.py extracted_data/dataset_manifest.csv --epochs 100 --hidden 128
"""

import os, sys, argparse, json
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (accuracy_score, f1_score,
                              roc_auc_score, confusion_matrix)

from dataset import MalwareGraphDataset
from model import GINMalwareClassifier, SAGEMalwareClassifier


def train_epoch(model, loader, optimiser, device):
    model.train()
    total_loss = 0
    for batch in loader:
        batch = batch.to(device)
        optimiser.zero_grad()
        out  = model(batch.x, batch.edge_index, batch.batch)
        loss = F.cross_entropy(out, batch.y)
        loss.backward()
        optimiser.step()
        total_loss += loss.item()
    return total_loss / len(loader)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    preds, probs, labels = [], [], []
    for batch in loader:
        batch  = batch.to(device)
        out    = model(batch.x, batch.edge_index, batch.batch)
        prob   = F.softmax(out, dim=1)[:, 1].cpu().numpy()
        pred   = out.argmax(dim=1).cpu().numpy()
        label  = batch.y.cpu().numpy()
        preds.extend(pred)
        probs.extend(prob)
        labels.extend(label)

    acc = accuracy_score(labels, preds)
    f1  = f1_score(labels, preds, zero_division=0)
    auc = roc_auc_score(labels, probs) if len(set(labels)) > 1 else 0.0
    cm  = confusion_matrix(labels, preds)
    return acc, f1, auc, cm


def run(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Train] Device: {device}")

    # Load dataset
    ds      = MalwareGraphDataset(args.manifest)
    labels  = ds.labels()
    in_dim  = ds[0].x.size(1)
    n       = len(ds)
    print(f"[Train] {n} graphs  |  feature dim={in_dim}  |  model={args.model.upper()}")

    skf     = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)
    indices = np.arange(n)

    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(indices, labels), 1):
        print(f"\\n── Fold {fold}/{args.folds} "
              f"(train={len(train_idx)}, test={len(test_idx)}) ──")

        train_ds = [ds[i] for i in train_idx]
        test_ds  = [ds[i] for i in test_idx]

        train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
        test_loader  = DataLoader(test_ds,  batch_size=args.batch_size, shuffle=False)

        # Build model
        if args.model == "sage":
            model = SAGEMalwareClassifier(in_dim, hidden=args.hidden,
                                          layers=args.layers, dropout=args.dropout)
        else:
            model = GINMalwareClassifier(in_dim, hidden=args.hidden,
                                         layers=args.layers, dropout=args.dropout)
        model = model.to(device)

        optimiser = torch.optim.Adam(model.parameters(), lr=args.lr,
                                     weight_decay=args.weight_decay)
        scheduler = torch.optim.lr_scheduler.StepLR(optimiser, step_size=30, gamma=0.5)

        best_f1, best_state = 0.0, None
        for epoch in range(1, args.epochs + 1):
            loss = train_epoch(model, train_loader, optimiser, device)
            scheduler.step()
            if epoch % 10 == 0 or epoch == args.epochs:
                acc, f1, auc, _ = evaluate(model, test_loader, device)
                print(f"  Epoch {epoch:>3}  loss={loss:.4f}  "
                      f"acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}")
                if f1 >= best_f1:
                    best_f1    = f1
                    best_state = {k: v.clone() for k, v in model.state_dict().items()}

        # Final eval with best weights
        model.load_state_dict(best_state)
        acc, f1, auc, cm = evaluate(model, test_loader, device)
        print(f"  Best → acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}")
        print(f"  Confusion matrix:\\n{cm}")

        fold_results.append({"fold": fold, "acc": acc, "f1": f1, "auc": auc})

        # Per-sample predictions for this fold
        model.eval()
        with torch.no_grad():
            for data in test_ds:
                b = data.to(device)
                out  = model(b.x, b.edge_index,
                             torch.zeros(b.num_nodes, dtype=torch.long, device=device))
                pred = out.argmax(dim=1).item()
                prob = F.softmax(out, dim=1)[0, 1].item()
                status = "✅" if pred == b.y.item() else "❌"
                print(f"    {status} {data.name:<35} "
                      f"pred={pred} true={b.y.item()} prob={prob:.3f}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\\n" + "="*60)
    print(f"  {args.folds}-FOLD CV RESULTS ({args.model.upper()})")
    print("="*60)
    accs = [r["acc"] for r in fold_results]
    f1s  = [r["f1"]  for r in fold_results]
    aucs = [r["auc"] for r in fold_results]
    print(f"  Accuracy : {np.mean(accs):.3f} ± {np.std(accs):.3f}")
    print(f"  F1       : {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")
    print(f"  AUC-ROC  : {np.mean(aucs):.3f} ± {np.std(aucs):.3f}")
    print("="*60)

    # Save results
    out_path = f"results_{args.model}_{args.folds}fold.json"
    with open(out_path, "w") as f:
        json.dump({
            "model": args.model, "folds": args.folds,
            "epochs": args.epochs, "hidden": args.hidden,
            "mean_acc": np.mean(accs), "std_acc": np.std(accs),
            "mean_f1":  np.mean(f1s),  "std_f1":  np.std(f1s),
            "mean_auc": np.mean(aucs), "std_auc": np.std(aucs),
            "fold_results": fold_results,
        }, f, indent=2)
    print(f"  Results saved → {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", help="Path to dataset_manifest.csv")
    parser.add_argument("--model",        default="gin",  choices=["gin", "sage"])
    parser.add_argument("--folds",        type=int,   default=5)
    parser.add_argument("--epochs",       type=int,   default=100)
    parser.add_argument("--hidden",       type=int,   default=64)
    parser.add_argument("--layers",       type=int,   default=3)
    parser.add_argument("--dropout",      type=float, default=0.3)
    parser.add_argument("--lr",           type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--batch-size",   type=int,   default=8)
    args = parser.parse_args()
    run(args)
'''

for fname, content in [("dataset.py", dataset_py), ("model.py", model_py), ("train.py", train_py)]:
    with open(fname, "w", encoding="utf-8") as f:
        f.write(content)

import ast
for fname in ["dataset.py", "model.py", "train.py"]:
    with open(fname) as f:
        src = f.read()
    try:
        ast.parse(src)
        print(f"[OK] {fname}  ({src.count(chr(10))} lines, syntax valid)")
    except SyntaxError as e:
        print(f"[ERROR] {fname}: {e}")