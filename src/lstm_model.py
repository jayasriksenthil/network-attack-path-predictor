"""LSTM next-technique predictor trained on ordered ATT&CK sequences (MITRE Attack Flow corpus)."""
import json, os, random
import torch, torch.nn as nn

ROOT = os.path.join(os.path.dirname(__file__), "..")
SEQ_PATH = os.path.join(ROOT, "data", "sequences.json")
MODEL_PATH = os.path.join(ROOT, "data", "lstm.pt")
PAD, UNK = 0, 1


def parent(t):            # T1059.001 -> T1059 (reduces sparsity on a small corpus)
    return t.split(".")[0]


def load_sequences(collapse=True):
    data = json.load(open(SEQ_PATH))
    out = []
    for d in data:
        s = [parent(t) if collapse else t for t in d["seq"]]
        out.append((d["flow"], s))
    return out


def build_vocab(seqs):
    toks = sorted({t for s in seqs for t in s})
    itos = ["<pad>", "<unk>"] + toks
    return itos, {t: i for i, t in enumerate(itos)}


class NextTech(nn.Module):
    def __init__(self, vocab, emb=64, hid=128, layers=2, drop=0.3):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb, padding_idx=PAD)
        self.lstm = nn.LSTM(emb, hid, layers, batch_first=True, dropout=drop)
        self.drop = nn.Dropout(drop)
        self.out = nn.Linear(hid, vocab)

    def forward(self, x):
        h, _ = self.lstm(self.drop(self.emb(x)))
        return self.out(self.drop(h))


def make_batches(seqs, stoi, bs=32, shuffle=True):
    ids = [[stoi.get(t, UNK) for t in s] for s in seqs]
    order = list(range(len(ids)))
    if shuffle: random.shuffle(order)
    for i in range(0, len(order), bs):
        b = [ids[j] for j in order[i:i + bs]]
        L = max(map(len, b))
        x = torch.zeros(len(b), L, dtype=torch.long)
        for r, s in enumerate(b): x[r, :len(s)] = torch.tensor(s)
        yield x


def train(train_seqs, stoi, itos, epochs=40, lr=2e-3, val_seqs=None, seed=0, verbose=True):
    random.seed(seed); torch.manual_seed(seed)
    m = NextTech(len(itos))
    opt = torch.optim.AdamW(m.parameters(), lr=lr, weight_decay=1e-2)
    lossf = nn.CrossEntropyLoss(ignore_index=PAD)
    best, best_state = 1e9, None
    for ep in range(epochs):
        m.train()
        for x in make_batches(train_seqs, stoi):
            logits = m(x[:, :-1])
            loss = lossf(logits.reshape(-1, logits.size(-1)), x[:, 1:].reshape(-1))
            opt.zero_grad(); loss.backward(); nn.utils.clip_grad_norm_(m.parameters(), 1.0); opt.step()
        if val_seqs:
            m.eval(); tot = n = 0
            with torch.no_grad():
                for x in make_batches(val_seqs, stoi, shuffle=False):
                    lg = m(x[:, :-1]); tot += lossf(lg.reshape(-1, lg.size(-1)), x[:, 1:].reshape(-1)).item(); n += 1
            v = tot / max(n, 1)
            if v < best: best, best_state = v, {k: t.clone() for k, t in m.state_dict().items()}
            if verbose and ep % 5 == 0: print(f"epoch {ep:2d} val_loss {v:.3f}")
    if best_state: m.load_state_dict(best_state)
    return m.eval()


def predict_next(model, prefix, stoi, itos, k=5, exclude_seen=False):
    ids = torch.tensor([[stoi.get(parent(t), UNK) for t in prefix]])
    with torch.no_grad():
        p = torch.softmax(model(ids)[0, -1], -1)
    p[PAD] = 0; p[UNK] = 0
    if exclude_seen:
        for i in ids[0]: p[i] = 0
    top = torch.topk(p, k)
    return [{"technique": itos[i], "score": round(float(s), 3), "type": "predicted-lstm"}
            for s, i in zip(top.values, top.indices) if s > 0]


def save(model, itos):
    torch.save({"state": model.state_dict(), "itos": itos}, MODEL_PATH)


def load():
    ck = torch.load(MODEL_PATH, map_location="cpu")
    itos = ck["itos"]; m = NextTech(len(itos)); m.load_state_dict(ck["state"])
    return m.eval(), itos, {t: i for i, t in enumerate(itos)}


def rollout(model, prefix, stoi, itos, steps=4):
    """Greedy multi-step LSTM forecast: repeatedly take the most likely unseen next technique.
    Returns [{"technique", "score"}] where score = LSTM probability of that step given the path so far."""
    path, seq = [], [parent(t) for t in prefix]
    for _ in range(steps):
        nxt = predict_next(model, seq, stoi, itos, k=1, exclude_seen=True)
        if not nxt:
            break
        path.append({"technique": nxt[0]["technique"], "score": nxt[0]["score"]})
        seq.append(nxt[0]["technique"])
    return path
