"""Build ordered ATT&CK technique sequences from the MITRE CTID Attack Flow corpus (Apache-2.0).
Source: https://github.com/center-for-threat-informed-defense/attack-flow  (corpus/*.afb)
Each .afb is a graph of actions; edges give the real order of steps in a documented intrusion.
Output: data/sequences.json  -> [{"flow": name, "seq": ["T1566.001", "T1059.001", ...]}, ...]
"""
import glob, json, os, subprocess, sys
from collections import defaultdict

ROOT = os.path.join(os.path.dirname(__file__), "..")
REPO = os.path.join(ROOT, "data", "attack-flow")
OUT = os.path.join(ROOT, "data", "sequences.json")


def fetch():
    if not os.path.isdir(REPO):
        subprocess.check_call(["git", "clone", "--depth", "1",
                               "https://github.com/center-for-threat-informed-defense/attack-flow.git", REPO])


def _props(o):
    return {k: v for k, v in o.get("properties", []) if isinstance(k, str)}


def flow_to_paths(path, max_paths=200):
    d = json.load(open(path, encoding="utf-8"))
    objs = {o["instance"]: o for o in d["objects"]}
    latch_owner = {}                      # latch id -> node id
    for o in objs.values():
        for a in (o.get("anchors") or {}).values():
            for l in (objs.get(a, {}).get("latches") or []):
                latch_owner[l] = o["instance"]
    adj = defaultdict(set)
    for o in objs.values():
        if o["id"] == "dynamic_line":
            s, t = latch_owner.get(o["source"]), latch_owner.get(o["target"])
            if s and t and s != t:
                adj[s].add(t)
    is_action = lambda n: objs[n]["id"] == "action" and _props(objs[n]).get("technique_id")
    # collapse non-action nodes: action -> next actions reachable through assets/conditions/operators
    def next_actions(n, seen=None):
        seen = seen or set(); out = []
        for m in adj[n]:
            if m in seen: continue
            seen.add(m)
            out += [m] if is_action(m) else next_actions(m, seen)
        return out
    acts = [n for n in objs if is_action(n)]
    nxt = {a: list(dict.fromkeys(next_actions(a))) for a in acts}
    has_in = {m for a in acts for m in nxt[a]}
    starts = [a for a in acts if a not in has_in] or acts[:1]
    paths = []
    def dfs(n, trail):
        if len(paths) >= max_paths: return
        trail = trail + [n]
        succ = [m for m in nxt[n] if m not in trail]
        if not succ:
            paths.append(trail); return
        for m in succ: dfs(m, trail)
    for s in starts: dfs(s, [])
    return [[_props(objs[n])["technique_id"] for n in p] for p in paths if len(p) >= 2]


def build():
    fetch()
    data = []
    for f in sorted(glob.glob(os.path.join(REPO, "corpus", "*.afb"))):
        name = os.path.basename(f)[:-4]
        try:
            for seq in flow_to_paths(f):
                data.append({"flow": name, "seq": seq})
        except Exception as e:
            print("skip", name, e, file=sys.stderr)
    json.dump(data, open(OUT, "w"), indent=1)
    flows = {x["flow"] for x in data}
    print(f"{len(data)} sequences from {len(flows)} flows -> {OUT}")


if __name__ == "__main__":
    build()
