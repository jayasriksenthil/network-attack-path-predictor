"""Attack-path graph driven by the model's own forecast.
Left to right:  observed exposures (orange)  ->  LSTM forecast path (teal)
Extra teal boxes under the path are the other top-ranked first-step candidates.
Edge labels are LSTM probabilities."""
import textwrap
import networkx as nx
from .attack_names import name

OBS, PRED, ALT = "#e67e22", "#16808f", "#7fb8c2"


def build_graph(ordered_obs, first_step, path):
    """ordered_obs: observed technique IDs in tactic order. first_step: top-k LSTM predictions.
    path: greedy LSTM rollout [{technique, score}, ...]."""
    g = nx.DiGraph(); x = 0
    for i, t in enumerate(ordered_obs):
        g.add_node(t, kind="observed", pos=(i, 0))
        if i: g.add_edge(ordered_obs[i - 1], t, label="", style="dashed")
    x = len(ordered_obs)
    prev = ordered_obs[-1] if ordered_obs else None
    path_ids = [p["technique"] for p in path]
    for j, p in enumerate(path):
        g.add_node(p["technique"], kind="predicted", pos=(x + j, 0))
        if prev: g.add_edge(prev, p["technique"], label=f"{p['score']:.2f}", style="solid")
        prev = p["technique"]
    row = 1
    last_obs = ordered_obs[-1] if ordered_obs else None
    for p in first_step:
        if p["technique"] in path_ids or p["technique"] in g: continue
        g.add_node(p["technique"], kind="alt", pos=(x, row)); row += 1
        if last_obs: g.add_edge(last_obs, p["technique"], label=f"{p['score']:.2f}", style="solid")
    return g


def draw(g, path, title="LSTM-predicted attack path"):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch, Patch
    pos = {n: d["pos"] for n, d in g.nodes(data=True)}
    xs = [p[0] for p in pos.values()] or [0]; ys = [p[1] for p in pos.values()] or [0]
    W, H = 2.35, 1.35
    fig, ax = plt.subplots(figsize=(max(8, (max(xs) + 1) * 2.4), max(3.6, (max(ys) + 1) * 1.7 + 1.2)))
    col = {"observed": OBS, "predicted": "#16808f", "alt": ALT}
    for n, d in g.nodes(data=True):
        x, y = d["pos"][0] * W, -d["pos"][1] * H
        ax.add_patch(FancyBboxPatch((x - .95, y - .42), 1.9, .84, boxstyle="round,pad=0.02,rounding_size=0.1",
                                    fc=col[d["kind"]], ec="none", zorder=2))
        label = n + "\n" + "\n".join(textwrap.wrap(name(n), 22)[:2])
        ax.text(x, y, label, ha="center", va="center", fontsize=8, color="white", weight="bold", zorder=3)
    for a, b, e in g.edges(data=True):
        (x1, y1), (x2, y2) = [(pos[n][0] * W, -pos[n][1] * H) for n in (a, b)]
        ls = "--" if e["style"] == "dashed" else "-"
        if g.nodes[b]["kind"] == "alt":                      # elbow: down from the last observed box, then right
            ax.plot([x1, x1], [y1 - .42, y2], color="#555", lw=1.4, zorder=1)
            ax.annotate("", xy=(x2 - .97, y2), xytext=(x1 - .01, y2),
                        arrowprops=dict(arrowstyle="-|>", color="#555", lw=1.4), zorder=1)
            lx, ly = (x1 + x2 - .97) / 2, y2 + .12
        else:
            ax.annotate("", xy=(x2 - .97, y2), xytext=(x1 + .97, y1),
                        arrowprops=dict(arrowstyle="-|>", color="#555", lw=1.4, linestyle=ls), zorder=1)
            lx, ly = (x1 + .97 + x2 - .97) / 2, y1 + .17
        if e["label"]:
            ax.text(lx, ly, e["label"], fontsize=8, color="#222", ha="center",
                    bbox=dict(fc="white", ec="none", pad=1.2), zorder=4)
    ax.set_xlim(-1.2, (max(xs)) * W + 1.3); ax.set_ylim(-(max(ys)) * H - .9, .9)
    ax.axis("off"); ax.set_title(title, fontsize=12, weight="bold", loc="left")
    ax.legend(handles=[Patch(color=OBS, label="Observed evidence (scan / traffic)"),
                       Patch(color="#16808f", label="LSTM forecast path"),
                       Patch(color=ALT, label="Other top LSTM candidates")],
              loc="lower center", bbox_to_anchor=(.5, -.12), ncol=3, frameon=False, fontsize=8)
    fig.savefig(path, dpi=140, bbox_inches="tight", facecolor="white"); plt.close(fig)
