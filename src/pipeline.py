import os
from .domain_scanner import scan_domain
from .attack_mapper import map_indicators
from .markov_predictor import load_transitions, predict
from .risk import score
from .attack_graph import build_graph
from .report import ai_report, MODEL_INFO
from .lstm_model import MODEL_PATH as LSTM_PATH

TACTIC_ORDER = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                'Credential Access', 'Discovery', 'Command and Control', 'Impact']


def run(domain, scan=None, model='lstm', flows=None):
    """domain: site to scan (None to skip). flows: optional CSV/XLSX of network flows to classify (see flow_detector)."""
    if domain or scan:
        scan = scan or scan_domain(domain)
        mappings = map_indicators(scan)
    else:
        scan, mappings = {"domain": "(network flows only)"}, []
    if flows:
        from .flow_detector import detect, merge_mappings
        mappings = merge_mappings(mappings + detect(flows))
    ordered = [m['technique'] for m in sorted(
        mappings, key=lambda m: TACTIC_ORDER.index(m['tactic']) if m['tactic'] in TACTIC_ORDER else 99)]
    transitions = load_transitions()
    use_lstm = model == 'lstm' and os.path.exists(LSTM_PATH)
    if use_lstm and ordered:
        from .lstm_model import load, predict_next, rollout
        net, itos, stoi = load()
        predictions = predict_next(net, ordered, stoi, itos, k=5, exclude_seen=True)
        path = rollout(net, ordered, stoi, itos, steps=4)
        info = dict(MODEL_INFO)
    else:                                            # Markov fallback (also used if nothing was observed)
        predictions = predict(ordered, transitions)
        path = [{"technique": p["technique"], "score": p["score"]} for p in predictions[:1]]
        info = {"name": "Markov chain", "training_data": "Attack Flow corpus transitions",
                "evaluation": "Markov top-3 about 15%, top-5 about 20% on unseen intrusions"}
    risk = score(mappings, predictions)
    graph = build_graph(ordered, predictions, path)
    payload = {"domain": scan["domain"], "scan": scan, "mappings": mappings, "predictions": predictions,
               "path": path, "risk": risk, "model": info}
    return {**payload, "ordered": ordered, "graph": graph, "report": ai_report(payload)}
