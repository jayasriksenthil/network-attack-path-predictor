"""Risk scoring: weighted from observed mappings plus a smaller contribution from predictions."""

def score(mappings, predictions):
    obs = sum(m["confidence"] for m in mappings) * 18
    pred = sum(p["score"] for p in predictions) * 10
    total = min(100, round(obs + pred))
    level = "Low" if total < 25 else "Medium" if total < 50 else "High" if total < 75 else "Critical"
    return {"score": total, "level": level}
