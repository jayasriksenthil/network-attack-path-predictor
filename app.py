import streamlit as st
from src.pipeline import run
from src.attack_graph import draw

st.set_page_config(page_title="AI Attack Intelligence", layout="wide")
st.title("AI Attack Intelligence Platform")
domain = st.text_input("Domain (authorized assessments only)", "example.com")
up = st.file_uploader("Optional: network-flow file (CSV or XLSX) to classify", type=["csv", "xlsx"])
ok = st.checkbox("I own this domain or have written authorization to assess it")
if st.button("Scan") and ok:
    flows = None
    if up is not None:
        import tempfile, os
        flows = os.path.join(tempfile.mkdtemp(), up.name)
        open(flows, "wb").write(up.getbuffer())
    with st.spinner("Collecting passive data..."):
        r = run(domain, flows=flows)
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk", f"{r['risk']['score']}/100", r["risk"]["level"])
    c2.metric("Observed exposures", len(r["mappings"]))
    c3.metric("Predicted techniques", len(r["predictions"]))
    st.subheader("Observed (evidence-backed)")
    st.dataframe([{k: m[k] for k in ("technique", "name", "tactic", "confidence")} | {"evidence": "; ".join(m["evidence"])} for m in r["mappings"]])
    st.subheader("LSTM forecast (predicted, not confirmed)")
    from src.attack_names import name
    st.dataframe([{"technique": q["technique"], "name": name(q["technique"]), "lstm_probability": q["score"]} for q in r["predictions"]])
    st.caption("Most likely path: " + " → ".join(f"{x['technique']} {name(x['technique'])}" for x in r["path"]))
    draw(r["graph"], "output/attack_path.png")
    st.image("output/attack_path.png")
    st.subheader("AI Security Analyst")
    st.markdown(r["report"])
elif not ok:
    st.info("Tick the authorization box to enable scanning.")
