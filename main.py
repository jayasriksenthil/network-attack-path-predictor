import argparse, os
os.makedirs("output", exist_ok=True)
from src.pipeline import run
from src.attack_graph import draw

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Attack detection, LSTM path prediction and risk report")
    ap.add_argument("domain", nargs="?", help="domain you are authorized to assess (omit to use --flows only)")
    ap.add_argument("--flows", help="CSV/XLSX file or folder of network flows to classify")
    a = ap.parse_args()
    d = a.domain if (a.domain or a.flows) else input("Domain you are authorized to assess: ")
    r = run(d, flows=a.flows)
    draw(r["graph"], "output/attack_path.png")
    open("output/report.md", "w", encoding="utf-8").write(r["report"])
    print(r["report"])
