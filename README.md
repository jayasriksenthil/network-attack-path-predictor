# AI-Driven Attack Detection, Path Prediction & Risk Intelligence System
pip install -r requirements.txt
python -m src.domain_scanner yourdomain.com     # Stage 1 only
python main.py yourdomain.com                   # full pipeline -> output/report.md, output/attack_path.png
streamlit run app.py                            # dashboard
Set ANTHROPIC_API_KEY for the GenAI report (otherwise a template report is used).
data/transitions.json is built from the real Attack Flow corpus (see LSTM section).
Only assess domains you own or are authorized to test.

## LSTM model (added)
Dataset: MITRE CTID Attack Flow corpus (Apache-2.0) - real, ORDERED intrusion paths.
  python -m src.dataset_attackflow     # downloads corpus, writes data/sequences.json (835 paths, 34 intrusions)
  python -m src.evaluate               # LSTM vs Markov vs frequency, holding out whole intrusions
Training the final model + real Markov table was done once; files: data/lstm.pt, data/transitions.json.
main.py / app.py use the LSTM by default; run(domain, model='markov') switches to Markov.
Honest result (5 flow-holdout splits, next-technique accuracy, see output/evaluation_results.txt):
  LSTM top1 7% top3 20% top5 25% | Markov top1 9% top3 15% top5 20% | frequency 3% / 12% / 17%.
Small corpus (34 intrusions) => both models are modest; report this plainly.

## Output is LSTM-based
Report, graph and dashboard all come from the LSTM forecast:
- Predictions: top-5 next techniques with LSTM probabilities and official ATT&CK names (data/technique_names.json).
- Attack path: 4-step greedy LSTM rollout starting from the observed exposures.
- Graph: orange = observed, teal = LSTM path, light teal = other top candidates; edge labels = LSTM probabilities.
- Report: sections for observed exposures, LSTM forecast, attack path, defensive actions, limitations (with measured accuracy).
Examples (from a mock scan, not a real domain): output/sample_report.md and output/sample_attack_path.png.

## Network-flow attack detection (added)
Reads your CICIDS2017-style files (CSV or Excel; a folder or a single file) and detects attack types in the traffic.
Detected attacks become OBSERVED evidence (source "network-flow") and the LSTM then forecasts what follows them.

  1) Train once on your LABELLED files (needs a "Label" column: BENIGN, PortScan, DoS Hulk, ...):
       python -m src.flow_detector train "C:/path/to/MachineLearningCVE"
     -> data/flow_model.joblib and output/flow_detection_results.txt (precision/recall per attack type)
  2) Classify new traffic (no Label column needed):
       python -m src.flow_detector detect "C:/path/to/new_traffic.csv"
  3) Full report using BOTH the website scan and the traffic:
       python main.py yourdomain.com --flows "C:/path/to/new_traffic.csv"
     Traffic only:   python main.py --flows "C:/path/to/new_traffic.csv"
     Dashboard:      streamlit run app.py   (upload the traffic file in the page)

Label -> stage -> ATT&CK mapping (from your add_stage_column.py): PortScan -> Reconnaissance/T1595; FTP/SSH-Patator and
web brute force -> Credential Access/T1110; SQL injection, XSS, Heartbleed -> Initial Access/T1190; Bot -> C2/T1071;
DoS/DDoS -> Impact/T1498; Infiltration -> Privilege Escalation/T1068 (weak mapping, confidence capped at 0.4).
Large data: training uses at most 40,000 rows per attack type to stay fast. Scores use a random row split, so they are
optimistic; describe them as "held-out rows of the same dataset".

### Real data used for the detector
Trained on CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB), using the preprocessed train / cross-validation / test
files published with the open-source project github.com/ArnaudRosay/mlp4nids (MIT licence).
Original dataset paper: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion
Traffic Characterization", ICISSP 2018. Please cite both if you publish results.
Result (paper's own held-out test set, 278,270 flows): 99.5% overall accuracy. Strong for DoS, DDoS, PortScan, FTP/SSH-Patator
(F1 about 0.98 to 1.0). Weak for Bot (precision 0.38), Web Attack XSS (F1 0.36), Web Attack Brute Force (F1 0.64); SQL injection,
Heartbleed and Infiltration have too few examples to trust. Full table: output/flow_detection_results.txt.
False-alarm check: 2 x 50,000 purely benign flows produced no alerts. Weak classes are only reported when they make up >= 5% of
the traffic, strong ones when they make up >= 1%.
Try it now with the included real sample (1,500 flows):  python main.py --flows data/sample_traffic.csv
Retrain on your own files:  python -m src.flow_detector train "your folder" --test "your test file"   (about 20 seconds)
