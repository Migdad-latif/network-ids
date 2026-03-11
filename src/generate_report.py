"""
generate_report.py
------------------
Generates the final research-style project report
as a formatted plaintext file in results/.
Fill in the bracketed sections with your actual results.
"""

import os
import json
from datetime import datetime

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
OUTPUT_FILE = os.path.join(RESULTS_DIR, 'NIDS_Research_Report.txt')

# ── Load actual alert counts from data files ───────────────────────────────────

def load_alert_counts():
    sig_count = 0
    ml_count  = 0

    sig_file = os.path.join(BASE_DIR, 'data', 'alerts.json')
    ml_file  = os.path.join(BASE_DIR, 'data', 'ml_alerts.json')

    if os.path.exists(sig_file):
        with open(sig_file) as f:
            sig_count = len(json.load(f))

    if os.path.exists(ml_file):
        with open(ml_file) as f:
            ml_count = len(json.load(f))

    return sig_count, ml_count

def generate_report():
    sig_count, ml_count = load_alert_counts()
    total_alerts = sig_count + ml_count
    date_str = datetime.now().strftime('%B %d, %Y')

    D = '=' * 72
    S = '-' * 72

    report = f"""
{D}

       NETWORK INTRUSION DETECTION SYSTEM (NIDS)
       A Research-Quality Implementation Using Python and Machine Learning

{D}

   Author      : Migdad Latif Shaw
  Institution : The open university Bsc CyberSecurity
  Date        : March 11, 2026
  Repository  : https://github.com/Migdad-latif/network-ids

{D}


1. ABSTRACT
{S}

  This report presents the design, implementation, and evaluation of a
  Network Intrusion Detection System (NIDS) built using Python, Scapy,
  and Scikit-learn. The system combines two complementary detection
  approaches: a rule-based signature engine capable of identifying known
  attack patterns, and an unsupervised machine learning model using
  Isolation Forest for zero-day anomaly detection.

  The system was evaluated against four real Nmap attack scenarios
  including SYN stealth scans, service version probes, ICMP ping sweeps,
  and aggressive full-port scans. Across all tests, the system raised
  {total_alerts} total alerts — {sig_count} from signature detection and
  {ml_count} from the ML anomaly detector — demonstrating effective
  coverage of both known and behaviorally anomalous traffic patterns.


2. INTRODUCTION
{S}

  Network intrusion detection is a critical component of modern cyber
  security infrastructure. As networks grow in complexity and attack
  techniques evolve, automated detection systems must balance sensitivity
  (catching real attacks) with specificity (avoiding false positives).

  Traditional signature-based systems such as Snort and Suricata excel
  at detecting known attack patterns but are blind to novel threats.
  Machine learning approaches offer complementary capability by modelling
  normal traffic behaviour and flagging statistical deviations — without
  requiring prior knowledge of the attack pattern.

  This project implements both approaches within a unified Python
  pipeline, providing a research-quality demonstration of how layered
  detection strategies improve overall NIDS effectiveness.

  The system addresses the following research questions:

    RQ1: Can a Python-based NIDS detect real Nmap attack traffic using
         rule-based signature matching?

    RQ2: Can unsupervised ML anomaly detection identify attack traffic
         that signature rules alone do not cover?

    RQ3: How do the two detection approaches complement each other
         in a layered detection architecture?


3. SYSTEM ARCHITECTURE
{S}

  The system is structured as a five-stage pipeline:

  Stage 1 — Packet Capture (packet_capture.py)
    Scapy's sniff() function captures live packets from the network
    interface. Each packet is parsed into a structured record containing
    timestamp, source/destination IPs, protocol, ports, and size.
    Records are saved to data/captured_packets.csv.

  Stage 2 — Feature Extraction (feature_extractor.py)
    Raw packet fields are transformed into ML-ready numerical features.
    This includes IP classification (private/public), port classification
    (well-known/registered/ephemeral), one-hot protocol encoding, and
    aggregate per-source-IP statistics such as unique destination port
    count — the primary port scan indicator.

  Stage 3a — Signature Detection (signature_detector.py)
    Five rule-based signatures are evaluated against the packet data:
      - Port Scan: unique destination ports per source IP >= 10
      - SYN Flood: high packet count with tiny average packet size
      - DNS Amplification: high UDP port 53 volume from one source
      - Sensitive Port Access: traffic to SSH, RDP, SMB, MySQL ports
      - Large Outbound Transfer: total bytes from private IP > 500KB

  Stage 3b — ML Anomaly Detection (anomaly_detector.py)
    An Isolation Forest model is trained on the scaled feature matrix.
    The algorithm isolates anomalies by building random decision trees
    and measuring the path length to isolate each data point. Anomalous
    packets have shorter path lengths — they are statistical outliers
    that sit away from the dense cluster of normal traffic.
    PCA dimensionality reduction is used for 2D visualisation.

  Stage 4 — Alert Logging (alert_logger.py)
    All alerts are passed through Python's logging module with a
    RotatingFileHandler, producing persistent, severity-filtered logs.
    A session summary report is generated after each pipeline run.

  Stage 5 — Visualisation (visualiser.py)
    Six Matplotlib charts are produced:
      1. Protocol distribution pie chart
      2. Packet size histogram by protocol
      3. Traffic timeline (packets per second)
      4. Top talkers bar chart
      5. PCA anomaly scatter plot
      6. Isolation Forest score timeline


4. DETECTION SIGNATURES
{S}

  4.1 Port Scan Detection
    Threshold : >= 10 unique destination ports from one source IP
    Severity  : HIGH
    Rationale : Normal hosts contact a small, consistent set of ports.
                A host probing many ports in a short window is almost
                certainly performing reconnaissance.

  4.2 SYN Flood Detection
    Threshold : >= 20 packets with average size <= 100 bytes
    Severity  : CRITICAL
    Rationale : TCP SYN packets carry no payload and are 40-60 bytes.
                A flood of tiny packets from one source indicates an
                attempt to exhaust the target's TCP connection table.

  4.3 DNS Amplification Detection
    Threshold : >= 10 UDP packets to port 53 from one source
    Severity  : HIGH
    Rationale : Attackers use open DNS resolvers to amplify traffic
                volume. Legitimate clients send very few DNS queries
                per session.

  4.4 Sensitive Port Access
    Ports     : 22 (SSH), 23 (Telnet), 445 (SMB), 3306 (MySQL),
                3389 (RDP), 25 (SMTP), 53 (DNS), 8080 (HTTP-Alt)
    Severity  : CRITICAL (22, 445, 3389) / MEDIUM (others)
    Rationale : These ports represent high-value attack surfaces.
                Any unsolicited access attempt warrants investigation.

  4.5 Large Outbound Transfer
    Threshold : Total outbound bytes from private IP > 500,000
    Severity  : HIGH
    Rationale : Legitimate browsing generates moderate outbound traffic.
                A host sending large volumes to public IPs may indicate
                data exfiltration following a successful compromise.


5. MACHINE LEARNING METHODOLOGY
{S}

  Algorithm    : Isolation Forest (Liu et al., 2008)
  Library      : Scikit-learn 1.x
  Features     : 22 engineered features (see feature_extractor.py)
  Scaling      : StandardScaler (zero mean, unit variance)
  Contamination: 10% (tunable parameter)
  Trees        : 200 isolation trees
  Visualisation: PCA reduction to 2 principal components

  The Isolation Forest algorithm was selected for the following reasons:

    - Unsupervised: no labelled attack data required
    - Efficient: O(n log n) complexity, scales to live capture
    - Interpretable: anomaly scores have clear meaning
    - Robust: performs well on high-dimensional tabular data

  Feature scaling with StandardScaler is essential because features
  span very different magnitudes — packet_size ranges 40-1500 bytes
  while hour ranges 0-23 — and Isolation Forest path lengths are
  sensitive to feature scale without normalisation.


6. EVALUATION AND RESULTS
{S}

   6.2 Attack Test Results

    Test 1 — SYN Stealth Scan (nmap -sS)
    Packets captured  : Packets captured : 483
    Alerts raised     : Alerts raised : 3
    Signatures fired  :  PORT_SCAN, SENSITIVE_PORT_ACCESS
    ML anomalies      : 49

    Test 2 — Service Version Scan (nmap -sV)
    Packets captured  : 492
    Alerts raised     : 3
    Signatures fired  : SENSITIVE_PORT_ACCESS, PORT_SCAN
    ML anomalies      : 47

    Test 3 — Ping Sweep (nmap -sn)
    Packets captured  : 405
    Alerts raised     : 1
    Signatures fired  : SENSITIVE_PORT_ACCESS, PORT_SCAN
    ML anomalies      : 41

    Test 4 — Aggressive Full Scan (nmap -A)
    Packets captured  : 500
    Alerts raised     : 8
    Signatures fired  : All five signatures
    ML anomalies      :39

  6.3 Summary
    Total signature alerts : {sig_count}
    Total ML alerts        : {ml_count}
    Combined total         : {total_alerts}

  6.4 Limitations and Observations

    Reply Traffic: The NIDS captures both incoming attack traffic and
    the defender PC's reply packets. This causes the defender's own IP
    to appear in some alerts — a known challenge in passive monitoring
    systems. Production NIDS tools address this with TCP state tracking.

    Contamination Tuning: The Isolation Forest contamination parameter
    directly controls the ML detection rate. A value of 0.1 flags 10%
    of traffic as anomalous regardless of content. In production, this
    would be calibrated against a clean baseline capture.

    Signature Thresholds: Fixed thresholds (e.g. >= 10 unique ports)
    may produce false positives on networks with high legitimate
    port diversity, or false negatives on slow, low-and-slow scans.


7. DISCUSSION
{S}

  The results demonstrate that layered detection — combining signature
  rules with ML anomaly detection — provides broader coverage than
  either approach alone.

  Signature detection excels at:
    - Precisely identifying known attack patterns (port scan, SYN flood)
    - Producing human-readable, actionable alerts with clear evidence
    - Zero false negatives for attacks that exactly match a rule

  ML detection excels at:
    - Flagging statistically unusual traffic without prior rule knowledge
    - Detecting variations of known attacks that slightly evade signatures
    - Providing continuous anomaly scoring rather than binary decisions

  The PCA scatter plots visually confirm that Nmap attack traffic
  occupies a distinct region of feature space compared to normal
  browsing traffic — validating the ML approach's theoretical basis.


8. CONCLUSION
{S}

  This project successfully demonstrates a research-quality NIDS
  implementation that detects real network attacks using both
  signature-based and machine learning approaches. The system correctly
  identified all four Nmap attack scenarios and produced structured,
  logged alert output suitable for security analyst review.

  Future work could extend this system with:
    - Real-time streaming detection (currently batch after capture)
    - TCP connection state tracking to eliminate reply-traffic alerts
    - Supervised ML using labelled datasets such as NSL-KDD or CICIDS
    - A web-based dashboard for live alert monitoring
    - PCAP file import for offline forensic analysis


9. REFERENCES
{S}

  Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation forest.
    2008 Eighth IEEE International Conference on Data Mining, 413-422.

  Bejtlich, R. (2004). The Tao of Network Security Monitoring.
    Addison-Wesley.

  Scikit-learn developers (2024). sklearn.ensemble.IsolationForest.
    https://scikit-learn.org/stable/modules/generated/
    sklearn.ensemble.IsolationForest.html

  Nmap Project (2024). Nmap Network Scanning.
    https://nmap.org/book/

  Scapy Project (2024). Scapy Documentation.
    https://scapy.readthedocs.io/

{D}
  END OF REPORT
{D}
"""

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"[✓] Research report saved → results/NIDS_Research_Report.txt")
    return OUTPUT_FILE

if __name__ == '__main__':
    generate_report()