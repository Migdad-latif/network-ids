# 🛡️ Network Intrusion Detection System (NIDS)

> A research-quality Network Intrusion Detection System built with Python,
> Scapy, and Machine Learning — detecting real Nmap attacks using both
> rule-based signatures and Isolation Forest anomaly detection.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5-green)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.x-orange)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## 📋 Overview

This NIDS captures live network traffic, extracts 22 engineered features
from each packet, detects known attack signatures, flags statistical
anomalies using machine learning, logs all alerts to rotating files, and
visualises traffic patterns across six analytical charts.

The system was tested against four real Nmap attack scenarios and
successfully detected all of them.

---

## 🏗️ Architecture
```
Network Traffic
      ↓
packet_capture.py    — Scapy live capture
      ↓
feature_extractor.py — 22 engineered features
      ↓
┌─────────────────────┬──────────────────────┐
│ signature_detector  │  anomaly_detector    │
│ 5 rule signatures   │  Isolation Forest    │
└─────────────────────┴──────────────────────┘
      ↓
alert_logger.py      — rotating logs + report
      ↓
visualiser.py        — 6 Matplotlib charts
```

---

## 🔍 Detection Capabilities

| Signature | Attack Type | Severity |
|---|---|---|
| Port Scan | >= 10 unique dst ports from one IP | HIGH |
| SYN Flood | High packet volume, tiny avg size | CRITICAL |
| DNS Amplification | High UDP/53 volume from one IP | HIGH |
| Sensitive Port Access | SSH, RDP, SMB, MySQL access | CRITICAL |
| Large Outbound Transfer | > 500KB outbound from private IP | HIGH |
| ML Anomaly | Isolation Forest outlier detection | Variable |

---

## 📁 Repository Structure
```
network-ids/
├── README.md
├── requirements.txt
├── src/
│   ├── packet_capture.py      # Module C — Scapy capture engine
│   ├── feature_extractor.py   # Module D — Feature engineering
│   ├── signature_detector.py  # Module E — Rule-based detection
│   ├── alert_logger.py        # Module F — Rotating alert logger
│   ├── visualiser.py          # Module G — Traffic charts
│   ├── anomaly_detector.py    # Module H — Isolation Forest ML
│   ├── run_pipeline.py        # Full pipeline runner
│   ├── generate_diagram.py    # Architecture diagram generator
│   └── generate_report.py     # Research report generator
├── data/
│   ├── captured_packets.csv   # Raw packet capture
│   ├── features.csv           # Engineered feature matrix
│   ├── alerts.json            # Signature detection alerts
│   └── ml_alerts.json         # ML anomaly alerts
├── logs/
│   └── nids.log               # Rotating alert log
├── results/
│   ├── chart1_protocol_distribution.png
│   ├── chart2_packet_size_distribution.png
│   ├── chart3_traffic_timeline.png
│   ├── chart4_top_talkers.png
│   ├── chart5_ml_anomaly_scatter.png
│   ├── chart6_anomaly_score_timeline.png
│   ├── architecture_diagram.png
│   ├── alert_report.txt
│   └── NIDS_Research_Report.txt
├── docs/
└── tests/
```

---

## ⚡ Quick Start

### Prerequisites
- Windows 10/11
- Python 3.11
- [Npcap](https://npcap.com) installed
- Administrator privileges (for packet capture)

### Installation
```bash
git clone https://github.com/YourUsername/network-ids.git
cd network-ids
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Run Packet Capture
```bash
# Run VS Code as Administrator, then:
python src\packet_capture.py
```

### Run Full Detection Pipeline
```bash
python src\run_pipeline.py
```

### View Results
```bash
explorer results
```

---

## 📊 Results

The system was tested against four Nmap attack scenarios:

| Attack | Command | Signatures Fired |
|---|---|---|
| SYN Stealth Scan | `nmap -sS` | PORT_SCAN, SENSITIVE_PORT_ACCESS |
| Version Scan | `nmap -sV` | SENSITIVE_PORT_ACCESS, PORT_SCAN |
| Ping Sweep | `nmap -sn` | ML_ANOMALY |
| Aggressive Scan | `nmap -A` | All signatures |

---

## 🤖 Machine Learning

- **Algorithm**: Isolation Forest (Liu et al., 2008)
- **Features**: 22 engineered numerical features
- **Scaling**: StandardScaler
- **Visualisation**: PCA 2D projection
- **Contamination**: 10% (tunable)

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Packet Capture | Scapy 2.5 |
| ML Detection | Scikit-learn IsolationForest |
| Visualisation | Matplotlib |
| Data Processing | Pandas, NumPy |
| Language | Python 3.11 |
| Version Control | Git / GitHub |

---

## 📄 Documentation

- [`results/NIDS_Research_Report.txt`](results/NIDS_Research_Report.txt) — Full research report
- [`results/architecture_diagram.png`](results/architecture_diagram.png) — System architecture
- [`results/alert_report.txt`](results/alert_report.txt) — Sample alert session report

---

## ⚠️ Ethical Notice

This system is built for **educational and research purposes only**.
All attack testing was performed on a private home network against
machines owned by the author. Never run network scans against systems
you do not own or have explicit permission to test.

---

## 📚 References

- Liu, F. T., et al. (2008). Isolation Forest. IEEE ICDM.
- Bejtlich, R. (2004). The Tao of Network Security Monitoring.
- Scikit-learn Documentation. https://scikit-learn.org
- Nmap Reference Guide. https://nmap.org/book/
## Author
Migdad latif shaw-(https://github.com/Migdad-latif/network-ids)
The open university Bsc CyberSecurity

## License
MIT License