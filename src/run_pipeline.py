"""
run_pipeline.py
---------------
Full NIDS pipeline runner.
Executes all detection modules in sequence against
the current captured_packets.csv data.
"""

import os
import sys

# Add src to path so modules import correctly
sys.path.insert(0, os.path.dirname(__file__))

from feature_extractor  import run_extraction
from signature_detector import run_detection
from anomaly_detector   import run_anomaly_detection
from alert_logger       import run_logging
from visualiser         import run_visualisation

def run_full_pipeline():
    print("\n" + "█" * 70)
    print("  NIDS — FULL DETECTION PIPELINE")
    print("█" * 70 + "\n")

    print("▶  Stage 1/5 — Feature Extraction")
    run_extraction()

    print("\n▶  Stage 2/5 — Signature Detection")
    run_detection()

    print("\n▶  Stage 3/5 — ML Anomaly Detection")
    run_anomaly_detection()

    print("\n▶  Stage 4/5 — Alert Logging")
    run_logging()

    print("\n▶  Stage 5/5 — Visualisation")
    run_visualisation()

    print("\n" + "█" * 70)
    print("  PIPELINE COMPLETE")
    print("  Check results/ for charts and logs/ for alert report")
    print("█" * 70 + "\n")

if __name__ == '__main__':
    run_full_pipeline()