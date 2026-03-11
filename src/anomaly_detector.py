"""
anomaly_detector.py
-------------------
Module H: Unsupervised ML anomaly detection using Isolation Forest.
Reads engineered features, trains a model, scores every packet,
flags anomalies, and produces a results visualisation.
"""

import os
import json
import numpy  as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.ensemble    import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR      = os.path.join(os.path.dirname(__file__), '..')
FEATURES_FILE = os.path.join(BASE_DIR, 'data', 'features.csv')
RAW_FILE      = os.path.join(BASE_DIR, 'data', 'captured_packets.csv')
RESULTS_DIR   = os.path.join(BASE_DIR, 'results')
ML_ALERTS_FILE = os.path.join(BASE_DIR, 'data', 'ml_alerts.json')

# ── Model Configuration ────────────────────────────────────────────────────────

MODEL_CONFIG = {
    # contamination: estimated proportion of anomalies in the data.
    # 0.1 means we expect ~10% of traffic to be anomalous.
    # Increase if you ran an Nmap scan during capture.
    'contamination'  : 0.1,

    # n_estimators: number of isolation trees.
    # More trees = more stable scores but slower training.
    'n_estimators'   : 200,

    # max_samples: number of samples per tree.
    # 'auto' uses min(256, n_samples).
    'max_samples'    : 'auto',

    # random_state: seed for reproducibility.
    'random_state'   : 42,
}

# ── Style (matches visualiser.py) ─────────────────────────────────────────────

STYLE = {
    'figure_bg' : '#0d1117',
    'axes_bg'   : '#161b22',
    'text'      : '#e6edf3',
    'grid'      : '#30363d',
    'normal'    : '#58a6ff',   # blue  — normal traffic
    'anomaly'   : '#f78166',   # red   — anomalous traffic
    'font_size' : 11,
    'title_size': 13,
}

# ── Helper: Apply Dark Theme ───────────────────────────────────────────────────

def apply_dark_theme(fig, axes):
    fig.patch.set_facecolor(STYLE['figure_bg'])
    for ax in (axes if hasattr(axes, '__iter__') else [axes]):
        ax.set_facecolor(STYLE['axes_bg'])
        ax.tick_params(colors=STYLE['text'], labelsize=STYLE['font_size'])
        ax.xaxis.label.set_color(STYLE['text'])
        ax.yaxis.label.set_color(STYLE['text'])
        ax.title.set_color(STYLE['text'])
        for spine in ax.spines.values():
            spine.set_edgecolor(STYLE['grid'])
        ax.grid(color=STYLE['grid'], linestyle='--',
                linewidth=0.5, alpha=0.7)

# ── Stage 1: Load and Validate Features ───────────────────────────────────────

def load_features(features_file=FEATURES_FILE):
    """
    Loads the engineered feature CSV.
    Validates that enough data exists for meaningful ML.
    Returns a clean numeric DataFrame.
    """
    if not os.path.exists(features_file):
        raise FileNotFoundError(
            f"Features file not found: {features_file}\n"
            f"Run feature_extractor.py first."
        )

    df = pd.read_csv(features_file)
    print(f"[✓] Loaded features: {df.shape[0]} rows × {df.shape[1]} columns")

    if df.shape[0] < 20:
        raise ValueError(
            f"Only {df.shape[0]} packets found. "
            f"Capture at least 50 packets for meaningful ML results."
        )

    # Drop any remaining non-numeric columns defensively
    df = df.select_dtypes(include=[np.number])

    # Fill any NaN values with column median
    df = df.fillna(df.median())

    print(f"[✓] Feature matrix ready: {df.shape}")
    print(f"    Features used: {list(df.columns)}")
    return df

# ── Stage 2: Scale Features ────────────────────────────────────────────────────

def scale_features(df):
    """
    Applies StandardScaler to normalise all features to
    zero mean and unit variance.

    This is critical for Isolation Forest — without scaling,
    high-magnitude features like total_bytes would dominate
    the anomaly scores unfairly.
    """
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)
    print(f"[✓] Features scaled with StandardScaler")
    return X_scaled, scaler

# ── Stage 3: Train Isolation Forest ───────────────────────────────────────────

def train_model(X_scaled, config=MODEL_CONFIG):
    """
    Trains an Isolation Forest on the scaled feature matrix.
    Returns the fitted model.
    """
    model = IsolationForest(
        n_estimators = config['n_estimators'],
        contamination= config['contamination'],
        max_samples  = config['max_samples'],
        random_state = config['random_state'],
        n_jobs       = -1,   # use all CPU cores
    )

    model.fit(X_scaled)
    print(f"[✓] Isolation Forest trained")
    print(f"    Trees      : {config['n_estimators']}")
    print(f"    Contamination : {config['contamination'] * 100:.0f}%")
    return model

# ── Stage 4: Predict and Score ─────────────────────────────────────────────────

def predict_anomalies(model, X_scaled):
    """
    Generates predictions and anomaly scores for every packet.

    predict() returns:
       1  → normal
      -1  → anomaly

    decision_function() returns a continuous score:
      Positive → more normal
      Negative → more anomalous
    """
    predictions = model.predict(X_scaled)          # 1 or -1
    scores      = model.decision_function(X_scaled) # continuous score

    n_anomalies = (predictions == -1).sum()
    n_normal    = (predictions ==  1).sum()

    print(f"[✓] Predictions complete")
    print(f"    Normal    : {n_normal}  packets")
    print(f"    Anomalous : {n_anomalies} packets "
          f"({n_anomalies/len(predictions)*100:.1f}%)")

    return predictions, scores

# ── Stage 5: Build ML Alert Records ───────────────────────────────────────────

def build_ml_alerts(predictions, scores, raw_df):
    """
    Pairs ML anomaly predictions with raw packet data
    to produce structured alert records.
    """
    alerts = []

    # Align raw_df index with predictions (may differ in length
    # if feature extraction dropped rows)
    n = min(len(predictions), len(raw_df))

    for i in range(n):
        if predictions[i] == -1:
            score  = float(scores[i])
            row    = raw_df.iloc[i]

            # Severity based on how negative the score is
            if score < -0.15:
                severity = 'CRITICAL'
            elif score < -0.10:
                severity = 'HIGH'
            elif score < -0.05:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

            alert = {
                'timestamp'   : str(row.get('timestamp', 'N/A')),
                'attack_type' : 'ML_ANOMALY',
                'severity'    : severity,
                'src_ip'      : str(row.get('src_ip', 'N/A')),
                'dst_ip'      : str(row.get('dst_ip', 'N/A')),
                'protocol'    : str(row.get('protocol', 'N/A')),
                'dst_port'    : str(row.get('dst_port', 'N/A')),
                'packet_size' : int(row.get('packet_size', 0)),
                'description' : (
                    f"ML anomaly detected. Isolation Forest score: "
                    f"{score:.4f}. Packet deviates significantly "
                    f"from baseline normal traffic pattern."
                ),
                'evidence'    : {
                    'anomaly_score'    : round(score, 4),
                    'threshold'        : 0.0,
                    'packet_index'     : i,
                },
            }
            alerts.append(alert)

    return alerts

# ── Stage 6: PCA Visualisation ────────────────────────────────────────────────

def plot_anomaly_scatter(X_scaled, predictions, scores):
    """
    Reduces the high-dimensional feature space to 2D using PCA,
    then plots normal vs anomalous packets as a scatter chart.

    PCA (Principal Component Analysis) finds the two directions
    of maximum variance in the data — giving the best 2D view
    of how anomalies separate from normal traffic.
    """
    print("[*] Generating PCA scatter plot...")

    pca        = PCA(n_components=2, random_state=42)
    X_2d       = pca.fit_transform(X_scaled)
    variance   = pca.explained_variance_ratio_

    normal_mask  = predictions ==  1
    anomaly_mask = predictions == -1

    fig, ax = plt.subplots(figsize=(10, 7))
    apply_dark_theme(fig, ax)

    # Normal points
    ax.scatter(
        X_2d[normal_mask, 0], X_2d[normal_mask, 1],
        c     = STYLE['normal'],
        alpha = 0.5,
        s     = 20,
        label = f'Normal ({normal_mask.sum()} packets)',
    )

    # Anomalous points — larger and more opaque so they stand out
    ax.scatter(
        X_2d[anomaly_mask, 0], X_2d[anomaly_mask, 1],
        c      = STYLE['anomaly'],
        alpha  = 0.9,
        s      = 60,
        marker = 'X',
        label  = f'Anomaly ({anomaly_mask.sum()} packets)',
        zorder = 5,
    )

    ax.set_xlabel(
        f'Principal Component 1 ({variance[0]*100:.1f}% variance)',
        fontsize=STYLE['font_size']
    )
    ax.set_ylabel(
        f'Principal Component 2 ({variance[1]*100:.1f}% variance)',
        fontsize=STYLE['font_size']
    )
    ax.set_title(
        'ML Anomaly Detection — PCA Feature Space\n'
        'Red × marks indicate packets flagged as anomalous',
        fontsize   = STYLE['title_size'],
        fontweight = 'bold',
        color      = STYLE['text'],
    )
    ax.legend(
        framealpha = 0,
        labelcolor = STYLE['text'],
        fontsize   = STYLE['font_size'],
    )

    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, 'chart5_ml_anomaly_scatter.png')
    fig.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=STYLE['figure_bg'])
    plt.close(fig)
    print(f"  [✓] Saved → results/chart5_ml_anomaly_scatter.png")
    return path

# ── Stage 7: Anomaly Score Timeline ───────────────────────────────────────────

def plot_score_timeline(scores, predictions):
    """
    Line chart of anomaly scores over packet index (time order).
    Scores below 0 indicate anomalies.
    Clear dips show exactly when anomalous bursts occurred.
    """
    print("[*] Generating anomaly score timeline...")

    fig, ax = plt.subplots(figsize=(11, 5))
    apply_dark_theme(fig, ax)

    indices = np.arange(len(scores))

    ax.plot(
        indices, scores,
        color     = STYLE['normal'],
        linewidth = 0.9,
        alpha     = 0.8,
        label     = 'Anomaly score',
    )

    # Shade anomalous regions
    ax.fill_between(
        indices, scores, 0,
        where  = scores < 0,
        color  = STYLE['anomaly'],
        alpha  = 0.4,
        label  = 'Anomalous region',
    )

    # Decision boundary
    ax.axhline(y=0, color=STYLE['anomaly'], linestyle='--',
               linewidth=1.2, label='Decision boundary (0)')

    ax.set_xlabel('Packet Index (time order)', fontsize=STYLE['font_size'])
    ax.set_ylabel('Anomaly Score',             fontsize=STYLE['font_size'])
    ax.set_title(
        'Isolation Forest Anomaly Scores Over Time\n'
        'Scores below 0 indicate anomalous packets',
        fontsize   = STYLE['title_size'],
        fontweight = 'bold',
        color      = STYLE['text'],
    )
    ax.legend(
        framealpha = 0,
        labelcolor = STYLE['text'],
        fontsize   = STYLE['font_size'],
    )

    path = os.path.join(RESULTS_DIR, 'chart6_anomaly_score_timeline.png')
    fig.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=STYLE['figure_bg'])
    plt.close(fig)
    print(f"  [✓] Saved → results/chart6_anomaly_score_timeline.png")
    return path

# ── Main Pipeline ──────────────────────────────────────────────────────────────

def run_anomaly_detection(
    features_file = FEATURES_FILE,
    raw_file      = RAW_FILE,
    output_file   = ML_ALERTS_FILE,
):
    """
    Full ML anomaly detection pipeline:
    1. Load features
    2. Scale
    3. Train Isolation Forest
    4. Predict anomalies
    5. Build alert records
    6. Generate visualisations
    7. Save ML alerts JSON
    """
    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM — ML Anomaly Detection")
    print("=" * 70)
    print()

    # ── Load
    df_features = load_features(features_file)
    raw_df      = pd.read_csv(raw_file) if os.path.exists(raw_file) else pd.DataFrame()

    print()

    # ── Scale
    X_scaled, scaler = scale_features(df_features)
    print()

    # ── Train
    model = train_model(X_scaled)
    print()

    # ── Predict
    predictions, scores = predict_anomalies(model, X_scaled)
    print()

    # ── Build alerts
    ml_alerts = build_ml_alerts(predictions, scores, raw_df)

    # ── Visualise
    print("  Generating ML visualisations...")
    print(f"  {'─' * 60}")
    plot_anomaly_scatter(X_scaled, predictions, scores)
    plot_score_timeline(scores, predictions)
    print()

    # ── Save alerts
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(ml_alerts, f, indent=2)

    # ── Final summary
    severity_counts = {}
    for a in ml_alerts:
        severity_counts[a['severity']] = severity_counts.get(a['severity'], 0) + 1

    print("=" * 70)
    print("  ML DETECTION SUMMARY")
    print("=" * 70)
    print(f"  Total packets analysed : {len(predictions)}")
    print(f"  Normal packets         : {(predictions == 1).sum()}")
    print(f"  Anomalous packets      : {(predictions == -1).sum()}")
    print(f"  Detection rate         : "
          f"{(predictions == -1).sum() / len(predictions) * 100:.1f}%")

    if severity_counts:
        print(f"\n  ML Alert Severity Breakdown:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                bar = '█' * min(count, 30)
                print(f"    {sev:<10} : {count:>4}  {bar}")

    print(f"\n  Charts saved:")
    print(f"    results/chart5_ml_anomaly_scatter.png")
    print(f"    results/chart6_anomaly_score_timeline.png")
    print(f"\n[✓] ML alerts saved to {output_file}")

    return predictions, scores, ml_alerts

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    run_anomaly_detection()