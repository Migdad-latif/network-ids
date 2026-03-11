"""
feature_extractor.py
--------------------
Module D: Feature extraction pipeline.
Reads raw captured_packets.csv, engineers features,
and saves a clean ML-ready dataset to data/features.csv
"""

import os
import ipaddress
import pandas as pd
import numpy as np

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
INPUT_FILE  = os.path.join(BASE_DIR, 'data', 'captured_packets.csv')
OUTPUT_FILE = os.path.join(BASE_DIR, 'data', 'features.csv')

# ── Helper: IP Classification ──────────────────────────────────────────────────

def is_private_ip(ip_str):
    """
    Returns 1 if the IP address is in a private RFC-1918 range,
    0 if public, -1 if the string is not a valid IP.
    Private ranges: 10.x, 172.16–31.x, 192.168.x
    """
    try:
        return 1 if ipaddress.ip_address(ip_str).is_private else 0
    except ValueError:
        return -1

# ── Helper: Port Classification ────────────────────────────────────────────────

def classify_port(port):
    """
    Classifies a port number into three categories:
      well_known  → 0–1023   (HTTP, HTTPS, DNS, SSH, etc.)
      registered  → 1024–49151
      ephemeral   → 49152–65535 (temporary client-side ports)
    Returns 'unknown' if port is missing.
    """
    try:
        port = int(port)
        if port <= 1023:
            return 'well_known'
        elif port <= 49151:
            return 'registered'
        else:
            return 'ephemeral'
    except (ValueError, TypeError):
        return 'unknown'

# ── Helper: Packet Size Category ──────────────────────────────────────────────

def size_category(size):
    """
    Buckets packet size into:
      small  → < 100 bytes   (control packets, ACKs)
      medium → 100–999 bytes (typical web traffic)
      large  → ≥ 1000 bytes  (file transfers, video)
    """
    if size < 100:
        return 'small'
    elif size < 1000:
        return 'medium'
    else:
        return 'large'

# ── Core: Per-Packet Features ──────────────────────────────────────────────────

def extract_base_features(df):
    """
    Derives per-packet features from raw fields.
    These features describe a single packet in isolation.
    """
    print("[*] Extracting base per-packet features...")

    # ── Timestamp features
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour']      = df['timestamp'].dt.hour
    df['minute']    = df['timestamp'].dt.minute
    df['second']    = df['timestamp'].dt.second

    # ── IP features
    df['is_private_src'] = df['src_ip'].apply(is_private_ip)
    df['is_private_dst'] = df['dst_ip'].apply(is_private_ip)

    # Flag packets going from private → public (potential exfiltration)
    df['outbound'] = (
        (df['is_private_src'] == 1) & (df['is_private_dst'] == 0)
    ).astype(int)

    # Flag packets coming from public → private (potential intrusion)
    df['inbound'] = (
        (df['is_private_src'] == 0) & (df['is_private_dst'] == 1)
    ).astype(int)

    # ── Port features
    df['src_port_class'] = df['src_port'].apply(classify_port)
    df['dst_port_class'] = df['dst_port'].apply(classify_port)

    # Common attack-relevant destination ports (flag as 1 if matched)
    SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080}
    df['dst_is_sensitive'] = df['dst_port'].apply(
        lambda p: 1 if p in SENSITIVE_PORTS else 0
    )

    # ── Packet size features
    df['size_cat'] = df['packet_size'].apply(size_category)

    # ── Protocol: one-hot encode
    protocol_dummies = pd.get_dummies(df['protocol'], prefix='proto')
    df = pd.concat([df, protocol_dummies], axis=1)

    # ── Port class: one-hot encode dst port class
    dst_port_dummies = pd.get_dummies(df['dst_port_class'], prefix='dst_port')
    df = pd.concat([df, dst_port_dummies], axis=1)

    return df

# ── Core: Aggregate (Per-Source-IP) Features ──────────────────────────────────

def extract_aggregate_features(df):
    """
    Derives features that aggregate behaviour across all packets
    from the same source IP. These are critical for detecting
    port scans, floods, and other volume-based attacks.
    """
    print("[*] Extracting aggregate per-source-IP features...")

    agg = df.groupby('src_ip').agg(
        packet_count   = ('packet_size', 'count'),
        avg_pkt_size   = ('packet_size', 'mean'),
        std_pkt_size   = ('packet_size', 'std'),
        total_bytes    = ('packet_size', 'sum'),
        unique_dst_ips = ('dst_ip', 'nunique'),
        unique_dst_ports = ('dst_port', 'nunique'),
    ).reset_index()

    # High unique_dst_ports from one source → classic port scan indicator
    agg['avg_pkt_size']    = agg['avg_pkt_size'].round(2)
    agg['std_pkt_size']    = agg['std_pkt_size'].fillna(0).round(2)

    # Merge aggregate features back onto each packet row
    df = df.merge(agg, on='src_ip', suffixes=('', '_agg'))

    return df

# ── Core: Encode Categoricals to Integers ─────────────────────────────────────

def encode_categoricals(df):
    """
    Converts any remaining string columns to numeric codes
    so the DataFrame is fully numeric for ML consumption.
    """
    print("[*] Encoding categorical columns to integers...")

    # size_cat → integer code
    size_map = {'small': 0, 'medium': 1, 'large': 2}
    df['size_cat_encoded'] = df['size_cat'].map(size_map)

    return df

# ── Core: Select Final Feature Columns ────────────────────────────────────────

def select_features(df):
    """
    Picks only the columns that will be passed to ML models.
    Drops raw strings (IPs, timestamps) — they've already been
    encoded into numeric features above.
    """
    desired = [
        # Time
        'hour', 'minute', 'second',
        # IP-level
        'is_private_src', 'is_private_dst', 'outbound', 'inbound',
        # Port-level
        'dst_is_sensitive',
        # Packet size
        'packet_size', 'size_cat_encoded',
        # Aggregate behaviour
        'packet_count', 'avg_pkt_size', 'std_pkt_size',
        'total_bytes', 'unique_dst_ips', 'unique_dst_ports',
    ]

    # Add any one-hot columns that were created (proto_TCP etc.)
    one_hot_cols = [c for c in df.columns if c.startswith('proto_') or
                                             c.startswith('dst_port_')]
    desired += one_hot_cols

    # Keep only columns that actually exist (safe for small datasets)
    available = [c for c in desired if c in df.columns]

    return df[available]

# ── Main Pipeline ──────────────────────────────────────────────────────────────

def run_extraction(input_file=INPUT_FILE, output_file=OUTPUT_FILE):
    """
    Full feature extraction pipeline.
    Reads raw CSV → engineers features → saves features CSV.
    """
    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM — Feature Extraction Module")
    print("=" * 70)

    # ── Load raw data
    if not os.path.exists(input_file):
        print(f"[✗] Input file not found: {input_file}")
        print("    Run packet_capture.py first to generate captured_packets.csv")
        return

    df = pd.read_csv(input_file)
    print(f"[✓] Loaded {len(df)} packets from {input_file}")
    print(f"    Columns: {list(df.columns)}\n")

    # ── Run pipeline stages
    df = extract_base_features(df)
    df = extract_aggregate_features(df)
    df = encode_categoricals(df)
    df_features = select_features(df)

    # ── Save
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df_features.to_csv(output_file, index=False)

    print(f"\n[✓] Feature extraction complete.")
    print(f"    Input  rows    : {len(df)}")
    print(f"    Output columns : {len(df_features.columns)}")
    print(f"    Output shape   : {df_features.shape}")
    print(f"    Saved to       : {output_file}")
    print(f"\n  Feature columns extracted:")
    for col in df_features.columns:
        print(f"    • {col}")

    return df_features

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    run_extraction()