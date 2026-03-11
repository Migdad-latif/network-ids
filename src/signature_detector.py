"""
signature_detector.py
---------------------
Module E: Signature-based attack detection engine.
Applies rule-based signatures to extracted features
and returns structured alerts with severity levels.
"""

import os
import json
import pandas as pd
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.join(os.path.dirname(__file__), '..')
FEATURES_FILE = os.path.join(BASE_DIR, 'data', 'features.csv')
RAW_FILE      = os.path.join(BASE_DIR, 'data', 'captured_packets.csv')
OUTPUT_FILE   = os.path.join(BASE_DIR, 'data', 'alerts.json')

# ── Thresholds (tunable) ───────────────────────────────────────────────────────

THRESHOLDS = {
    'port_scan_unique_ports'   : 10,      # unique dst ports from one src
    'syn_flood_packet_count'   : 20,      # packets from one src in session
    'syn_flood_max_avg_size'   : 100,     # bytes — SYN packets are tiny
    'dns_amp_packet_count'     : 10,      # UDP/53 packets from one src
    'exfil_total_bytes'        : 500000,  # 500 KB outbound threshold
}

# Ports considered sensitive / high value targets
SENSITIVE_PORTS = {
    22   : 'SSH',
    23   : 'Telnet',
    25   : 'SMTP',
    53   : 'DNS',
    445  : 'SMB',
    3306 : 'MySQL',
    3389 : 'RDP',
    8080 : 'HTTP-Alt',
}

# ── Alert Builder ──────────────────────────────────────────────────────────────

def make_alert(attack_type, severity, src_ip, description, evidence):
    """
    Returns a structured alert dictionary.

    Parameters
    ----------
    attack_type : str   — name of the detected attack pattern
    severity    : str   — 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'
    src_ip      : str   — source IP that triggered the rule
    description : str   — human-readable explanation
    evidence    : dict  — raw metric values that triggered the rule
    """
    return {
        'timestamp'   : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'attack_type' : attack_type,
        'severity'    : severity,
        'src_ip'      : src_ip,
        'description' : description,
        'evidence'    : evidence,
    }

# ── Signature 1 — Port Scan Detection ─────────────────────────────────────────

def detect_port_scan(raw_df):
    """
    Detects port scan behaviour.
    Rule: one source IP sends packets to >= THRESHOLD unique destination ports.
    """
    alerts = []

    scan_stats = raw_df.groupby('src_ip')['dst_port'].nunique().reset_index()
    scan_stats.columns = ['src_ip', 'unique_dst_ports']

    flagged = scan_stats[
        scan_stats['unique_dst_ports'] >= THRESHOLDS['port_scan_unique_ports']
    ]

    for _, row in flagged.iterrows():
        alerts.append(make_alert(
            attack_type = 'PORT_SCAN',
            severity    = 'HIGH',
            src_ip      = row['src_ip'],
            description = (
                f"Possible port scan detected. Source contacted "
                f"{row['unique_dst_ports']} unique destination ports."
            ),
            evidence = {
                'unique_dst_ports' : int(row['unique_dst_ports']),
                'threshold'        : THRESHOLDS['port_scan_unique_ports'],
            }
        ))

    return alerts

# ── Signature 2 — SYN Flood Detection ─────────────────────────────────────────

def detect_syn_flood(raw_df, feat_df):
    """
    Detects SYN flood / DoS behaviour.
    Rule: source sends high packet volume AND average packet size is tiny.
    Small size indicates bare TCP SYN packets with no payload.
    """
    alerts = []

    # Aggregate from raw packets
    stats = raw_df.groupby('src_ip').agg(
        packet_count = ('packet_size', 'count'),
        avg_size     = ('packet_size', 'mean'),
    ).reset_index()

    flagged = stats[
        (stats['packet_count'] >= THRESHOLDS['syn_flood_packet_count']) &
        (stats['avg_size']     <= THRESHOLDS['syn_flood_max_avg_size'])
    ]

    for _, row in flagged.iterrows():
        alerts.append(make_alert(
            attack_type = 'SYN_FLOOD',
            severity    = 'CRITICAL',
            src_ip      = row['src_ip'],
            description = (
                f"Possible SYN flood. Source sent {int(row['packet_count'])} "
                f"packets with average size {round(row['avg_size'], 1)} bytes."
            ),
            evidence = {
                'packet_count'    : int(row['packet_count']),
                'avg_packet_size' : round(float(row['avg_size']), 2),
                'thresholds'      : {
                    'min_packets'  : THRESHOLDS['syn_flood_packet_count'],
                    'max_avg_size' : THRESHOLDS['syn_flood_max_avg_size'],
                }
            }
        ))

    return alerts

# ── Signature 3 — DNS Amplification Detection ──────────────────────────────────

def detect_dns_amplification(raw_df):
    """
    Detects DNS amplification attack behaviour.
    Rule: source sends many UDP packets to port 53.
    Attackers spoof IPs and use open resolvers to amplify traffic.
    """
    alerts = []

    dns_traffic = raw_df[
        (raw_df['protocol'] == 'UDP') &
        (raw_df['dst_port'] == 53)
    ]

    dns_stats = dns_traffic.groupby('src_ip').size().reset_index(name='dns_count')

    flagged = dns_stats[
        dns_stats['dns_count'] >= THRESHOLDS['dns_amp_packet_count']
    ]

    for _, row in flagged.iterrows():
        alerts.append(make_alert(
            attack_type = 'DNS_AMPLIFICATION',
            severity    = 'HIGH',
            src_ip      = row['src_ip'],
            description = (
                f"Possible DNS amplification. Source sent "
                f"{row['dns_count']} UDP packets to port 53."
            ),
            evidence = {
                'dns_packet_count' : int(row['dns_count']),
                'threshold'        : THRESHOLDS['dns_amp_packet_count'],
                'protocol'         : 'UDP',
                'dst_port'         : 53,
            }
        ))

    return alerts

# ── Signature 4 — Sensitive Port Access ───────────────────────────────────────

def detect_sensitive_port_access(raw_df):
    """
    Detects access attempts to high-value service ports.
    Rule: any packet destined for a port in SENSITIVE_PORTS.
    Each unique src_ip → sensitive_port pair generates one alert.
    """
    alerts = []

    sensitive_traffic = raw_df[raw_df['dst_port'].isin(SENSITIVE_PORTS.keys())]

    # One alert per unique (src_ip, dst_port) pair — avoid duplicates
    pairs = sensitive_traffic[['src_ip', 'dst_port']].drop_duplicates()

    for _, row in pairs.iterrows():
        port     = int(row['dst_port'])
        service  = SENSITIVE_PORTS.get(port, 'Unknown')
        severity = 'CRITICAL' if port in {22, 3389, 445} else 'MEDIUM'

        alerts.append(make_alert(
            attack_type = 'SENSITIVE_PORT_ACCESS',
            severity    = severity,
            src_ip      = row['src_ip'],
            description = (
                f"Access attempt to sensitive port {port} ({service})."
            ),
            evidence = {
                'dst_port' : port,
                'service'  : service,
            }
        ))

    return alerts

# ── Signature 5 — Large Outbound Transfer ─────────────────────────────────────

def detect_exfiltration(raw_df):
    """
    Detects potential data exfiltration.
    Rule: a private source IP sends total_bytes above threshold
    to public (non-private) destination IPs.
    """
    import ipaddress

    alerts = []

    def is_private(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    # Filter outbound: private src → public dst
    outbound = raw_df[
        raw_df['src_ip'].apply(is_private) &
        ~raw_df['dst_ip'].apply(is_private)
    ]

    if outbound.empty:
        return alerts

    stats = outbound.groupby('src_ip').agg(
        total_bytes = ('packet_size', 'sum')
    ).reset_index()

    flagged = stats[stats['total_bytes'] >= THRESHOLDS['exfil_total_bytes']]

    for _, row in flagged.iterrows():
        alerts.append(make_alert(
            attack_type = 'LARGE_OUTBOUND_TRANSFER',
            severity    = 'HIGH',
            src_ip      = row['src_ip'],
            description = (
                f"Large outbound data transfer detected. "
                f"{int(row['total_bytes']):,} bytes sent to public IPs."
            ),
            evidence = {
                'total_bytes_sent' : int(row['total_bytes']),
                'threshold_bytes'  : THRESHOLDS['exfil_total_bytes'],
            }
        ))

    return alerts

# ── Alert Printer ──────────────────────────────────────────────────────────────

SEVERITY_COLOURS = {
    'LOW'      : '',
    'MEDIUM'   : '',
    'HIGH'     : '',
    'CRITICAL' : '',
}

SEVERITY_LABEL = {
    'LOW'      : '[ LOW      ]',
    'MEDIUM'   : '[ MEDIUM   ]',
    'HIGH'     : '[ HIGH     ]',
    'CRITICAL' : '[ CRITICAL ]',
}

def print_alert(alert):
    label = SEVERITY_LABEL.get(alert['severity'], '[  ???  ]')
    print(f"\n  {label} {alert['attack_type']}")
    print(f"  {'─' * 60}")
    print(f"  Source IP   : {alert['src_ip']}")
    print(f"  Description : {alert['description']}")
    print(f"  Evidence    : {alert['evidence']}")
    print(f"  Timestamp   : {alert['timestamp']}")

# ── Main Detection Runner ──────────────────────────────────────────────────────

def run_detection(
    raw_file=RAW_FILE,
    features_file=FEATURES_FILE,
    output_file=OUTPUT_FILE
):
    """
    Runs all signature detections against the captured data.
    Saves all alerts to alerts.json.
    """
    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM — Signature Detection Module")
    print("=" * 70)

    # ── Load data
    if not os.path.exists(raw_file):
        print(f"[✗] Raw packet file not found: {raw_file}")
        return []

    raw_df  = pd.read_csv(raw_file)
    feat_df = pd.read_csv(features_file) if os.path.exists(features_file) else pd.DataFrame()

    # Fill missing port values with 0 for numeric operations
    raw_df['dst_port'] = pd.to_numeric(raw_df['dst_port'], errors='coerce').fillna(0).astype(int)
    raw_df['src_port'] = pd.to_numeric(raw_df['src_port'], errors='coerce').fillna(0).astype(int)

    print(f"[✓] Loaded {len(raw_df)} packets for analysis\n")
    print(f"  Running 5 signature checks...")
    print(f"  {'─' * 60}")

    # ── Run all signatures
    all_alerts = []
    all_alerts += detect_port_scan(raw_df)
    all_alerts += detect_syn_flood(raw_df, feat_df)
    all_alerts += detect_dns_amplification(raw_df)
    all_alerts += detect_sensitive_port_access(raw_df)
    all_alerts += detect_exfiltration(raw_df)

    # ── Print results
    print(f"\n  {'═' * 60}")
    print(f"  DETECTION RESULTS — {len(all_alerts)} alert(s) raised")
    print(f"  {'═' * 60}")

    if all_alerts:
        for alert in all_alerts:
            print_alert(alert)
    else:
        print("\n  [✓] No attacks detected in current capture session.")
        print("      This is expected for normal browsing traffic.")
        print("      Alerts will fire when Nmap attack tests run in Step I.")

    # ── Save alerts to JSON
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(all_alerts, f, indent=2)

    print(f"\n[✓] {len(all_alerts)} alert(s) saved to {output_file}")

    # ── Summary table
    if all_alerts:
        severity_counts = {}
        for a in all_alerts:
            severity_counts[a['severity']] = severity_counts.get(a['severity'], 0) + 1
        print("\n  Severity Summary:")
        for sev, count in sorted(severity_counts.items()):
            print(f"    {SEVERITY_LABEL[sev]} : {count} alert(s)")

    return all_alerts

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    run_detection()