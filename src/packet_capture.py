"""
packet_capture.py
-----------------
Module C: Live packet capture engine using Scapy.
Captures packets from the active network interface,
parses key fields, and saves results to CSV.
"""

import csv
import os
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

# ── Configuration ─────────────────────────────────────────────────────────────

OUTPUT_DIR  = os.path.join(os.path.dirname(__file__), '..', 'data')
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'captured_packets.csv')

CSV_HEADERS = [
    'timestamp',
    'src_ip',
    'dst_ip',
    'protocol',
    'src_port',
    'dst_port',
    'packet_size'
]

# ── State ──────────────────────────────────────────────────────────────────────

captured_packets = []   # holds parsed packet dicts during the session

# ── Packet Parser ──────────────────────────────────────────────────────────────

def parse_packet(packet):
    """
    Callback fired by Scapy for every captured packet.
    Extracts fields and stores them in captured_packets list.
    """

    # Only process packets that have an IP layer
    if not packet.haslayer(IP):
        return

    # Determine protocol and extract ports where applicable
    if packet.haslayer(TCP):
        protocol = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = 'ICMP'
        src_port = None
        dst_port = None

    else:
        protocol = 'OTHER'
        src_port = None
        dst_port = None

    # Build the record
    record = {
        'timestamp'   : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip'      : packet[IP].src,
        'dst_ip'      : packet[IP].dst,
        'protocol'    : protocol,
        'src_port'    : src_port,
        'dst_port'    : dst_port,
        'packet_size' : len(packet)
    }

    captured_packets.append(record)

    # Print a live summary line to the terminal
    print(
        f"[{record['timestamp']}] "
        f"{record['protocol']:<6} "
        f"{record['src_ip']:>15} : {str(record['src_port']):<6} → "
        f"{record['dst_ip']:>15} : {str(record['dst_port']):<6} "
        f"| {record['packet_size']} bytes"
    )

# ── Save to CSV ────────────────────────────────────────────────────────────────

def save_to_csv(packets, filepath=OUTPUT_FILE):
    """
    Writes the list of parsed packet dicts to a CSV file.
    Appends to existing file if it already exists.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    file_exists = os.path.isfile(filepath)

    with open(filepath, mode='a', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)

        if not file_exists:
            writer.writeheader()    # write column names on first run only

        writer.writerows(packets)

    print(f"\n[✓] {len(packets)} packets saved to {filepath}")

# ── Main Capture Function ──────────────────────────────────────────────────────

def start_capture(packet_count=500, interface=None):   # ← updated: 50 → 500
    """
    Starts live packet capture.

    Parameters
    ----------
    packet_count : int
        Number of packets to capture before stopping automatically.
    interface : str or None
        Network interface name. None lets Scapy choose the default.
    """

    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM — Packet Capture Module")
    print("=" * 70)
    print(f"  Capturing {packet_count} packets. Press Ctrl+C to stop early.\n")

    start_time = time.time()

    try:
        sniff(
            iface=interface,
            prn=parse_packet,       # callback for each packet
            count=packet_count,     # stop after this many packets
            store=False             # don't store raw packets in memory
        )

    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user.")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n[✓] Capture complete in {elapsed}s — {len(captured_packets)} packets collected.")

    if captured_packets:
        save_to_csv(captured_packets)
    else:
        print("[!] No IP packets were captured. Check your network interface.")

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    start_capture(packet_count=500)   # ← updated: 50 → 500