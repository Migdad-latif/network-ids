"""
live_detector.py
----------------
Real-time per-packet signature detection.
Lightweight version of signature_detector.py
designed to run on every packet as it arrives.
"""

import ipaddress
from datetime import datetime
from collections import defaultdict

# ── Sensitive ports ────────────────────────────────────────────────────────────

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

# ── Thresholds ─────────────────────────────────────────────────────────────────

THRESHOLDS = {
    'port_scan_unique_ports' : 10,
    'syn_flood_packet_count' : 20,
    'syn_flood_max_avg_size' : 100,
    'dns_amp_count'          : 10,
}

class LiveDetector:
    """
    Stateful per-packet detector.
    Maintains rolling counters per source IP and fires
    alerts the moment a threshold is crossed.
    Each threshold fires only ONCE per source IP per
    session to avoid alert flooding.
    """

    def __init__(self):
        # Per source IP tracking
        self.src_ports      = defaultdict(set)    # src_ip → set of dst ports
        self.src_pkt_count  = defaultdict(int)    # src_ip → packet count
        self.src_pkt_sizes  = defaultdict(list)   # src_ip → list of sizes
        self.dns_count      = defaultdict(int)    # src_ip → UDP/53 count

        # Track which alerts already fired per IP (prevent duplicates)
        self.fired = defaultdict(set)

    def _make_alert(self, attack_type, severity, src_ip, description, evidence):
        return {
            'timestamp'   : datetime.now().strftime('%H:%M:%S'),
            'attack_type' : attack_type,
            'severity'    : severity,
            'src_ip'      : src_ip,
            'description' : description,
            'evidence'    : evidence,
        }

    def _is_private(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def check(self, pkt):
        """
        Receives a single parsed packet dict and returns
        a list of any alerts fired (may be empty).
        """
        alerts  = []
        src_ip  = pkt.get('src_ip', '')
        proto   = pkt.get('protocol', '')
        dst_port = pkt.get('dst_port')
        size    = pkt.get('size', 0)

        # ── Update counters
        self.src_pkt_count[src_ip] += 1
        self.src_pkt_sizes[src_ip].append(size)

        if dst_port:
            self.src_ports[src_ip].add(dst_port)

        if proto == 'UDP' and dst_port == 53:
            self.dns_count[src_ip] += 1

        # ── Check 1: Port scan
        unique_ports = len(self.src_ports[src_ip])
        if (unique_ports >= THRESHOLDS['port_scan_unique_ports']
                and 'PORT_SCAN' not in self.fired[src_ip]):
            self.fired[src_ip].add('PORT_SCAN')
            alerts.append(self._make_alert(
                'PORT_SCAN', 'HIGH', src_ip,
                f"Port scan — {unique_ports} unique ports contacted",
                {'unique_dst_ports': unique_ports}
            ))

        # ── Check 2: SYN flood
        pkt_count = self.src_pkt_count[src_ip]
        if pkt_count >= THRESHOLDS['syn_flood_packet_count']:
            sizes    = self.src_pkt_sizes[src_ip]
            avg_size = sum(sizes) / len(sizes)
            if (avg_size <= THRESHOLDS['syn_flood_max_avg_size']
                    and 'SYN_FLOOD' not in self.fired[src_ip]):
                self.fired[src_ip].add('SYN_FLOOD')
                alerts.append(self._make_alert(
                    'SYN_FLOOD', 'CRITICAL', src_ip,
                    f"SYN flood — {pkt_count} packets, avg {avg_size:.0f}B",
                    {'packet_count': pkt_count, 'avg_size': round(avg_size, 1)}
                ))

        # ── Check 3: DNS amplification
        dns_count = self.dns_count[src_ip]
        if (dns_count >= THRESHOLDS['dns_amp_count']
                and 'DNS_AMP' not in self.fired[src_ip]):
            self.fired[src_ip].add('DNS_AMP')
            alerts.append(self._make_alert(
                'DNS_AMPLIFICATION', 'HIGH', src_ip,
                f"DNS amplification — {dns_count} UDP/53 packets",
                {'dns_packet_count': dns_count}
            ))

        # ── Check 4: Sensitive port access
        if dst_port in SENSITIVE_PORTS:
            key = f"SENSITIVE_{dst_port}"
            if key not in self.fired[src_ip]:
                self.fired[src_ip].add(key)
                service  = SENSITIVE_PORTS[dst_port]
                severity = 'CRITICAL' if dst_port in {22, 445, 3389} else 'MEDIUM'
                alerts.append(self._make_alert(
                    'SENSITIVE_PORT_ACCESS', severity, src_ip,
                    f"Access to port {dst_port} ({service})",
                    {'port': dst_port, 'service': service}
                ))

        return alerts

    def reset(self):
        """Clears all counters — call between capture sessions."""
        self.src_ports.clear()
        self.src_pkt_count.clear()
        self.src_pkt_sizes.clear()
        self.dns_count.clear()
        self.fired.clear()