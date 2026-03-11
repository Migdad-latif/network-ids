"""
app.py
------
SIEM Dashboard Server — threading emit fix.
Uses socketio.emit() with proper namespace for
background thread → browser push on Windows.
"""

import os
import sys
import threading
import time
from datetime import datetime
from collections import defaultdict, deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask          import Flask, render_template_string
from flask_socketio import SocketIO, emit
from live_detector  import LiveDetector

# ── App Setup ──────────────────────────────────────────────────────────────────

app      = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-siem-secret'

socketio = SocketIO(
    app,
    async_mode          = 'threading',
    cors_allowed_origins= '*',
    logger              = False,
    engineio_logger     = False,
    ping_timeout        = 60,
    ping_interval       = 25,
)

# ── Paths ──────────────────────────────────────────────────────────────────────

HTML_FILE = os.path.join(os.path.dirname(__file__), 'siem.html')

# ── Shared State ───────────────────────────────────────────────────────────────

state = {
    'capturing'       : False,
    'packet_count'    : 0,
    'alert_count'     : 0,
    'packets'         : deque(maxlen=500),
    'alerts'          : deque(maxlen=200),
    'protocol_counts' : defaultdict(int),
    'top_talkers'     : defaultdict(int),
    'timeline'        : deque(maxlen=60),
    'lock'            : threading.Lock(),
}

detector = LiveDetector()

# ── Safe emit from background thread ──────────────────────────────────────────

def bg_emit(event, data):
    """
    Safely emits a SocketIO event from a background thread.
    Must use namespace='/' explicitly when calling from
    outside a request context on Windows threading mode.
    """
    try:
        socketio.emit(event, data, namespace='/')
    except Exception:
        pass   # silently skip if no clients connected

# ── Packet Handler ─────────────────────────────────────────────────────────────

def handle_packet(packet):
    try:
        from scapy.all import IP, TCP, UDP, ICMP
    except ImportError:
        return

    if not packet.haslayer(IP):
        return

    if packet.haslayer(TCP):
        proto    = 'TCP'
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        proto    = 'UDP'
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        proto    = 'ICMP'
        src_port = None
        dst_port = None
    else:
        proto    = 'OTHER'
        src_port = None
        dst_port = None

    pkt_data = {
        'timestamp' : datetime.now().strftime('%H:%M:%S'),
        'src_ip'    : str(packet[IP].src),
        'dst_ip'    : str(packet[IP].dst),
        'protocol'  : proto,
        'src_port'  : src_port,
        'dst_port'  : dst_port,
        'size'      : len(packet),
    }

    # ── Update state
    with state['lock']:
        state['packet_count']           += 1
        state['packets'].append(pkt_data)
        state['protocol_counts'][proto] += 1
        state['top_talkers'][pkt_data['src_ip']] += 1
        count = state['packet_count']

    # ── Push packet immediately to browser
    bg_emit('new_packet', pkt_data)

    # ── Run detection
    alerts = detector.check(pkt_data)
    for alert in alerts:
        with state['lock']:
            state['alert_count'] += 1
            state['alerts'].append(alert)
        bg_emit('new_alert', alert)
        print(f"  [!] {alert['severity']} — {alert['attack_type']} "
              f"from {alert['src_ip']}")

    # ── Push stats every 10 packets
    if count % 10 == 0:
        push_stats()

    # ── Terminal heartbeat every 50 packets
    if count % 50 == 0:
        with state['lock']:
            alerts_total = state['alert_count']
        print(f"  [→] {count} packets | {alerts_total} alerts")

# ── Stats Push ─────────────────────────────────────────────────────────────────

def push_stats():
    with state['lock']:
        top = sorted(
            state['top_talkers'].items(),
            key=lambda x: -x[1]
        )[:8]
        stats = {
            'packet_count'    : state['packet_count'],
            'alert_count'     : state['alert_count'],
            'protocol_counts' : dict(state['protocol_counts']),
            'top_talkers'     : [{'ip': ip, 'count': c} for ip, c in top],
        }
    bg_emit('stats_update', stats)

# ── Capture Thread ─────────────────────────────────────────────────────────────

def capture_thread():
    print("[*] Capture thread waiting for server...")
    time.sleep(2)

    try:
        from scapy.all import sniff
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except ImportError as e:
        print(f"[✗] Scapy import failed: {e}")
        return

    print("[✓] Scapy ready — capturing packets...")
    state['capturing'] = True

    try:
        sniff(
            prn         = handle_packet,
            store       = False,
            stop_filter = lambda p: not state['capturing'],
        )
    except Exception as e:
        print(f"[✗] Capture error: {e}")
        print("    Ensure VS Code is running as Administrator.")
        state['capturing'] = False

# ── Timeline Thread ────────────────────────────────────────────────────────────

def timeline_thread():
    """Pushes a packets-per-second tick every second."""
    last_count = 0
    while True:
        time.sleep(1)
        with state['lock']:
            current = state['packet_count']
        delta      = current - last_count
        last_count = current

        tick = {
            'time'  : datetime.now().strftime('%H:%M:%S'),
            'count' : delta,
        }
        with state['lock']:
            state['timeline'].append(tick)
        bg_emit('timeline_tick', tick)

# ── SocketIO Events ────────────────────────────────────────────────────────────

@socketio.on('connect', namespace='/')
def on_connect():
    print(f"[→] Browser connected — sending current state")

    with state['lock']:
        recent_packets = list(state['packets'])[-50:]
        recent_alerts  = list(state['alerts'])[-20:]
        top = sorted(
            state['top_talkers'].items(),
            key=lambda x: -x[1]
        )[:8]
        initial = {
            'packet_count'    : state['packet_count'],
            'alert_count'     : state['alert_count'],
            'protocol_counts' : dict(state['protocol_counts']),
            'top_talkers'     : [{'ip': ip, 'count': c} for ip, c in top],
            'recent_packets'  : recent_packets,
            'recent_alerts'   : recent_alerts,
            'timeline'        : list(state['timeline']),
            'capturing'       : state['capturing'],
        }

    emit('initial_state', initial)

@socketio.on('disconnect', namespace='/')
def on_disconnect():
    print(f"[←] Browser disconnected")

@socketio.on('ping_check', namespace='/')
def on_ping():
    emit('pong_check', {'status': 'alive'})

# ── Route ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    with open(HTML_FILE, 'r', encoding='utf-8') as f:
        return render_template_string(f.read())

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 70)
    print("  NIDS SIEM DASHBOARD")
    print("=" * 70)
    print(f"  URL     : http://localhost:5000")
    print(f"  Wait for '[✓] Scapy ready' before opening browser")
    print(f"  Ctrl+C  : stop server")
    print("=" * 70 + "\n")

    threading.Thread(target=capture_thread,  daemon=True).start()
    threading.Thread(target=timeline_thread, daemon=True).start()

    socketio.run(
        app,
        host        = '0.0.0.0',
        port        = 5000,
        debug       = False,
        use_reloader= False,
    )