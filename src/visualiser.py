"""
visualiser.py
-------------
Module G: Traffic visualisation using Matplotlib.
Reads captured_packets.csv and generates four analytical
charts saved as PNG files in results/.
"""

import os
import pandas as pd
import matplotlib
matplotlib.use('Agg')   # non-interactive backend — works without a display
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from collections import Counter
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
INPUT_FILE  = os.path.join(BASE_DIR, 'data', 'captured_packets.csv')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

# ── Style Configuration ────────────────────────────────────────────────────────

STYLE = {
    'figure_bg'  : '#0d1117',   # dark background — professional NIDS aesthetic
    'axes_bg'    : '#161b22',
    'text'       : '#e6edf3',
    'grid'       : '#30363d',
    'accent_1'   : '#58a6ff',   # blue
    'accent_2'   : '#3fb950',   # green
    'accent_3'   : '#f78166',   # red/orange
    'accent_4'   : '#d2a8ff',   # purple
    'accent_5'   : '#ffa657',   # amber
    'font_size'  : 11,
    'title_size' : 13,
}

PROTOCOL_COLOURS = {
    'TCP'   : STYLE['accent_1'],
    'UDP'   : STYLE['accent_2'],
    'ICMP'  : STYLE['accent_3'],
    'OTHER' : STYLE['accent_4'],
}

# ── Helper: Apply Dark Theme to Axes ──────────────────────────────────────────

def apply_dark_theme(fig, axes):
    """Applies consistent dark theme styling to a figure and its axes."""
    fig.patch.set_facecolor(STYLE['figure_bg'])

    for ax in (axes if hasattr(axes, '__iter__') else [axes]):
        ax.set_facecolor(STYLE['axes_bg'])
        ax.tick_params(colors=STYLE['text'], labelsize=STYLE['font_size'])
        ax.xaxis.label.set_color(STYLE['text'])
        ax.yaxis.label.set_color(STYLE['text'])
        ax.title.set_color(STYLE['text'])

        for spine in ax.spines.values():
            spine.set_edgecolor(STYLE['grid'])

        ax.grid(color=STYLE['grid'], linestyle='--', linewidth=0.5, alpha=0.7)

# ── Helper: Save Figure ────────────────────────────────────────────────────────

def save_figure(fig, filename):
    """Saves a figure to results/ and closes it to free memory."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    filepath = os.path.join(RESULTS_DIR, filename)
    fig.savefig(filepath, dpi=150, bbox_inches='tight',
                facecolor=STYLE['figure_bg'])
    plt.close(fig)
    print(f"  [✓] Saved → results/{filename}")
    return filepath

# ── Chart 1 — Protocol Distribution ───────────────────────────────────────────

def plot_protocol_distribution(df):
    """
    Pie chart showing the proportion of each protocol in the capture.
    Helps identify protocol-level anomalies (e.g. unusually high ICMP).
    """
    protocol_counts = df['protocol'].value_counts()
    protocols = protocol_counts.index.tolist()
    counts    = protocol_counts.values.tolist()
    colours   = [PROTOCOL_COLOURS.get(p, STYLE['accent_5']) for p in protocols]

    fig, ax = plt.subplots(figsize=(7, 6))
    apply_dark_theme(fig, ax)

    wedges, texts, autotexts = ax.pie(
        counts,
        labels      = protocols,
        colors      = colours,
        autopct     = '%1.1f%%',
        startangle  = 140,
        wedgeprops  = {'edgecolor': STYLE['figure_bg'], 'linewidth': 2},
    )

    for text in texts:
        text.set_color(STYLE['text'])
        text.set_fontsize(STYLE['font_size'])

    for autotext in autotexts:
        autotext.set_color(STYLE['figure_bg'])
        autotext.set_fontweight('bold')
        autotext.set_fontsize(STYLE['font_size'])

    ax.set_title(
        'Protocol Distribution',
        fontsize=STYLE['title_size'],
        fontweight='bold',
        pad=20,
        color=STYLE['text']
    )

    # Legend with counts
    legend_labels = [f"{p}  ({c} packets)" for p, c in zip(protocols, counts)]
    ax.legend(
        legend_labels,
        loc            = 'lower center',
        bbox_to_anchor = (0.5, -0.12),
        ncol           = 2,
        framealpha     = 0,
        labelcolor     = STYLE['text'],
        fontsize       = STYLE['font_size'] - 1,
    )

    return save_figure(fig, 'chart1_protocol_distribution.png')

# ── Chart 2 — Packet Size Distribution ────────────────────────────────────────

def plot_packet_size_distribution(df):
    """
    Histogram of packet sizes.
    Normal traffic has a varied distribution.
    DoS/flood attacks show a sharp spike at very small sizes (40-64 bytes).
    Large file transfers show a spike near 1500 bytes (MTU).
    """
    fig, ax = plt.subplots(figsize=(9, 5))
    apply_dark_theme(fig, ax)

    # Plot separate histogram per protocol for richer analysis
    for protocol, colour in PROTOCOL_COLOURS.items():
        subset = df[df['protocol'] == protocol]['packet_size']
        if subset.empty:
            continue
        ax.hist(
            subset,
            bins      = 40,
            alpha     = 0.75,
            color     = colour,
            label     = protocol,
            edgecolor = STYLE['figure_bg'],
            linewidth = 0.5,
        )

    ax.set_xlabel('Packet Size (bytes)', fontsize=STYLE['font_size'])
    ax.set_ylabel('Packet Count',        fontsize=STYLE['font_size'])
    ax.set_title(
        'Packet Size Distribution by Protocol',
        fontsize   = STYLE['title_size'],
        fontweight = 'bold',
        color      = STYLE['text']
    )

    ax.legend(
        framealpha = 0,
        labelcolor = STYLE['text'],
        fontsize   = STYLE['font_size'],
    )

    # Mark common thresholds
    ax.axvline(x=64,   color=STYLE['accent_3'], linestyle=':', linewidth=1.2,
               label='Min TCP (64B)')
    ax.axvline(x=1500, color=STYLE['accent_5'], linestyle=':', linewidth=1.2,
               label='MTU (1500B)')

    ax.text(68,   ax.get_ylim()[1] * 0.85, '← SYN size',
            color=STYLE['accent_3'], fontsize=9)
    ax.text(1380, ax.get_ylim()[1] * 0.85, 'MTU →',
            color=STYLE['accent_5'], fontsize=9)

    return save_figure(fig, 'chart2_packet_size_distribution.png')

# ── Chart 3 — Traffic Timeline ─────────────────────────────────────────────────

def plot_traffic_timeline(df):
    """
    Line chart of packets-per-second over the capture window.
    A sudden spike indicates a flood attack or scan burst.
    Flat lines indicate normal background traffic.
    """
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Resample to per-second packet counts
    df = df.set_index('timestamp').sort_index()
    timeline = df.resample('1s')['packet_size'].count().reset_index()
    timeline.columns = ['time', 'packets_per_second']

    fig, ax = plt.subplots(figsize=(11, 5))
    apply_dark_theme(fig, ax)

    ax.plot(
        timeline['time'],
        timeline['packets_per_second'],
        color     = STYLE['accent_1'],
        linewidth = 1.8,
        label     = 'Packets / second',
    )

    ax.fill_between(
        timeline['time'],
        timeline['packets_per_second'],
        alpha = 0.25,
        color = STYLE['accent_1'],
    )

    # Mark peak
    peak_idx = timeline['packets_per_second'].idxmax()
    peak_row = timeline.loc[peak_idx]
    ax.annotate(
        f"Peak: {int(peak_row['packets_per_second'])} pkt/s",
        xy         = (peak_row['time'], peak_row['packets_per_second']),
        xytext     = (peak_row['time'], peak_row['packets_per_second'] * 1.15),
        arrowprops = {'arrowstyle': '->', 'color': STYLE['accent_3']},
        color      = STYLE['accent_3'],
        fontsize   = STYLE['font_size'],
        fontweight = 'bold',
    )

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    fig.autofmt_xdate(rotation=30)

    ax.set_xlabel('Time',               fontsize=STYLE['font_size'])
    ax.set_ylabel('Packets per Second', fontsize=STYLE['font_size'])
    ax.set_title(
        'Network Traffic Timeline',
        fontsize   = STYLE['title_size'],
        fontweight = 'bold',
        color      = STYLE['text']
    )
    ax.legend(framealpha=0, labelcolor=STYLE['text'], fontsize=STYLE['font_size'])

    return save_figure(fig, 'chart3_traffic_timeline.png')

# ── Chart 4 — Top Talkers ──────────────────────────────────────────────────────

def plot_top_talkers(df, top_n=10):
    """
    Horizontal bar chart of source IPs by packet count.
    An attacker IP will appear dramatically above background hosts.
    Helps immediately identify the loudest source in the capture.
    """
    top_ips = (
        df.groupby('src_ip')['packet_size']
        .agg(packet_count='count', total_bytes='sum')
        .sort_values('packet_count', ascending=True)
        .tail(top_n)
        .reset_index()
    )

    fig, ax = plt.subplots(figsize=(10, max(4, len(top_ips) * 0.55)))
    apply_dark_theme(fig, ax)

    # Colour the top bar differently — likely the attacker or most active host
    bar_colours = [STYLE['accent_1']] * len(top_ips)
    bar_colours[-1] = STYLE['accent_3']   # highlight busiest IP in red

    bars = ax.barh(
        top_ips['src_ip'],
        top_ips['packet_count'],
        color     = bar_colours,
        edgecolor = STYLE['figure_bg'],
        linewidth = 0.5,
    )

    # Add packet count labels on each bar
    for bar, count in zip(bars, top_ips['packet_count']):
        ax.text(
            bar.get_width() + 0.3,
            bar.get_y() + bar.get_height() / 2,
            str(count),
            va        = 'center',
            color     = STYLE['text'],
            fontsize  = STYLE['font_size'] - 1,
            fontweight = 'bold',
        )

    ax.set_xlabel('Packet Count',   fontsize=STYLE['font_size'])
    ax.set_ylabel('Source IP',      fontsize=STYLE['font_size'])
    ax.set_title(
        f'Top {top_n} Talkers by Packet Count',
        fontsize   = STYLE['title_size'],
        fontweight = 'bold',
        color      = STYLE['text']
    )

    ax.legend(
        handles = [
            plt.Rectangle((0,0),1,1, color=STYLE['accent_3'], label='Busiest host'),
            plt.Rectangle((0,0),1,1, color=STYLE['accent_1'], label='Other hosts'),
        ],
        framealpha = 0,
        labelcolor = STYLE['text'],
        fontsize   = STYLE['font_size'],
    )

    return save_figure(fig, 'chart4_top_talkers.png')

# ── Main Runner ────────────────────────────────────────────────────────────────

def run_visualisation(input_file=INPUT_FILE):
    """
    Full visualisation pipeline.
    Loads captured_packets.csv and generates all four charts.
    """
    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM — Visualisation Module")
    print("=" * 70)

    # ── Load data
    if not os.path.exists(input_file):
        print(f"[✗] Input file not found: {input_file}")
        print("    Run packet_capture.py first.")
        return

    df = pd.read_csv(input_file)
    print(f"[✓] Loaded {len(df)} packets from {input_file}")
    print(f"    Protocols found : {df['protocol'].unique().tolist()}")
    print(f"    Time range      : {df['timestamp'].min()} → {df['timestamp'].max()}")
    print(f"\n  Generating charts...")
    print(f"  {'─' * 60}")

    # ── Generate all charts
    paths = []
    paths.append(plot_protocol_distribution(df))
    paths.append(plot_packet_size_distribution(df))
    paths.append(plot_traffic_timeline(df))
    paths.append(plot_top_talkers(df))

    print(f"\n[✓] All charts saved to results/")
    print(f"\n  Summary statistics:")
    print(f"  {'─' * 60}")
    print(f"  Total packets    : {len(df)}")
    print(f"  Total bytes      : {df['packet_size'].sum():,}")
    print(f"  Avg packet size  : {df['packet_size'].mean():.1f} bytes")
    print(f"  Largest packet   : {df['packet_size'].max()} bytes")
    print(f"  Smallest packet  : {df['packet_size'].min()} bytes")
    print(f"  Unique src IPs   : {df['src_ip'].nunique()}")
    print(f"  Unique dst IPs   : {df['dst_ip'].nunique()}")
    print(f"  Unique dst ports : {df['dst_port'].nunique()}")

    return paths

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    run_visualisation()