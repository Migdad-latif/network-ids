"""
generate_diagram.py
-------------------
Generates a professional system architecture diagram
for the NIDS project using Matplotlib.
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

STYLE = {
    'figure_bg' : '#0d1117',
    'text'      : '#e6edf3',
    'grid'      : '#30363d',
    'blue'      : '#58a6ff',
    'green'     : '#3fb950',
    'red'       : '#f78166',
    'purple'    : '#d2a8ff',
    'amber'     : '#ffa657',
    'teal'      : '#39d353',
}

def draw_box(ax, x, y, w, h, label, sublabel, colour):
    """Draws a rounded box with a label and sublabel."""
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle    = "round,pad=0.02",
        linewidth   = 1.5,
        edgecolor   = colour,
        facecolor   = '#161b22',
        zorder      = 3,
    )
    ax.add_patch(box)
    ax.text(x, y + 0.04, label,
            ha='center', va='center',
            fontsize=9, fontweight='bold',
            color=colour, zorder=4)
    ax.text(x, y - 0.06, sublabel,
            ha='center', va='center',
            fontsize=7, color=STYLE['text'],
            alpha=0.75, zorder=4)

def draw_arrow(ax, x1, y1, x2, y2, colour='#30363d'):
    ax.annotate('',
        xy     = (x2, y2),
        xytext = (x1, y1),
        arrowprops=dict(
            arrowstyle = '-|>',
            color      = colour,
            lw         = 1.4,
        ),
        zorder = 2,
    )

def generate_architecture_diagram():
    fig, ax = plt.subplots(figsize=(14, 9))
    fig.patch.set_facecolor(STYLE['figure_bg'])
    ax.set_facecolor(STYLE['figure_bg'])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')

    # ── Title
    ax.text(0.5, 0.96,
            'Network Intrusion Detection System — Architecture',
            ha='center', va='center',
            fontsize=14, fontweight='bold',
            color=STYLE['text'])

    ax.text(0.5, 0.91,
            'Python  ·  Scapy  ·  Scikit-learn  ·  Matplotlib',
            ha='center', va='center',
            fontsize=9, color=STYLE['text'], alpha=0.6)

    # ── Layer labels
    for y, label in [
        (0.78, 'CAPTURE LAYER'),
        (0.60, 'PROCESSING LAYER'),
        (0.40, 'DETECTION LAYER'),
        (0.20, 'OUTPUT LAYER'),
    ]:
        ax.text(0.01, y, label,
                fontsize=7, color=STYLE['text'],
                alpha=0.4, va='center',
                fontweight='bold')
        ax.axhline(y=y - 0.08, xmin=0.01, xmax=0.99,
                   color=STYLE['grid'], linewidth=0.4, alpha=0.5)

    # ── Row 1: Input sources
    draw_box(ax, 0.25, 0.78, 0.18, 0.10,
             'Network Interface', 'Live packets / Scapy sniff()',
             STYLE['blue'])
    draw_box(ax, 0.75, 0.78, 0.18, 0.10,
             'Nmap Attack Traffic', 'SYN · Version · Aggressive',
             STYLE['red'])

    # ── Row 2: Capture + Feature extraction
    draw_box(ax, 0.25, 0.60, 0.20, 0.10,
             'Packet Capture', 'packet_capture.py',
             STYLE['blue'])
    draw_box(ax, 0.75, 0.60, 0.20, 0.10,
             'Feature Extractor', 'feature_extractor.py',
             STYLE['amber'])

    # ── Row 3: Detection engines
    draw_box(ax, 0.20, 0.40, 0.20, 0.10,
             'Signature Detector', 'signature_detector.py',
             STYLE['red'])
    draw_box(ax, 0.50, 0.40, 0.20, 0.10,
             'ML Anomaly Detector', 'anomaly_detector.py',
             STYLE['purple'])
    draw_box(ax, 0.80, 0.40, 0.16, 0.10,
             'Alert Logger', 'alert_logger.py',
             STYLE['green'])

    # ── Row 4: Outputs
    draw_box(ax, 0.15, 0.20, 0.16, 0.10,
             'alerts.json', 'Signature alerts',
             STYLE['red'])
    draw_box(ax, 0.36, 0.20, 0.16, 0.10,
             'ml_alerts.json', 'ML anomaly alerts',
             STYLE['purple'])
    draw_box(ax, 0.57, 0.20, 0.16, 0.10,
             'nids.log', 'Rotating log file',
             STYLE['green'])
    draw_box(ax, 0.78, 0.20, 0.16, 0.10,
             'Charts (PNG)', 'Visualiser output',
             STYLE['amber'])

    # ── Arrows: Row 1 → Row 2
    draw_arrow(ax, 0.25, 0.73, 0.25, 0.65, STYLE['blue'])
    draw_arrow(ax, 0.75, 0.73, 0.75, 0.65, STYLE['red'])

    # ── Arrows: Row 2 → Row 3
    draw_arrow(ax, 0.30, 0.55, 0.55, 0.45, STYLE['amber'])
    draw_arrow(ax, 0.30, 0.55, 0.25, 0.45, STYLE['blue'])
    draw_arrow(ax, 0.70, 0.55, 0.55, 0.45, STYLE['amber'])
    draw_arrow(ax, 0.70, 0.55, 0.78, 0.45, STYLE['amber'])

    # ── Arrows: Row 3 → Row 4
    draw_arrow(ax, 0.20, 0.35, 0.15, 0.25, STYLE['red'])
    draw_arrow(ax, 0.50, 0.35, 0.36, 0.25, STYLE['purple'])
    draw_arrow(ax, 0.80, 0.35, 0.57, 0.25, STYLE['green'])
    draw_arrow(ax, 0.75, 0.55, 0.78, 0.25, STYLE['amber'])

    # ── Legend
    legend_items = [
        mpatches.Patch(color=STYLE['blue'],   label='Capture'),
        mpatches.Patch(color=STYLE['amber'],  label='Processing'),
        mpatches.Patch(color=STYLE['red'],    label='Signature Detection'),
        mpatches.Patch(color=STYLE['purple'], label='ML Detection'),
        mpatches.Patch(color=STYLE['green'],  label='Logging'),
    ]
    legend = ax.legend(
        handles        = legend_items,
        loc            = 'lower center',
        bbox_to_anchor = (0.5, 0.01),
        ncol           = 5,
        framealpha     = 0,
        labelcolor     = STYLE['text'],
        fontsize       = 8,
    )

    # ── Save
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, 'architecture_diagram.png')
    fig.savefig(path, dpi=180, bbox_inches='tight',
                facecolor=STYLE['figure_bg'])
    plt.close(fig)
    print(f"[✓] Architecture diagram saved → results/architecture_diagram.png")
    return path

if __name__ == '__main__':
    generate_architecture_diagram()