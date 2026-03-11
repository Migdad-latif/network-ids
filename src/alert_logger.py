"""
alert_logger.py
---------------
Module F: Professional alert logging system.
Provides structured, rotating, severity-filtered logging
for all NIDS detection events. Generates session reports.
"""

import os
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from collections import defaultdict

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
LOG_DIR     = os.path.join(BASE_DIR, 'logs')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
ALERTS_FILE = os.path.join(BASE_DIR, 'data', 'alerts.json')

LOG_FILE    = os.path.join(LOG_DIR, 'nids.log')
REPORT_FILE = os.path.join(RESULTS_DIR, 'alert_report.txt')

# ── Severity Configuration ─────────────────────────────────────────────────────

# Map NIDS severity strings to Python logging levels
SEVERITY_TO_LEVEL = {
    'LOW'      : logging.INFO,
    'MEDIUM'   : logging.WARNING,
    'HIGH'     : logging.ERROR,
    'CRITICAL' : logging.CRITICAL,
}

SEVERITY_RANK = {
    'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4
}

# ── Log Formatter ──────────────────────────────────────────────────────────────

class NIDSFormatter(logging.Formatter):
    """
    Custom log formatter that produces structured, readable
    log lines with consistent field alignment.

    Format:
    [2025-01-15 14:32:01] [CRITICAL] PORT_SCAN        | 192.168.1.5 | Possible port scan...
    """

    def format(self, record):
        # Standard fields always present
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        level     = f"{record.levelname:<8}"
        message   = record.getMessage()
        return f"[{timestamp}] [{level}] {message}"

# ── Logger Setup ───────────────────────────────────────────────────────────────

def setup_logger(
    log_file     = LOG_FILE,
    max_bytes    = 5 * 1024 * 1024,   # 5 MB per log file
    backup_count = 3,                  # keep 3 rotated files
    min_severity = 'LOW'               # minimum severity to log
):
    """
    Initialises and returns the NIDS logger.

    Uses a RotatingFileHandler so the log file never exceeds
    max_bytes. When full it rotates: nids.log → nids.log.1 → etc.
    Simultaneously writes to console for live monitoring.

    Parameters
    ----------
    log_file     : path to the log file
    max_bytes    : max file size before rotation
    backup_count : number of rotated backups to keep
    min_severity : minimum alert severity to record ('LOW', 'MEDIUM', etc.)
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger('NIDS')
    logger.setLevel(logging.DEBUG)   # capture everything; handlers filter

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        logger.handlers.clear()

    min_level = SEVERITY_TO_LEVEL.get(min_severity.upper(), logging.DEBUG)

    # ── File handler (rotating)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes    = max_bytes,
        backupCount = backup_count,
        encoding    = 'utf-8'
    )
    file_handler.setLevel(min_level)
    file_handler.setFormatter(NIDSFormatter())

    # ── Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min_level)
    console_handler.setFormatter(NIDSFormatter())

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# ── Session State ──────────────────────────────────────────────────────────────

class AlertSession:
    """
    Tracks statistics for the current logging session.
    Accumulates alert counts, unique IPs, and top attackers
    so a summary report can be generated at session end.
    """

    def __init__(self):
        self.start_time    = datetime.now()
        self.alerts        = []                    # all alert dicts
        self.severity_counts = defaultdict(int)    # severity → count
        self.attacker_counts = defaultdict(int)    # src_ip → count
        self.type_counts     = defaultdict(int)    # attack_type → count

    def record(self, alert):
        self.alerts.append(alert)
        self.severity_counts[alert['severity']]    += 1
        self.attacker_counts[alert['src_ip']]      += 1
        self.type_counts[alert['attack_type']]     += 1

    @property
    def total(self):
        return len(self.alerts)

    @property
    def top_attacker(self):
        if not self.attacker_counts:
            return ('None', 0)
        return max(self.attacker_counts.items(), key=lambda x: x[1])

    @property
    def highest_severity(self):
        if not self.severity_counts:
            return 'NONE'
        return max(
            self.severity_counts.keys(),
            key=lambda s: SEVERITY_RANK.get(s, 0)
        )

    @property
    def duration(self):
        delta = datetime.now() - self.start_time
        return str(delta).split('.')[0]   # trim microseconds

# ── Core: Log a Single Alert ───────────────────────────────────────────────────

def log_alert(alert, logger, session):
    """
    Logs a single alert dict through the logger and records
    it in the session for summary reporting.

    Parameters
    ----------
    alert   : dict produced by signature_detector.make_alert()
    logger  : logger instance from setup_logger()
    session : AlertSession instance tracking this run
    """
    severity    = alert.get('severity', 'LOW')
    attack_type = alert.get('attack_type', 'UNKNOWN')
    src_ip      = alert.get('src_ip', '0.0.0.0')
    description = alert.get('description', '')
    evidence    = alert.get('evidence', {})

    level = SEVERITY_TO_LEVEL.get(severity, logging.INFO)

    # Format the log line
    evidence_str = ' | '.join(f"{k}={v}" for k, v in evidence.items())
    message = (
        f"{attack_type:<28} | "
        f"{src_ip:<18} | "
        f"{severity:<8} | "
        f"{description} | "
        f"evidence: {{{evidence_str}}}"
    )

    logger.log(level, message)
    session.record(alert)

# ── Core: Log All Alerts from JSON File ───────────────────────────────────────

def log_all_alerts(
    alerts_file  = ALERTS_FILE,
    min_severity = 'LOW',
    log_file     = LOG_FILE
):
    """
    Reads alerts.json, passes every alert through the logger,
    and returns the completed session object.
    """
    logger  = setup_logger(log_file=log_file, min_severity=min_severity)
    session = AlertSession()

    print("=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM — Alert Logging Module")
    print("=" * 70)

    # ── Load alerts
    if not os.path.exists(alerts_file):
        print(f"[!] No alerts file found at {alerts_file}")
        print(f"    Run signature_detector.py first.")
        return session

    with open(alerts_file, 'r') as f:
        alerts = json.load(f)

    print(f"[✓] Loaded {len(alerts)} alert(s) from {alerts_file}")
    print(f"    Minimum severity filter: {min_severity}")
    print(f"    Log file: {log_file}\n")

    if not alerts:
        print("  [✓] No alerts to log — capture session was clean.")
        print("      Generating clean-session report...\n")
    else:
        print(f"  Logging {len(alerts)} alert(s):")
        print(f"  {'─' * 60}")

    # ── Log each alert
    for alert in alerts:
        alert_severity_rank = SEVERITY_RANK.get(alert.get('severity', 'LOW'), 0)
        min_rank = SEVERITY_RANK.get(min_severity.upper(), 0)

        if alert_severity_rank >= min_rank:
            log_alert(alert, logger, session)

    return session

# ── Report Generator ───────────────────────────────────────────────────────────

def generate_report(session, report_file=REPORT_FILE):
    """
    Writes a structured plaintext session report to results/.
    Includes summary statistics, severity breakdown,
    top attackers, and full alert listing.
    """
    os.makedirs(os.path.dirname(report_file), exist_ok=True)

    divider     = "=" * 70
    sub_divider = "-" * 70

    lines = [
        divider,
        "  NETWORK INTRUSION DETECTION SYSTEM",
        "  Alert Session Report",
        divider,
        f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration   : {session.duration}",
        f"  Total Alerts : {session.total}",
        f"  Highest Severity : {session.highest_severity}",
        "",
        sub_divider,
        "  SEVERITY BREAKDOWN",
        sub_divider,
    ]

    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = session.severity_counts.get(sev, 0)
        bar   = '█' * count
        lines.append(f"  {sev:<10} : {count:>4}  {bar}")

    lines += [
        "",
        sub_divider,
        "  ATTACK TYPE BREAKDOWN",
        sub_divider,
    ]

    for attack_type, count in sorted(
        session.type_counts.items(), key=lambda x: -x[1]
    ):
        lines.append(f"  {attack_type:<30} : {count} alert(s)")

    lines += [
        "",
        sub_divider,
        "  TOP ATTACKING IPs",
        sub_divider,
    ]

    top_ips = sorted(
        session.attacker_counts.items(), key=lambda x: -x[1]
    )[:10]   # top 10

    if top_ips:
        for ip, count in top_ips:
            lines.append(f"  {ip:<20} : {count} alert(s)")
    else:
        lines.append("  No attacking IPs recorded.")

    lines += [
        "",
        sub_divider,
        "  FULL ALERT LOG",
        sub_divider,
    ]

    if session.alerts:
        for i, alert in enumerate(session.alerts, 1):
            lines += [
                f"",
                f"  Alert #{i}",
                f"  Timestamp   : {alert.get('timestamp')}",
                f"  Type        : {alert.get('attack_type')}",
                f"  Severity    : {alert.get('severity')}",
                f"  Source IP   : {alert.get('src_ip')}",
                f"  Description : {alert.get('description')}",
                f"  Evidence    : {alert.get('evidence')}",
            ]
    else:
        lines += [
            "",
            "  No alerts were raised during this session.",
            "  All monitored traffic appears normal.",
        ]

    lines += [
        "",
        divider,
        "  END OF REPORT",
        divider,
    ]

    report_text = "\n".join(lines)

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)

    return report_text

# ── Main Runner ────────────────────────────────────────────────────────────────

def run_logging(min_severity='LOW'):
    """
    Full logging pipeline:
    1. Read alerts.json
    2. Log each alert through rotating file logger
    3. Print session summary to terminal
    4. Generate report file
    """
    session = log_all_alerts(min_severity=min_severity)

    # ── Session summary
    print(f"\n{'=' * 70}")
    print(f"  SESSION SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total alerts logged : {session.total}")
    print(f"  Highest severity    : {session.highest_severity}")
    print(f"  Session duration    : {session.duration}")
    print(f"  Top attacker        : {session.top_attacker[0]} "
          f"({session.top_attacker[1]} alerts)")

    print(f"\n  Severity breakdown:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = session.severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:<10} : {count}")

    # ── Generate report
    report_text = generate_report(session)

    print(f"\n[✓] Log file    : {LOG_FILE}")
    print(f"[✓] Report file : {REPORT_FILE}")
    print(f"\n  Report preview:")
    print(f"  {'─' * 60}")
    for line in report_text.split('\n')[:20]:
        print(f"  {line}")
    print(f"  ... (see full report in results/alert_report.txt)")

    return session

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    run_logging(min_severity='LOW')