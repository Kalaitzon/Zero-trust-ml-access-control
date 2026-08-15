# -*- coding: utf-8 -*-
"""
=============================================================================
 TASK 3: Static rule-based policy engine (baseline, non-AI)
=============================================================================

A deterministic, fully auditable risk-weighting model. Each event accumulates
penalties from independent context signals. The total (clamped to 0-100) maps
to ALLOW / CHALLENGE / BLOCK. Pure Python, a single streaming pass, so it runs
under Application Control too.

The baseline is deliberately "field-local": it inspects each event in isolation
and CANNOT take into account a user's recent history or the behaviour of their
group. This exact blind spot is what the AI model is meant to cover in the next
stage. The baseline output serves as the comparison point for the Task 6
evaluation.

Input:  data/synthetic_enterprise_logs.csv
Output: data/baseline_decisions.csv
=============================================================================
"""

import csv
import os
from collections import defaultdict

# Create the data/ folder if it does not exist (to avoid FileNotFoundError).
os.makedirs('data', exist_ok=True)

IN_FILE = 'data/synthetic_enterprise_logs.csv'
OUT_FILE = 'data/baseline_decisions.csv'

# Base risk value and decision thresholds.
BASE_RISK = 10.0
T_CHALLENGE = 45.0        # >= 45 -> CHALLENGE (MFA required)
T_BLOCK = 75.0            # >= 75 -> BLOCK (immediate rejection)


def baseline_risk(row):
    """[TASK 3] Compute the risk score with deterministic per-signal weights."""
    score = BASE_RISK
    # Rule 1 - network zone (access outside the corporate perimeter).
    if row['network_zone'] == 'Public_Internet':
        score += 35.0
    elif row['network_zone'] == 'VPN_Remote':
        score += 15.0
    # Rule 2 - time of day (extract hour from the timestamp, off-hours 22:00-05:00).
    hour = int(row['timestamp'].split()[1].split(':')[0])
    if hour >= 22 or hour <= 5:
        score += 20.0
    # Rule 3 - resource sensitivity.
    if row['sensitivity'] == 'Privileged':
        score += 25.0
    elif row['sensitivity'] == 'Confidential':
        score += 15.0
    # Rule 4 - action severity (irreversible/modifying actions).
    if row['action'] == 'Delete':
        score += 15.0
    elif row['action'] == 'Write':
        score += 5.0
    # Rule 5 - device trust (unregistered device).
    if row['device_id'].startswith('DEV_UNKNOWN'):
        score += 30.0
    # Rule 6 - failed authentication.
    if row['outcome'] == 'Failure':
        score += 10.0
    return min(score, 100.0)     # clamp to 100


def decide(score):
    """[TASK 3] Map the score to a policy decision."""
    if score >= T_BLOCK:
        return 'BLOCK'
    if score >= T_CHALLENGE:
        return 'CHALLENGE'
    return 'ALLOW'


rows_out = []
# Confusion-matrix counters (detection = BLOCK or CHALLENGE on a true anomaly).
tp = fp = tn = fn = 0
by_type = defaultdict(lambda: {'ALLOW': 0, 'CHALLENGE': 0, 'BLOCK': 0})

# Streaming, line-by-line processing (constant memory, WDAC-compatible).
with open(IN_FILE, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        score = baseline_risk(row)
        action = decide(score)
        is_anom = row['is_anomaly'] == '1'
        detected = action in ('BLOCK', 'CHALLENGE')
        # Count per anomaly category and per confusion-matrix cell.
        if is_anom:
            by_type[row['anomaly_type']][action] += 1
            if detected:
                tp += 1
            else:
                fn += 1
        else:
            if detected:
                fp += 1
            else:
                tn += 1
        rows_out.append({
            'event_id': row['event_id'],
            'baseline_risk_score': round(score, 1),
            'baseline_decision': action,
            'is_anomaly': row['is_anomaly'],
            'anomaly_type': row['anomaly_type'],
        })

# Save the baseline decisions (used in Task 6 for comparison).
with open(OUT_FILE, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['event_id', 'baseline_risk_score',
                                      'baseline_decision', 'is_anomaly', 'anomaly_type'])
    w.writeheader()
    w.writerows(rows_out)

# Overall metrics (across the full dataset).
precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
fpr = fp / (fp + tn) if (fp + tn) else 0

print("=== STATIC BASELINE (full dataset) ===")
print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
print(f"Precision={precision:.3f}  Recall={recall:.3f}  F1={f1:.3f}  FPR={fpr:.3f}")
# Per-type breakdown: reveals the total miss (0%) of the context-dependent
# anomalies (Bulk_Data_Spike, Unusual_Resource_Access) -> motivation for the AI.
print("\nPer-anomaly-type detection:")
for t, d in sorted(by_type.items()):
    tot = sum(d.values())
    det = d['BLOCK'] + d['CHALLENGE']
    print(f"  {t:26s} ALLOW={d['ALLOW']:3d} CHALLENGE={d['CHALLENGE']:3d} "
          f"BLOCK={d['BLOCK']:3d}  detection={100*det/tot:.1f}%")
