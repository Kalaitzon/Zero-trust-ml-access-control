# -*- coding: utf-8 -*-
"""
=============================================================================
 TASK 4, TASK 5 & TASK 6: Hybrid AI model + decision engine + evaluation
=============================================================================

TASK 4 (Hybrid AI risk-scoring model):
  HYBRID approach. (a) Unsupervised signal: an IsolationForest is trained on the
  behavioural features of the training window and its anomaly score is fed back
  in as an extra feature (the "hybrid" element, following the anomaly-detection
  material). (b) Supervised scorer: a HistGradientBoosting classifier consumes
  all features and produces a calibrated probability, scaled to 0-100.

  Temporal-leakage prevention: events are sorted chronologically. The first 70%
  is the training window, the last 30% the held-out evaluation window. All
  rolling features are computed causally (past-only), so no future information
  leaks into a row's features.

TASK 5 (Dynamic decision engine):
  The decide() function converts the score to ALLOW / CHALLENGE / BLOCK with
  explicit Zero-Trust overrides (external-network safety net, lateral movement)
  and produces a reason (decision_reason) for each event.

TASK 6 (Evaluation - part):
  Computes the held-out metrics (Precision/Recall/F1, ROC-AUC, PR-AUC) and
  compares against the baseline on the SAME eval window. The rest of Task 6
  (figures, group breakdown) is done in 04_drift_fairness_plots.py.

Input:  data/synthetic_enterprise_logs.csv, data/baseline_decisions.csv
Output: data/evaluated_risk_logs.csv, data/dynamic_access_decisions.csv,
        data/_eval.pkl, data/_full.pkl, data/_models.pkl (intermediate artifacts)
=============================================================================
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.metrics import (classification_report, precision_recall_fscore_support,
                             roc_auc_score, average_precision_score,
                             precision_recall_curve, roc_curve, confusion_matrix)

RNG = 25012                    # fixed seed -> reproducibility
LOGS = 'data/synthetic_enterprise_logs.csv'

# Create the data/ folder if it does not exist (to avoid FileNotFoundError).
os.makedirs('data', exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Load + chronological ordering (the basis for avoiding temporal leakage)
# ---------------------------------------------------------------------------
df = pd.read_csv(LOGS)
df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values('timestamp').reset_index(drop=True)

# ---------------------------------------------------------------------------
# [TASK 4] 2. Feature engineering: causal (past-only) behavioural/contextual
#             features. They give the model the "context" that the baseline's
#             static rules lack.
# ---------------------------------------------------------------------------
df['hour'] = df['timestamp'].dt.hour
df['is_off_hours'] = ((df['hour'] >= 22) | (df['hour'] <= 5)).astype(int)
df['is_failure'] = (df['outcome'] == 'Failure').astype(int)

# Helper for rolling counts per user over a time window.
def rolling_count(group_key, window, on_col=None, agg='count'):
    s = df.set_index('timestamp').groupby(group_key)
    col = on_col if on_col else df.columns[0]
    r = s[col].rolling(window)
    r = r.count() if agg == 'count' else r.sum()
    return r.reset_index(level=0, drop=True).sort_index().values

# Feature A - access_frequency: user's request count in the previous 5 minutes.
#             Detects Bulk_Data_Spike (the frequency, not the single request).
df['access_frequency'] = rolling_count('user_id', '5min', on_col='event_id', agg='count')

# Feature B - recent_failure_count: user's failures in the previous 10 minutes.
#             Detects Privilege_Escalation (brute-force / credential stuffing).
df['recent_failure_count'] = rolling_count('user_id', '10min', on_col='is_failure', agg='sum')

# Feature C - session_resource_variety: distinct resources by the user in 15 min.
def rolling_nunique(window):
    out = np.zeros(len(df))
    for uid, g in df.groupby('user_id'):
        g = g.sort_values('timestamp')
        times = g['timestamp'].values
        res = g['resource_id'].values
        idx = g.index.values
        for i in range(len(g)):
            lo = times[i] - np.timedelta64(window, 'm')
            mask = (times[:i + 1] >= lo)
            out[idx[i]] = len(set(res[:i + 1][mask]))   # past only (causal)
    return out

df['session_resource_variety'] = rolling_nunique(15)

# Feature D - device_novelty: first time this user is seen on this device
#             (past-only), or an unknown device (DEV_UNKNOWN).
seen = set()
novel = np.zeros(len(df), dtype=int)
for i, (u, d) in enumerate(zip(df['user_id'], df['device_id'])):
    key = (u, d)
    if str(d).startswith('DEV_UNKNOWN') or key not in seen:
        novel[i] = 1
    seen.add(key)
df['device_novelty'] = novel

# Feature E - sensitivity_mismatch: a low-rank role (Intern/Employee) touching
#             high-sensitivity data (Confidential/Privileged).
df['sensitivity_mismatch'] = (
    df['role'].isin(['Intern', 'Employee']) &
    df['sensitivity'].isin(['Confidential', 'Privileged'])
).astype(int)

# Feature F - peer_rarity_score: how rare the resource is for the user's
#             department (running count, not the global table -> causal).
pair = {}
dept = {}
rarity = np.zeros(len(df))
for i, (dp, rs) in enumerate(zip(df['department'], df['resource_id'])):
    p = pair.get((dp, rs), 0)
    t = dept.get(dp, 0)
    rarity[i] = 1.0 - (p / t) if t > 0 else 1.0
    pair[(dp, rs)] = p + 1
    dept[dp] = t + 1
df['peer_rarity_score'] = rarity

# Feature G - user_hour_deviation: deviation of the hour from the running mean
#             access hour of THIS user (per-user baseline, not per-department).
run_sum = {}
run_n = {}
hdev = np.zeros(len(df))
for i, (u, h) in enumerate(zip(df['user_id'], df['hour'])):
    n = run_n.get(u, 0)
    mean = run_sum.get(u, 0) / n if n else h
    hdev[i] = abs(h - mean)
    run_sum[u] = run_sum.get(u, 0) + h
    run_n[u] = n + 1
df['user_hour_deviation'] = hdev

# Contextual: numeric encoding of the network zone.
zone_risk = {'Internal_Corporate': 0, 'VPN_Remote': 1, 'Public_Internet': 2}
df['zone_risk'] = df['network_zone'].map(zone_risk)

# Feature - cross_department: the resource id encodes a department tag different
#           from the user's department (a precise lateral-movement signal for
#           Unusual_Resource_Access).
dept_tag = {'ENG': 'Engineering', 'FIN': 'Finance', 'HR': 'HR', 'SAL': 'Sales'}
def is_foreign(row):
    for tag, d in dept_tag.items():
        if f"_{tag}_" in row['resource_id']:
            return int(d != row['department'])
    return 0
df['cross_department'] = df.apply(is_foreign, axis=1)

# The final set of behavioural features (without iso_score, which is added next).
BEHAV = ['access_frequency', 'recent_failure_count', 'session_resource_variety',
         'is_off_hours', 'device_novelty', 'sensitivity_mismatch',
         'peer_rarity_score', 'user_hour_deviation', 'zone_risk',
         'cross_department']

# ---------------------------------------------------------------------------
# [TASK 4] 3. Temporal split (70% train / 30% eval) - avoids temporal leakage
# ---------------------------------------------------------------------------
split = int(len(df) * 0.70)
train, ev = df.iloc[:split].copy(), df.iloc[split:].copy()
print(f"Train={len(train)} (anom={train.is_anomaly.sum()}) | "
      f"Eval={len(ev)} (anom={ev.is_anomaly.sum()})")

# ---------------------------------------------------------------------------
# [TASK 4] 4. Hybrid: the IsolationForest score as an extra feature
#             (the unsupervised part -> optional: supervised vs unsupervised)
# ---------------------------------------------------------------------------
iso = IsolationForest(n_estimators=200, contamination=0.06, random_state=RNG)
iso.fit(train[BEHAV])                      # train ONLY on the train set (no leakage)
# Higher score = more anomalous.
df['iso_score'] = -iso.score_samples(df[BEHAV])
train['iso_score'] = df['iso_score'].iloc[:split].values
ev['iso_score'] = df['iso_score'].iloc[split:].values

FEATURES = BEHAV + ['iso_score']

# ---------------------------------------------------------------------------
# [TASK 4] 5. Supervised scorer: HistGradientBoosting
# ---------------------------------------------------------------------------
# Class imbalance (~6% anomalies) -> sample weights so the model penalises a
# missed anomaly more heavily.
pos_w = (train['is_anomaly'] == 0).sum() / max(1, (train['is_anomaly'] == 1).sum())
sw = np.where(train['is_anomaly'] == 1, pos_w, 1.0)

clf = HistGradientBoostingClassifier(max_iter=300, max_depth=6,
                                     learning_rate=0.08, l2_regularization=1.0,
                                     random_state=RNG)
clf.fit(train[FEATURES], train['is_anomaly'], sample_weight=sw)

# Anomaly probability -> scaled to 0-100 (the AI Risk Score).
df['risk_ai'] = (clf.predict_proba(df[FEATURES])[:, 1] * 100).round(1)
ev['risk_ai'] = df['risk_ai'].iloc[split:].values
train['risk_ai'] = df['risk_ai'].iloc[:split].values

# ---------------------------------------------------------------------------
# [TASK 5] 6. Dynamic decision engine: score + contextual overrides
# ---------------------------------------------------------------------------
def decide(row):
    """[TASK 5] Convert the AI score to a decision with explicit Zero-Trust rules."""
    s = row['risk_ai']
    # Critical risk -> immediate BLOCK.
    if s >= 75:
        return 'BLOCK', f"Critical AI risk ({s:.0f}/100). High probability of active compromise."
    # Hard Zero-Trust safety net: a successful access from the public internet is
    # never auto-approved, regardless of the score (perimeter-breach guarantee).
    if s < 45 and row['zone_risk'] == 2:
        return 'CHALLENGE', (f"Low AI risk ({s:.0f}/100) overridden by policy: "
                             f"access from public internet requires step-up MFA.")
    # Medium risk -> CHALLENGE (step-up MFA), with a specialised reason.
    if s >= 45:
        if row['device_novelty'] == 1:
            why = "unrecognised device"
        elif row['is_off_hours'] == 1:
            why = "anomalous off-hours access"
        elif row['recent_failure_count'] >= 3:
            why = "repeated recent authentication failures"
        else:
            why = "behavioural deviation from baseline"
        return 'CHALLENGE', f"Medium AI risk ({s:.0f}/100). Context: {why}. Step-up MFA required."
    # Low score but Zero-Trust override: escalate to CHALLENGE only for genuine
    # lateral movement (low-rank role -> high-sensitivity resource of ANOTHER
    # department). This way routine in-department work is not needlessly challenged.
    if row['sensitivity_mismatch'] == 1 and row['cross_department'] == 1:
        return 'CHALLENGE', (f"Low AI risk ({s:.0f}/100) overridden by context: "
                             f"cross-department access to sensitive data "
                             f"(possible lateral movement). Escalated to manager approval.")
    # Low risk with no violation -> ALLOW.
    return 'ALLOW', f"Low AI risk ({s:.0f}/100). Request matches baseline behaviour."

dec = df.apply(decide, axis=1)
df['final_decision'] = [d[0] for d in dec]
df['decision_reason'] = [d[1] for d in dec]
ev['final_decision'] = df['final_decision'].iloc[split:].values

# ---------------------------------------------------------------------------
# [TASK 6] 7. Evaluation on the held-out window
# ---------------------------------------------------------------------------
y = ev['is_anomaly'].values
proba = ev['risk_ai'].values / 100.0
pred_hard = (clf.predict(ev[FEATURES])).astype(int)   # the model's own 0.5 threshold
pred_dec = ev['final_decision'].isin(['BLOCK', 'CHALLENGE']).astype(int).values

print("\n=== AI MODEL (held-out eval, model classifier) ===")
print(classification_report(y, pred_hard, digits=3, target_names=['Normal', 'Anomaly']))
print(f"ROC-AUC = {roc_auc_score(y, proba):.3f}")
print(f"PR-AUC  = {average_precision_score(y, proba):.3f}")

# Metrics of the full decision engine (BLOCK/CHALLENGE = detected).
p, r, f1, _ = precision_recall_fscore_support(y, pred_dec, average='binary', zero_division=0)
print("\n=== FULL DECISION ENGINE (BLOCK/CHALLENGE = detected) ===")
print(f"Precision={p:.3f} Recall={r:.3f} F1={f1:.3f}")

# [TASK 6] Compare against the baseline on the SAME eval window (fair comparison).
base = pd.read_csv('data/baseline_decisions.csv')
base = base.set_index('event_id').loc[ev['event_id']].reset_index()
base_pred = base['baseline_decision'].isin(['BLOCK', 'CHALLENGE']).astype(int).values
bp, br, bf1, _ = precision_recall_fscore_support(y, base_pred, average='binary', zero_division=0)
# The baseline "probability" (for ROC/PR) is the normalised risk score.
base_proba = base['baseline_risk_score'].values / 100.0
print("\n=== STATIC BASELINE (same eval window) ===")
print(f"Precision={bp:.3f} Recall={br:.3f} F1={bf1:.3f}")
print(f"ROC-AUC={roc_auc_score(y, base_proba):.3f}  PR-AUC={average_precision_score(y, base_proba):.3f}")

# ---------------------------------------------------------------------------
# 8. Save the deliverable files
# ---------------------------------------------------------------------------
# [TASK 4] evaluated_risk_logs.csv: full log + all features + AI score + decision.
df_out = df.copy()
df_out['calculated_risk_score_ai'] = df_out['risk_ai']
cols_scores = (['event_id', 'timestamp', 'user_id', 'role', 'department',
                'network_zone', 'device_id', 'resource_id', 'sensitivity',
                'action', 'outcome'] + FEATURES +
               ['calculated_risk_score_ai', 'final_decision', 'decision_reason',
                'is_anomaly', 'anomaly_type'])
df_out[cols_scores].to_csv('data/evaluated_risk_logs.csv', index=False)
# [TASK 5] dynamic_access_decisions.csv: the marker-facing audit log (4 columns).
df_out[['event_id', 'calculated_risk_score_ai', 'final_decision',
        'decision_reason']].to_csv('data/dynamic_access_decisions.csv', index=False)

# Intermediate artifacts (eval frame + models) for the next script (Task 6/7/optional).
ev.to_pickle('data/_eval.pkl')
df.to_pickle('data/_full.pkl')
import joblib
joblib.dump({'clf': clf, 'iso': iso, 'features': FEATURES, 'behav': BEHAV,
             'split': split}, 'data/_models.pkl')
print("\nSaved: evaluated_risk_logs.csv, dynamic_access_decisions.csv, _eval.pkl, _models.pkl")
