# -*- coding: utf-8 -*-
"""
=============================================================================
 TASK 6 (figures + group breakdown) + TASK 7 (drift) + OPTIONAL (fairness)
=============================================================================

TASK 6 (Evaluation & explainability - continued):
  Produces the evaluation figures (score distribution, ROC/PR, feature
  importance, detection per anomaly type) and the group breakdown (per
  department / role / sensitivity).

OPTIONAL TASK (Fairness analysis):
  Computes Precision/Recall/F1/FPR/FNR per department and per role, to detect
  disproportionate false-positive rates (FPR) across groups (the fairness pillar
  of Responsible AI). Also produces the corresponding figure.

TASK 7 (Drift simulation & governance):
  Simulates a "remote-work week" scenario (concept drift) on the eval window
  WITHOUT retraining, measures the precision collapse, and tests one mitigation
  (a temporary "corporate VPN -30 points" rule).

Reads the intermediate artifacts (_eval.pkl / _models.pkl) from 03_ai_pipeline.py.
Output: figures/fig1..fig6, data/fairness_by_*.csv, data/drift_summary.csv
=============================================================================
"""

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')       # no-display backend (save to files)
import matplotlib.pyplot as plt
from sklearn.metrics import (precision_recall_fscore_support, roc_auc_score,
                             average_precision_score, precision_recall_curve,
                             roc_curve, confusion_matrix)
import joblib

plt.rcParams.update({'figure.dpi': 120, 'font.size': 10})
CLR_AI, CLR_BASE = '#1f6feb', '#d1495b'     # blue = AI, red = baseline

# Create the data/ and figures/ folders if they do not exist.
os.makedirs('data', exist_ok=True)
os.makedirs('figures', exist_ok=True)

# Load the intermediate artifacts produced by 03_ai_pipeline.py.
ev = pd.read_pickle('data/_eval.pkl')
full = pd.read_pickle('data/_full.pkl')
M = joblib.load('data/_models.pkl')
clf, iso, FEATURES, BEHAV = M['clf'], M['iso'], M['features'], M['behav']

y = ev['is_anomaly'].values
proba = ev['risk_ai'].values / 100.0
# The baseline on the SAME eval window (for a fair comparison in the figures).
base = pd.read_csv('data/baseline_decisions.csv').set_index('event_id').loc[ev['event_id']].reset_index()
base_proba = base['baseline_risk_score'].values / 100.0

# ---------------------------------------------------------------------------
# [TASK 6] Figure 1: AI risk score distribution (normal vs anomaly)
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(7, 4))
ax.hist(ev.loc[ev.is_anomaly == 0, 'risk_ai'], bins=40, alpha=.7,
        label='Normal', color='#2a9d8f')
ax.hist(ev.loc[ev.is_anomaly == 1, 'risk_ai'], bins=40, alpha=.7,
        label='Anomaly', color=CLR_BASE)
ax.axvline(45, ls='--', c='gray'); ax.axvline(75, ls='--', c='k')
ax.text(46, ax.get_ylim()[1]*.7, 'CHALLENGE', fontsize=8)
ax.text(76, ax.get_ylim()[1]*.7, 'BLOCK', fontsize=8)
ax.set_xlabel('AI Risk Score (0-100)'); ax.set_ylabel('Count (log)')
ax.set_yscale('log'); ax.set_title('AI Risk Score Distribution (held-out eval)')
ax.legend()
fig.tight_layout(); fig.savefig('figures/fig1_score_distribution.png'); plt.close()

# ---------------------------------------------------------------------------
# [TASK 6] Figure 2: ROC + Precision-Recall curves, AI vs baseline
# ---------------------------------------------------------------------------
fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.3))
for name, pr, clr in [('AI-Assisted', proba, CLR_AI), ('Static Baseline', base_proba, CLR_BASE)]:
    fpr, tpr, _ = roc_curve(y, pr)
    a1.plot(fpr, tpr, color=clr, label=f'{name} (AUC={roc_auc_score(y, pr):.3f})')
    prec, rec, _ = precision_recall_curve(y, pr)
    a2.plot(rec, prec, color=clr, label=f'{name} (AP={average_precision_score(y, pr):.3f})')
a1.plot([0, 1], [0, 1], ls='--', c='gray'); a1.set_xlabel('FPR'); a1.set_ylabel('TPR')
a1.set_title('ROC Curve'); a1.legend(loc='lower right')
a2.set_xlabel('Recall'); a2.set_ylabel('Precision'); a2.set_title('Precision-Recall Curve')
a2.legend(loc='lower left')
fig.tight_layout(); fig.savefig('figures/fig2_roc_pr.png'); plt.close()

# ---------------------------------------------------------------------------
# [TASK 6] Figure 3: feature importance (permutation importance)
# ---------------------------------------------------------------------------
from sklearn.inspection import permutation_importance
imp = permutation_importance(clf, ev[FEATURES], y, n_repeats=10,
                             random_state=25012, scoring='average_precision')
order = np.argsort(imp.importances_mean)
fig, ax = plt.subplots(figsize=(7, 4.5))
ax.barh([FEATURES[i] for i in order], imp.importances_mean[order],
        xerr=imp.importances_std[order], color=CLR_AI)
ax.set_xlabel('Permutation importance (drop in PR-AUC)')
ax.set_title('Feature Importance (held-out eval)')
fig.tight_layout(); fig.savefig('figures/fig3_feature_importance.png'); plt.close()

# ---------------------------------------------------------------------------
# [TASK 6] Figure 4: detection per anomaly type, baseline vs AI
#          (shows that the AI covers the baseline's blind spots)
# ---------------------------------------------------------------------------
ev['ai_det'] = ev['final_decision'].isin(['BLOCK', 'CHALLENGE'])
base_dec = base.set_index('event_id')['baseline_decision']
ev['base_det'] = ev['event_id'].map(base_dec).isin(['BLOCK', 'CHALLENGE'])
an = ev[ev.is_anomaly == 1]
types = sorted(an['anomaly_type'].unique())
ai_rate = [100*an.loc[an.anomaly_type == t, 'ai_det'].mean() for t in types]
base_rate = [100*an.loc[an.anomaly_type == t, 'base_det'].mean() for t in types]
x = np.arange(len(types)); w = 0.38
fig, ax = plt.subplots(figsize=(9, 4.3))
ax.bar(x - w/2, base_rate, w, label='Static Baseline', color=CLR_BASE)
ax.bar(x + w/2, ai_rate, w, label='AI-Assisted', color=CLR_AI)
ax.set_xticks(x); ax.set_xticklabels([t.replace('_', '\n') for t in types], fontsize=8)
ax.set_ylabel('Detection rate (%)'); ax.set_ylim(0, 105)
ax.set_title('Detection Rate per Anomaly Type (held-out eval)')
ax.legend()
fig.tight_layout(); fig.savefig('figures/fig4_per_type.png'); plt.close()

# ---------------------------------------------------------------------------
# [TASK 6 / OPTIONAL] Group breakdown (department / role / sensitivity)
# ---------------------------------------------------------------------------
def group_metrics(frame, col):
    """Compute metrics per value of column col (for fairness / breakdown)."""
    rows = []
    for g, sub in frame.groupby(col):
        yy = sub['is_anomaly'].values
        pp = sub['ai_det'].astype(int).values
        if yy.sum() == 0 and (yy == 0).sum() == 0:
            continue
        p, r, f1, _ = precision_recall_fscore_support(yy, pp, average='binary', zero_division=0)
        n_norm = int((yy == 0).sum()); n_anom = int(yy.sum())
        fp = int(((yy == 0) & (pp == 1)).sum())
        fn = int(((yy == 1) & (pp == 0)).sum())
        fpr = fp / n_norm if n_norm else 0     # false positives (cost for legitimate users)
        fnr = fn / n_anom if n_anom else 0     # misses (security cost)
        rows.append({col: g, 'n': len(sub), 'anomalies': n_anom,
                     'precision': round(p, 3), 'recall': round(r, 3),
                     'F1': round(f1, 3), 'FPR': round(fpr, 3), 'FNR': round(fnr, 3)})
    return pd.DataFrame(rows)

print("=== GROUP BREAKDOWN: department ===")
gdept = group_metrics(ev, 'department'); print(gdept.to_string(index=False))
print("\n=== GROUP BREAKDOWN: role ===")
grole = group_metrics(ev, 'role'); print(grole.to_string(index=False))
print("\n=== GROUP BREAKDOWN: sensitivity ===")
gsens = group_metrics(ev, 'sensitivity'); print(gsens.to_string(index=False))
gdept.to_csv('data/fairness_by_department.csv', index=False)
grole.to_csv('data/fairness_by_role.csv', index=False)
gsens.to_csv('data/fairness_by_sensitivity.csv', index=False)

# [OPTIONAL] Figure 5: FPR per department and per role (fairness analysis)
fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4))
a1.bar(gdept['department'], gdept['FPR'], color=CLR_AI)
a1.set_title('False Positive Rate by Department'); a1.set_ylabel('FPR')
a1.tick_params(axis='x', rotation=20)
a2.bar(grole['role'], grole['FPR'], color='#e9925f')
a2.set_title('False Positive Rate by Role'); a2.set_ylabel('FPR')
fig.tight_layout(); fig.savefig('figures/fig5_fairness.png'); plt.close()

# ---------------------------------------------------------------------------
# [TASK 7] DRIFT scenario: a "remote-work week" applied to the eval window
# ---------------------------------------------------------------------------
drift = ev.copy()
rng = np.random.default_rng(25012)
# 100% of the connections move off the corporate LAN -> VPN / home networks.
mask_internal = drift['network_zone'] == 'Internal_Corporate'
drift.loc[mask_internal, 'network_zone'] = 'VPN_Remote'
drift['zone_risk'] = drift['network_zone'].map(
    {'Internal_Corporate': 0, 'VPN_Remote': 1, 'Public_Internet': 2})
# Shifted hours -> more off-hours. A share of new personal devices.
shift = rng.integers(0, 6, len(drift))
drift['hour'] = (drift['hour'] + shift) % 24
drift['is_off_hours'] = ((drift['hour'] >= 22) | (drift['hour'] <= 5)).astype(int)
new_dev = rng.random(len(drift)) < 0.25
drift.loc[new_dev, 'device_novelty'] = 1
# user_hour_deviation would need history; approximated by adding the shift.
drift['user_hour_deviation'] = (drift['user_hour_deviation'] + shift).astype(float)
# Recompute iso_score and AI score on the drifted features (WITHOUT retraining).
drift['iso_score'] = -iso.score_samples(drift[BEHAV])
drift['risk_ai'] = (clf.predict_proba(drift[FEATURES])[:, 1] * 100).round(1)

def eval_block(frame, proba_col='risk_ai'):
    """Metrics with the same thresholds/overrides, for a before/after comparison."""
    yy = frame['is_anomaly'].values
    pr = frame[proba_col].values / 100.0
    det = ((frame['risk_ai'] >= 45) |
           ((frame['risk_ai'] < 45) & (frame['zone_risk'] == 2)) |
           ((frame['risk_ai'] < 45) & (frame['sensitivity_mismatch'] == 1) &
            (frame['cross_department'] == 1))).astype(int).values
    p, r, f1, _ = precision_recall_fscore_support(yy, det, average='binary', zero_division=0)
    n_norm = int((yy == 0).sum()); fp = int(((yy == 0) & (det == 1)).sum())
    return dict(precision=round(p, 3), recall=round(r, 3), f1=round(f1, 3),
                fp=fp, fpr=round(fp/n_norm, 3),
                roc=round(roc_auc_score(yy, pr), 3),
                challenge_block=int(det.sum()))

before = eval_block(ev)
after = eval_block(drift)
print("\n=== DRIFT: before vs after (remote-work week) ===")
print("BEFORE:", before)
print("AFTER :", after)

# [TASK 7] Mitigation: a temporary "corporate VPN -30 points" rule (rule update).
drift_mit = drift.copy()
drift_mit['risk_ai'] = (drift_mit['risk_ai'] - 30 * (drift_mit['zone_risk'] == 1)).clip(lower=0)
after_mit = eval_block(drift_mit)
print("AFTER + mitigation (VPN -30, recalib):", after_mit)

# [TASK 7] Figure 6: impact of the drift and the mitigation
labels = ['Precision', 'Recall', 'FPR']
bvals = [before['precision'], before['recall'], before['fpr']]
avals = [after['precision'], after['recall'], after['fpr']]
mvals = [after_mit['precision'], after_mit['recall'], after_mit['fpr']]
x = np.arange(len(labels)); w = 0.26
fig, ax = plt.subplots(figsize=(8, 4.3))
ax.bar(x - w, bvals, w, label='Before drift', color=CLR_AI)
ax.bar(x, avals, w, label='After drift', color=CLR_BASE)
ax.bar(x + w, mvals, w, label='After + mitigation', color='#2a9d8f')
ax.set_xticks(x); ax.set_xticklabels(labels)
ax.set_title('System Behaviour under Remote-Work Drift'); ax.legend()
fig.tight_layout(); fig.savefig('figures/fig6_drift.png'); plt.close()

# Save the drift summary (before / after / after_mitigation).
pd.DataFrame([{'scenario': 'before', **before},
              {'scenario': 'after_drift', **after},
              {'scenario': 'after_mitigation', **after_mit}]
             ).to_csv('data/drift_summary.csv', index=False)

print("\nFigures written to figures/. Summary CSVs written to data/.")
