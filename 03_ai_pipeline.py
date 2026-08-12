# Ioannis Kalaitzidis, MTE25012

"""
=============================================================================
 TASK 4, TASK 5 & TASK 6: Υβριδικό μοντέλο AI + μηχανή αποφάσεων + αξιολόγηση

TASK 4 (Υβριδικό μοντέλο AI risk-scoring):
  Προσέγγιση HYBRID. (α) Unsupervised σήμα: ένα IsolationForest εκπαιδεύεται στα
  behavioural features του training window και το σκορ ανωμαλίας του
  επανεισάγεται ως επιπλέον feature (το "υβριδικό" στοιχείο, σύμφωνα με την ύλη
  για anomaly detection). (β) Supervised scorer: ένας HistGradientBoosting
  ταξινομητής καταναλώνει όλα τα features και παράγει βαθμονομημένη πιθανότητα,
  κλιμακωμένη στο 0-100.

  Αποφυγή temporal leakage: τα συμβάντα ταξινομούνται χρονικά. Το πρώτο 70% είναι
  το training window, το τελευταίο 30% το held-out evaluation. Ολα τα rolling
  features υπολογίζονται αιτιακά (past-only), ώστε καμία μελλοντική πληροφορία να
  μη διαρρέει στα features μιας γραμμής.

TASK 5 (Μηχανή δυναμικών αποφάσεων):
  Η συνάρτηση decide() μετατρέπει το σκορ σε ALLOW / CHALLENGE / BLOCK με ρητούς
  Zero-Trust overrides (external-network safety net, lateral movement) και
  παράγει αιτιολογία (decision_reason) για κάθε συμβάν.

TASK 6 (Αξιολόγηση - μέρος):
  Υπολογισμός των μετρικών στο held-out (Precision/Recall/F1, ROC-AUC, PR-AUC)
  και σύγκριση με τον baseline στο ΙΔΙΟ eval window. Οι υπόλοιπες αναλύσεις του
  Task 6 (γραφήματα, group breakdown) γίνονται στο 04_drift_fairness_plots.py.

Είσοδος:  data/synthetic_enterprise_logs.csv, data/baseline_decisions.csv
Έξοδος:   data/evaluated_risk_logs.csv, data/dynamic_access_decisions.csv,
          data/_eval.pkl, data/_full.pkl, data/_models.pkl (ενδιάμεσα artifacts)
=============================================================================
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.metrics import (classification_report, precision_recall_fscore_support,
                             roc_auc_score, average_precision_score,
                             precision_recall_curve, roc_curve, confusion_matrix)

RNG = 25012                    # σταθερός σπόρος -> αναπαραγωγιμότητα
LOGS = 'data/synthetic_enterprise_logs.csv'

# ---------------------------------------------------------------------------
# 1. Φόρτωση + χρονολογική ταξινόμηση (θεμέλιο για αποφυγή temporal leakage)
# ---------------------------------------------------------------------------
df = pd.read_csv(LOGS)
df['timestamp'] = pd.to_datetime(df['timestamp'])
df = df.sort_values('timestamp').reset_index(drop=True)

# ---------------------------------------------------------------------------
# [TASK 4] Feature engineering: αιτιακά (past-only) behavioural/contextual
#          χαρακτηριστικά. Δίνουν στο μοντέλο το "πλαίσιο" που λείπει από τους
#          στατικούς κανόνες του baseline.
# ---------------------------------------------------------------------------
df['hour'] = df['timestamp'].dt.hour
df['is_off_hours'] = ((df['hour'] >= 22) | (df['hour'] <= 5)).astype(int)
df['is_failure'] = (df['outcome'] == 'Failure').astype(int)

# Βοηθητική συνάρτηση για rolling μετρήσεις ανά χρήστη πάνω σε χρονικό παράθυρο.
def rolling_count(group_key, window, on_col=None, agg='count'):
    s = df.set_index('timestamp').groupby(group_key)
    col = on_col if on_col else df.columns[0]
    r = s[col].rolling(window)
    r = r.count() if agg == 'count' else r.sum()
    return r.reset_index(level=0, drop=True).sort_index().values

# Feature A - access_frequency: αιτήματα του χρήστη στα προηγούμενα 5 λεπτά.
#             Ανιχνεύει Bulk_Data_Spike (η συχνότητα, όχι το μεμονωμένο αίτημα).
df['access_frequency'] = rolling_count('user_id', '5min', on_col='event_id', agg='count')

# Feature B - recent_failure_count: αποτυχίες του χρήστη στα προηγούμενα 10 λεπτά.
#             Ανιχνεύει Privilege_Escalation (brute-force / credential stuffing).
df['recent_failure_count'] = rolling_count('user_id', '10min', on_col='is_failure', agg='sum')

# Feature C - session_resource_variety: διακριτοί πόροι του χρήστη σε 15 λεπτά.
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
            out[idx[i]] = len(set(res[:i + 1][mask]))   # μόνο παρελθόν (αιτιακό)
    return out

df['session_resource_variety'] = rolling_nunique(15)

# Feature D - device_novelty: πρώτη φορά που ο χρήστης εμφανίζεται σε αυτή τη
#             συσκευή (past-only), ή άγνωστη συσκευή (DEV_UNKNOWN).
seen = set()
novel = np.zeros(len(df), dtype=int)
for i, (u, d) in enumerate(zip(df['user_id'], df['device_id'])):
    key = (u, d)
    if str(d).startswith('DEV_UNKNOWN') or key not in seen:
        novel[i] = 1
    seen.add(key)
df['device_novelty'] = novel

# Feature E - sensitivity_mismatch: χαμηλός ρόλος (Intern/Employee) που αγγίζει
#             δεδομένα υψηλής ευαισθησίας (Confidential/Privileged).
df['sensitivity_mismatch'] = (
    df['role'].isin(['Intern', 'Employee']) &
    df['sensitivity'].isin(['Confidential', 'Privileged'])
).astype(int)

# Feature F - peer_rarity_score: πόσο σπάνιος είναι ο πόρος για το τμήμα του
#             χρήστη (running υπολογισμός, όχι από τον καθολικό πίνακα -> αιτιακό).
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

# Feature G - user_hour_deviation: απόκλιση της ώρας από τη running μέση ώρα
#             πρόσβασης του ΣΥΓΚΕΚΡΙΜΕΝΟΥ χρήστη (per-user baseline, όχι per-dept).
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

# Contextual: αριθμητική κωδικοποίηση ζώνης δικτύου.
zone_risk = {'Internal_Corporate': 0, 'VPN_Remote': 1, 'Public_Internet': 2}
df['zone_risk'] = df['network_zone'].map(zone_risk)

# Feature - cross_department: το id του πόρου κωδικοποιεί τμήμα διαφορετικό από το
#           τμήμα του χρήστη (ακριβές σήμα lateral movement για Unusual_Resource).
dept_tag = {'ENG': 'Engineering', 'FIN': 'Finance', 'HR': 'HR', 'SAL': 'Sales'}
def is_foreign(row):
    for tag, d in dept_tag.items():
        if f"_{tag}_" in row['resource_id']:
            return int(d != row['department'])
    return 0
df['cross_department'] = df.apply(is_foreign, axis=1)

# Το τελικό σύνολο των behavioural features (χωρίς το iso_score, που προστίθεται).
BEHAV = ['access_frequency', 'recent_failure_count', 'session_resource_variety',
         'is_off_hours', 'device_novelty', 'sensitivity_mismatch',
         'peer_rarity_score', 'user_hour_deviation', 'zone_risk',
         'cross_department']

# ---------------------------------------------------------------------------
# [TASK 4] Temporal split (70% train / 30% eval) - αποφυγή temporal leakage
# ---------------------------------------------------------------------------
split = int(len(df) * 0.70)
train, ev = df.iloc[:split].copy(), df.iloc[split:].copy()
print(f"Train={len(train)} (anom={train.is_anomaly.sum()}) | "
      f"Eval={len(ev)} (anom={ev.is_anomaly.sum()})")

# ---------------------------------------------------------------------------
# [TASK 4] Hybrid: το σκορ του IsolationForest ως επιπλέον feature
#             (το unsupervised σκέλος -> προαιρετικό: supervised vs unsupervised)
# ---------------------------------------------------------------------------
iso = IsolationForest(n_estimators=200, contamination=0.06, random_state=RNG)
iso.fit(train[BEHAV])                      # εκπαίδευση ΜΟΝΟ στο train (no leakage)
# Υψηλότερο σκορ = πιο ανώμαλο.
df['iso_score'] = -iso.score_samples(df[BEHAV])
train['iso_score'] = df['iso_score'].iloc[:split].values
ev['iso_score'] = df['iso_score'].iloc[split:].values

FEATURES = BEHAV + ['iso_score']

# ---------------------------------------------------------------------------
# [TASK 4] Supervised scorer: HistGradientBoosting
# ---------------------------------------------------------------------------
# Class imbalance (~6% ανωμαλίες) -> sample weights ώστε το μοντέλο να τιμωρεί
# αυστηρότερα τη διαφυγή μιας ανωμαλίας.
pos_w = (train['is_anomaly'] == 0).sum() / max(1, (train['is_anomaly'] == 1).sum())
sw = np.where(train['is_anomaly'] == 1, pos_w, 1.0)

clf = HistGradientBoostingClassifier(max_iter=300, max_depth=6,
                                     learning_rate=0.08, l2_regularization=1.0,
                                     random_state=RNG)
clf.fit(train[FEATURES], train['is_anomaly'], sample_weight=sw)

# Πιθανότητα ανωμαλίας -> κλιμάκωση στο 0-100 (το AI Risk Score).
df['risk_ai'] = (clf.predict_proba(df[FEATURES])[:, 1] * 100).round(1)
ev['risk_ai'] = df['risk_ai'].iloc[split:].values
train['risk_ai'] = df['risk_ai'].iloc[:split].values

# ---------------------------------------------------------------------------
# [TASK 5] Μηχανή δυναμικών αποφάσεων: σκορ + contextual overrides
# ---------------------------------------------------------------------------
def decide(row):
    """[TASK 5] Μετατρέπει το AI score σε απόφαση με ρητούς Zero-Trust κανόνες."""
    s = row['risk_ai']
    # Κρίσιμο ρίσκο -> άμεσο BLOCK.
    if s >= 75:
        return 'BLOCK', f"Critical AI risk ({s:.0f}/100). High probability of active compromise."
    # Hard Zero-Trust δίχτυ ασφαλείας: επιτυχής πρόσβαση από το public internet ΔΕΝ
    # εγκρίνεται ποτέ αυτόματα, ανεξαρτήτως σκορ (εγγύηση κατά perimeter breach).
    if s < 45 and row['zone_risk'] == 2:
        return 'CHALLENGE', (f"Low AI risk ({s:.0f}/100) overridden by policy: "
                             f"access from public internet requires step-up MFA.")
    # Μεσαίο ρίσκο -> CHALLENGE (step-up MFA), με εξειδικευμένη αιτιολογία.
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
    # Χαμηλό σκορ αλλά Zero-Trust override: αναβάθμιση σε CHALLENGE μόνο για γνήσιο
    # lateral movement (χαμηλός ρόλος -> πόρος υψηλής ευαισθησίας ΑΛΛΟΥ τμήματος).
    # Ετσι η καθημερινή εργασία εντός τμήματος δεν προκαλεί άσκοπα challenges.
    if row['sensitivity_mismatch'] == 1 and row['cross_department'] == 1:
        return 'CHALLENGE', (f"Low AI risk ({s:.0f}/100) overridden by context: "
                             f"cross-department access to sensitive data "
                             f"(possible lateral movement). Escalated to manager approval.")
    # Χαμηλό ρίσκο χωρίς παραβίαση -> ALLOW.
    return 'ALLOW', f"Low AI risk ({s:.0f}/100). Request matches baseline behaviour."

dec = df.apply(decide, axis=1)
df['final_decision'] = [d[0] for d in dec]
df['decision_reason'] = [d[1] for d in dec]
ev['final_decision'] = df['final_decision'].iloc[split:].values

# ---------------------------------------------------------------------------
# [TASK 6] Αξιολόγηση στο held-out window
# ---------------------------------------------------------------------------
y = ev['is_anomaly'].values
proba = ev['risk_ai'].values / 100.0
pred_hard = (clf.predict(ev[FEATURES])).astype(int)   # κατώφλι 0.5 του μοντέλου
pred_dec = ev['final_decision'].isin(['BLOCK', 'CHALLENGE']).astype(int).values

print("\n=== AI MODEL (held-out eval, model classifier) ===")
print(classification_report(y, pred_hard, digits=3, target_names=['Normal', 'Anomaly']))
print(f"ROC-AUC = {roc_auc_score(y, proba):.3f}")
print(f"PR-AUC  = {average_precision_score(y, proba):.3f}")

# Μετρικές της πλήρους μηχανής αποφάσεων (BLOCK/CHALLENGE = detected).
p, r, f1, _ = precision_recall_fscore_support(y, pred_dec, average='binary', zero_division=0)
print("\n=== FULL DECISION ENGINE (BLOCK/CHALLENGE = detected) ===")
print(f"Precision={p:.3f} Recall={r:.3f} F1={f1:.3f}")

# [TASK 6] Σύγκριση με τον baseline στο ΙΔΙΟ eval window (δίκαιη σύγκριση).
base = pd.read_csv('data/baseline_decisions.csv')
base = base.set_index('event_id').loc[ev['event_id']].reset_index()
base_pred = base['baseline_decision'].isin(['BLOCK', 'CHALLENGE']).astype(int).values
bp, br, bf1, _ = precision_recall_fscore_support(y, base_pred, average='binary', zero_division=0)
# Ως "πιθανότητα" του baseline (για ROC/PR) χρησιμοποιείται το κανονικοποιημένο σκορ.
base_proba = base['baseline_risk_score'].values / 100.0
print("\n=== STATIC BASELINE (same eval window) ===")
print(f"Precision={bp:.3f} Recall={br:.3f} F1={bf1:.3f}")
print(f"ROC-AUC={roc_auc_score(y, base_proba):.3f}  PR-AUC={average_precision_score(y, base_proba):.3f}")

# ---------------------------------------------------------------------------
# Αποθήκευση παραδοτέων αρχείων
# ---------------------------------------------------------------------------
# [TASK 4] evaluated_risk_logs.csv: πλήρες log + όλα τα features + AI score + απόφαση.
df_out = df.copy()
df_out['calculated_risk_score_ai'] = df_out['risk_ai']
cols_scores = (['event_id', 'timestamp', 'user_id', 'role', 'department',
                'network_zone', 'device_id', 'resource_id', 'sensitivity',
                'action', 'outcome'] + FEATURES +
               ['calculated_risk_score_ai', 'final_decision', 'decision_reason',
                'is_anomaly', 'anomaly_type'])
df_out[cols_scores].to_csv('data/evaluated_risk_logs.csv', index=False)
# [TASK 5] dynamic_access_decisions.csv: το marker-facing Audit Log (4 στήλες).
df_out[['event_id', 'calculated_risk_score_ai', 'final_decision',
        'decision_reason']].to_csv('data/dynamic_access_decisions.csv', index=False)

# Ενδιάμεσα artifacts (eval frame + μοντέλα) για το επόμενο script (Task 6/7/προαιρ.).
ev.to_pickle('data/_eval.pkl')
df.to_pickle('data/_full.pkl')
import joblib
joblib.dump({'clf': clf, 'iso': iso, 'features': FEATURES, 'behav': BEHAV,
             'split': split}, 'data/_models.pkl')
print("\nSaved: evaluated_risk_logs.csv, dynamic_access_decisions.csv, _eval.pkl, _models.pkl")
