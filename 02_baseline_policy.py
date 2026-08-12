# Ioannis Kalaitzidis, MTE25012

"""
=============================================================================
 TASK 3: Στατική μηχανή κανόνων (rule-based baseline, μη-AI)

Ντετερμινιστικό, πλήρως ελέγξιμο μοντέλο στάθμισης κινδύνου. Κάθε
συμβάν συγκεντρώνει ποινές από ανεξάρτητα contextual σήματα. Το άθροισμα
(περιορισμένο στο 0-100) αντιστοιχίζεται σε ALLOW / CHALLENGE / BLOCK. Καθαρή
Python, ένα streaming πέρασμα, ώστε να τρέχει και υπό Application Control.

Ο baseline είναι σκόπιμα "field-local": εξετάζει κάθε συμβάν μεμονωμένα και ΔΕΝ
μπορεί να λάβει υπόψη το πρόσφατο ιστορικό ενός χρήστη ή τη συμπεριφορά της
ομάδας του. Ακριβώς αυτό το τυφλό σημείο καλείται να καλύψει το μοντέλο AI στο
επόμενο στάδιο. Το αποτέλεσμα του baseline χρησιμεύει ως σημείο σύγκρισης για
την αξιολόγηση του Task 6.

Είσοδος:  data/synthetic_enterprise_logs.csv
Έξοδος:   data/baseline_decisions.csv
=============================================================================
"""

import csv
from collections import defaultdict

IN_FILE = 'data/synthetic_enterprise_logs.csv'
OUT_FILE = 'data/baseline_decisions.csv'

# Βασική τιμή κινδύνου και κατώφλια απόφασης.
BASE_RISK = 10.0
T_CHALLENGE = 45.0        # >= 45 -> CHALLENGE (απαίτηση MFA)
T_BLOCK = 75.0            # >= 75 -> BLOCK (άμεση απόρριψη)


def baseline_risk(row):
    """[TASK 3] Υπολογισμός σκορ κινδύνου με ντετερμινιστικά βάρη ανά σήμα."""
    score = BASE_RISK
    # Κανόνας 1 - ζώνη δικτύου (πρόσβαση εκτός εταιρικής περιμέτρου).
    if row['network_zone'] == 'Public_Internet':
        score += 35.0
    elif row['network_zone'] == 'VPN_Remote':
        score += 15.0
    # Κανόνας 2 - ώρα (εξαγωγή ώρας από τη χρονοσφραγίδα, off-hours 22:00-05:00).
    hour = int(row['timestamp'].split()[1].split(':')[0])
    if hour >= 22 or hour <= 5:
        score += 20.0
    # Κανόνας 3 - ευαισθησία πόρου.
    if row['sensitivity'] == 'Privileged':
        score += 25.0
    elif row['sensitivity'] == 'Confidential':
        score += 15.0
    # Κανόνας 4 - σοβαρότητα ενέργειας (μη αναστρέψιμες/τροποποιητικές).
    if row['action'] == 'Delete':
        score += 15.0
    elif row['action'] == 'Write':
        score += 5.0
    # Κανόνας 5 - εμπιστοσύνη συσκευής (μη εγγεγραμμένη συσκευή).
    if row['device_id'].startswith('DEV_UNKNOWN'):
        score += 30.0
    # Κανόνας 6 - αποτυχημένο authentication.
    if row['outcome'] == 'Failure':
        score += 10.0
    return min(score, 100.0)     # οριοθέτηση στο 100


def decide(score):
    """[TASK 3] Αντιστοίχιση σκορ σε απόφαση πολιτικής."""
    if score >= T_BLOCK:
        return 'BLOCK'
    if score >= T_CHALLENGE:
        return 'CHALLENGE'
    return 'ALLOW'


rows_out = []
# Μετρητές confusion matrix (detection = BLOCK ή CHALLENGE σε πραγματική ανωμαλία).
tp = fp = tn = fn = 0
by_type = defaultdict(lambda: {'ALLOW': 0, 'CHALLENGE': 0, 'BLOCK': 0})

# Streaming επεξεργασία γραμμή-γραμμή (σταθερή μνήμη, συμβατότητα με WDAC).
with open(IN_FILE, newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        score = baseline_risk(row)
        action = decide(score)
        is_anom = row['is_anomaly'] == '1'
        detected = action in ('BLOCK', 'CHALLENGE')
        # Καταμέτρηση ανά κατηγορία ανωμαλίας και ανά κελί του confusion matrix.
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

# Αποθήκευση των αποφάσεων του baseline (χρησιμοποιείται στο Task 6 για σύγκριση).
with open(OUT_FILE, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['event_id', 'baseline_risk_score',
                                      'baseline_decision', 'is_anomaly', 'anomaly_type'])
    w.writeheader()
    w.writerows(rows_out)

# Μετρικές συνολικά (σε ολόκληρο το dataset).
precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
fpr = fp / (fp + tn) if (fp + tn) else 0

print("=== STATIC BASELINE (full dataset) ===")
print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
print(f"Precision={precision:.3f}  Recall={recall:.3f}  F1={f1:.3f}  FPR={fpr:.3f}")
# Ανάλυση ανά τύπο: αναδεικνύει την πλήρη διαφυγή (0%) των context-dependent
# ανωμαλιών (Bulk_Data_Spike, Unusual_Resource_Access) -> κίνητρο για το AI.
print("\nPer-anomaly-type detection:")
for t, d in sorted(by_type.items()):
    tot = sum(d.values())
    det = d['BLOCK'] + d['CHALLENGE']
    print(f"  {t:26s} ALLOW={d['ALLOW']:3d} CHALLENGE={d['CHALLENGE']:3d} "
          f"BLOCK={d['BLOCK']:3d}  detection={100*det/tot:.1f}%")
