# Ioannis Kalaitzidis, MTE25012

"""
=============================================================================
 TASK 1 & TASK 2: Σύνθεση συνθετικού εταιρικού dataset + έγχυση ανωμαλιών

TASK 1 (Σχεδιασμός συνθετικού εταιρικού σεναρίου):
  Παράγει ένα ρεαλιστικό εταιρικό περιβάλλον με 60 χρήστες, 4 τμήματα, 4 ρόλους
  (RBAC), 30 πόρους 4 επιπέδων ευαισθησίας, για διάστημα 14 ημερών και ~15.000
  συμβάντα. Κάθε χρήστης έχει ένα προσωπικό behavioural baseline (τυπική ώρα
  εργασίας, προτιμώμενη ζώνη δικτύου, συνηθισμένοι πόροι), ώστε το επόμενο στάδιο
  να μπορεί να μετρήσει την απόκλιση ανά χρήστη και όχι μόνο ανά τμήμα.

TASK 2 (Έγχυση διαφοροποιημένων ανωμαλιών):
  Το 6% των συμβάντων τροποποιείται ώστε να αναπαριστά 6 τύπους ανωμαλιών (αντί
  για 5 που είναι το ελάχιστο). Οι 3 τελευταίοι τύποι (Unusual_Resource_Access,
  Bulk_Data_Spike, Privilege_Escalation) είναι σκόπιμα context-dependent: καμία
  μεμονωμένη τιμή πεδίου δεν είναι ύποπτη, οπότε δεν πιάνονται από στατικούς
  κανόνες. Οι ετικέτες (is_anomaly, anomaly_type) αποτελούν το ground truth.

Έξοδος: data/synthetic_enterprise_logs.csv
=============================================================================
"""

import csv
import random
from datetime import datetime, timedelta

# Σταθερός σπόρος τυχαιότητας -> πλήρης
# αναπαραγωγιμότητα και διαφοροποίηση από άλλες υλοποιήσεις.
SEED = 25012
random.seed(SEED)

# Παράμετροι μεγέθους του σεναρίου (υπερβαίνουν τα ελάχιστα της εκφώνησης).
N_USERS = 60
N_RESOURCES = 30
N_DAYS = 14
TOTAL_EVENTS = 15000
ANOMALY_RATE = 0.06               # 6% (εντός του συνιστώμενου εύρους 3-10%)
START_DATE = datetime(2026, 5, 1, 0, 0, 0)

DEPARTMENTS = ['Engineering', 'Finance', 'HR', 'Sales']
ROLES = ['Intern', 'Employee', 'Manager', 'Admin']
ROLE_WEIGHTS = [0.20, 0.50, 0.20, 0.10]     # κατανομή ρόλων
ZONES = ['Internal_Corporate', 'VPN_Remote', 'Public_Internet']
ACTIONS = ['Read', 'Write', 'Execute', 'Delete']

# ---------------------------------------------------------------------------
# [TASK 1] Ταυτότητες (RBAC) με προσωπικό behavioural baseline ανά χρήστη
# ---------------------------------------------------------------------------
users = []
for i in range(1, N_USERS + 1):
    dept = random.choice(DEPARTMENTS)
    role = random.choices(ROLES, weights=ROLE_WEIGHTS, k=1)[0]
    # Το Sales στηρίζεται περισσότερο σε τηλεργασία, οι υπόλοιποι κυρίως on-prem.
    home_zone_weights = {
        'Engineering': [0.75, 0.20, 0.05],
        'Finance':     [0.85, 0.13, 0.02],
        'HR':          [0.80, 0.17, 0.03],
        'Sales':       [0.55, 0.40, 0.05],
    }[dept]
    start_hour = random.randint(7, 10)          # προσωπική ώρα έναρξης εργασίας
    users.append({
        'user_id': f"USR_{i:03d}",
        'dept': dept,
        'role': role,
        'device': f"DEV_{100 + i}",             # μία έμπιστη συσκευή ανά χρήστη
        'zone_w': home_zone_weights,
        'start_hour': start_hour,
    })

# ---------------------------------------------------------------------------
# [TASK 1] Πόροι με επίπεδο ευαισθησίας + τμήμα ιδιοκτησίας
# ---------------------------------------------------------------------------
# Οι Confidential/Privileged πόροι ανήκουν σε συγκεκριμένα τμήματα, ώστε να είναι
# δυνατή η ανίχνευση οριζόντιας μετακίνησης (lateral movement) μεταξύ τμημάτων.
resources = [
    {'res_id': 'RES_PUB_01', 'dept': 'All', 'sensitivity': 'Public'},
    {'res_id': 'RES_PUB_02', 'dept': 'All', 'sensitivity': 'Public'},
    {'res_id': 'RES_PUB_03', 'dept': 'All', 'sensitivity': 'Public'},
    {'res_id': 'RES_INT_01', 'dept': 'All', 'sensitivity': 'Internal'},
    {'res_id': 'RES_INT_02', 'dept': 'All', 'sensitivity': 'Internal'},
    {'res_id': 'RES_INT_03', 'dept': 'All', 'sensitivity': 'Internal'},
    {'res_id': 'RES_INT_04', 'dept': 'All', 'sensitivity': 'Internal'},
    {'res_id': 'RES_ENG_CODE',   'dept': 'Engineering', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_ENG_CICD',   'dept': 'Engineering', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_ENG_PROD_DB','dept': 'Engineering', 'sensitivity': 'Privileged'},
    {'res_id': 'RES_FIN_LEDGER', 'dept': 'Finance', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_FIN_TAX',    'dept': 'Finance', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_FIN_BANK',   'dept': 'Finance', 'sensitivity': 'Privileged'},
    {'res_id': 'RES_HR_PAYROLL', 'dept': 'HR', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_HR_RECORDS', 'dept': 'HR', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_HR_MEDICAL', 'dept': 'HR', 'sensitivity': 'Privileged'},
    {'res_id': 'RES_SAL_CRM',    'dept': 'Sales', 'sensitivity': 'Internal'},
    {'res_id': 'RES_SAL_PIPE',   'dept': 'Sales', 'sensitivity': 'Confidential'},
    {'res_id': 'RES_SAL_CONTRACTS','dept': 'Sales', 'sensitivity': 'Privileged'},
]
# Συμπλήρωση μέχρι τους 30 πόρους με generic internal πόρους.
for i in range(len(resources), N_RESOURCES):
    resources.append({'res_id': f"RES_GEN_{i:02d}", 'dept': 'All', 'sensitivity': 'Internal'})

res_by_dept = {}
for r in resources:
    res_by_dept.setdefault(r['dept'], []).append(r)
# Επιτρεπτοί πόροι ανά τμήμα = οι πόροι του τμήματος + οι κοινοί (All).
allowed_for = lambda dept: res_by_dept.get(dept, []) + res_by_dept['All']

# Σε κάθε χρήστη δίνεται ένα μικρό σύνολο συνηθισμένων πόρων (habitual set),
# δηλαδή το κανονικό του σύνολο εργασίας.
for u in users:
    pool = allowed_for(u['dept'])
    k = min(len(pool), random.randint(4, 7))
    u['habitual'] = random.sample(pool, k)

# ---------------------------------------------------------------------------
# [TASK 1] Παραγωγή νόμιμης (φυσιολογικής) κίνησης
# ---------------------------------------------------------------------------
def business_hour(u):
    """Επιστρέφει ώρα από το κανονικό μοτίβο εργασίας του χρήστη."""
    if random.random() < 0.85:
        return max(6, min(19, int(random.gauss(u['start_hour'] + 4, 2))))
    # Μικρό ποσοστό νόμιμης βραδινής εργασίας.
    return random.choice([6, 7, 18, 19, 20])

logs = []
n_anomalies = int(TOTAL_EVENTS * ANOMALY_RATE)
n_normal = TOTAL_EVENTS - n_anomalies

for _ in range(n_normal):
    u = random.choice(users)
    day = random.randint(0, N_DAYS - 1)
    hour = business_hour(u)
    ts = START_DATE + timedelta(days=day, hours=hour,
                                minutes=random.randint(0, 59),
                                seconds=random.randint(0, 59))
    # Συνηθισμένος πόρος τις περισσότερες φορές, περιστασιακά άλλος επιτρεπτός.
    if random.random() < 0.8:
        res = random.choice(u['habitual'])
    else:
        res = random.choice(allowed_for(u['dept']))
    zone = random.choices(ZONES, weights=u['zone_w'], k=1)[0]
    action = random.choices(ACTIONS, weights=[0.7, 0.18, 0.08, 0.04], k=1)[0]
    outcome = 'Success' if random.random() < 0.97 else 'Failure'
    logs.append({
        'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
        'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
        'network_zone': zone, 'device_id': u['device'],
        'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
        'action': action, 'outcome': outcome,
        'is_anomaly': 0, 'anomaly_type': '',
    })

# ---------------------------------------------------------------------------
# [TASK 2] Έγχυση ανωμαλιών: 6 κατηγορίες, ισοκατανεμημένες
# ---------------------------------------------------------------------------
cats = ['Impossible_Travel', 'Off_Hours_Privileged', 'New_Device_Sensitive',
        'Unusual_Resource_Access', 'Bulk_Data_Spike', 'Privilege_Escalation']
per_cat = n_anomalies // len(cats)      # ~150 εγγραφές ανά τύπο

priv_res = [r for r in resources if r['sensitivity'] == 'Privileged']
conf_res = [r for r in resources if r['sensitivity'] in ('Confidential', 'Privileged')]

def rand_ts(day=None, hour=None):
    """Τυχαία χρονοσφραγίδα (προαιρετικά με σταθερή ημέρα ή ώρα)."""
    day = random.randint(0, N_DAYS - 1) if day is None else day
    hour = random.randint(8, 17) if hour is None else hour
    return START_DATE + timedelta(days=day, hours=hour,
                                  minutes=random.randint(0, 59),
                                  seconds=random.randint(0, 59))

# [TASK 2] 4.1 Impossible travel: επιτυχής πρόσβαση από Public_Internet
#          (προσομοιώνει παραβίαση περιμέτρου / perimeter breach). Απλός τύπος.
for _ in range(per_cat):
    u = random.choice(users)
    res = random.choice(allowed_for(u['dept']))
    logs.append({
        'timestamp': rand_ts().strftime('%Y-%m-%d %H:%M:%S'),
        'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
        'network_zone': 'Public_Internet', 'device_id': u['device'],
        'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
        'action': 'Read', 'outcome': 'Success',
        'is_anomaly': 1, 'anomaly_type': 'Impossible_Travel',
    })

# [TASK 2] Off-hours privileged: πρόσβαση σε privileged πόρους 01:00-04:00.
#          Απλός τύπος (πιάνεται από time-of-day + sensitivity).
for _ in range(per_cat):
    u = random.choice(users)
    res = random.choice(priv_res)
    logs.append({
        'timestamp': rand_ts(hour=random.randint(1, 4)).strftime('%Y-%m-%d %H:%M:%S'),
        'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
        'network_zone': 'VPN_Remote', 'device_id': u['device'],
        'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
        'action': random.choice(['Read', 'Write']), 'outcome': 'Success',
        'is_anomaly': 1, 'anomaly_type': 'Off_Hours_Privileged',
    })

# [TASK 2] New-device sensitive: άγνωστη συσκευή + Delete σε ευαίσθητο πόρο.
#          Απλός τύπος (πιάνεται από device trust + action severity).
for _ in range(per_cat):
    u = random.choice(users)
    res = random.choice(conf_res)
    logs.append({
        'timestamp': rand_ts().strftime('%Y-%m-%d %H:%M:%S'),
        'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
        'network_zone': random.choice(['Internal_Corporate', 'VPN_Remote']),
        'device_id': f"DEV_UNKNOWN_{random.randint(1000, 9999)}",
        'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
        'action': 'Delete', 'outcome': 'Success',
        'is_anomaly': 1, 'anomaly_type': 'New_Device_Sensitive',
    })

# [TASK 2] Unusual resource access: πρόσβαση σε Confidential/Privileged πόρο
#          ΑΛΛΟΥ τμήματος, εντός ωραρίου, από έμπιστη συσκευή.
#          CONTEXT-DEPENDENT: κανένα πεδίο δεν είναι ύποπτο μόνο του, μόνο ο
#          συνδυασμός χρήστη-πόρου-τμήματος αποκαλύπτει το lateral movement.
for _ in range(per_cat):
    u = random.choice(users)
    foreign = [r for r in resources
               if r['dept'] not in ('All', u['dept'])
               and r['sensitivity'] in ('Confidential', 'Privileged')]
    res = random.choice(foreign)
    logs.append({
        'timestamp': rand_ts().strftime('%Y-%m-%d %H:%M:%S'),
        'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
        'network_zone': 'Internal_Corporate', 'device_id': u['device'],
        'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
        'action': 'Read', 'outcome': 'Success',
        'is_anomaly': 1, 'anomaly_type': 'Unusual_Resource_Access',
    })

# [TASK 2] Bulk data spike: ριπή ταχύτατων Read από τον ίδιο χρήστη.
#          CONTEXT-DEPENDENT: κάθε μεμονωμένο Read είναι νόμιμο, μόνο η ΣΥΧΝΟΤΗΤΑ
#          (πολλά αιτήματα σε λίγα δευτερόλεπτα) αποκαλύπτει το data exfiltration.
bursts = max(1, per_cat // 25)
made = 0
for _ in range(bursts):
    u = random.choice(users)
    res = random.choice(u['habitual'])
    base = rand_ts()
    burst_len = min(25, per_cat - made)
    for j in range(burst_len):
        ts = base + timedelta(seconds=j * random.randint(3, 8))
        logs.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
            'network_zone': 'Internal_Corporate', 'device_id': u['device'],
            'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
            'action': 'Read', 'outcome': 'Success',
            'is_anomaly': 1, 'anomaly_type': 'Bulk_Data_Spike',
        })
        made += 1
    if made >= per_cat:
        break

# [TASK 2] Privilege escalation: ριπή αποτυχημένων συνδέσεων -> μία επιτυχία.
#          CONTEXT-DEPENDENT: μόνο το ΙΣΤΟΡΙΚΟ των πρόσφατων αποτυχιών αποκαλύπτει
#          την επίθεση brute-force / credential stuffing.
esc = max(1, per_cat // 6)
made = 0
for _ in range(esc):
    u = random.choice(users)
    res = random.choice(conf_res)
    base = rand_ts()
    fails = min(5, per_cat - made)
    for j in range(fails):
        ts = base + timedelta(seconds=j * random.randint(2, 5))
        logs.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
            'network_zone': 'Public_Internet', 'device_id': u['device'],
            'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
            'action': 'Execute', 'outcome': 'Failure',
            'is_anomaly': 1, 'anomaly_type': 'Privilege_Escalation',
        })
        made += 1
    if made < per_cat:
        ts = base + timedelta(seconds=fails * 4)
        logs.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': u['user_id'], 'role': u['role'], 'department': u['dept'],
            'network_zone': 'Public_Internet', 'device_id': u['device'],
            'resource_id': res['res_id'], 'sensitivity': res['sensitivity'],
            'action': 'Execute', 'outcome': 'Success',
            'is_anomaly': 1, 'anomaly_type': 'Privilege_Escalation',
        })
        made += 1
    if made >= per_cat:
        break

# ---------------------------------------------------------------------------
# 5. Χρονολογική ταξινόμηση + event ids + αποθήκευση
# ---------------------------------------------------------------------------
# Η χρονολογική σειρά είναι απαραίτητη για το temporal split και τα rolling
# features του επόμενου σταδίου (αποφυγή temporal leakage).
logs.sort(key=lambda r: r['timestamp'])
for i, row in enumerate(logs):
    row['event_id'] = f"EVT_{i:05d}"

fields = ['event_id', 'timestamp', 'user_id', 'role', 'department',
          'network_zone', 'device_id', 'resource_id', 'sensitivity',
          'action', 'outcome', 'is_anomaly', 'anomaly_type']

with open('data/synthetic_enterprise_logs.csv', 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(logs)

# Σύνοψη για επιβεβαίωση (πλήθος και κατανομή ανωμαλιών).
n_anom = sum(r['is_anomaly'] for r in logs)
print(f"Generated {len(logs)} events | normal={len(logs)-n_anom} | anomalies={n_anom} "
      f"({100*n_anom/len(logs):.1f}%)")
from collections import Counter
print("Anomaly breakdown:", dict(Counter(r['anomaly_type'] for r in logs if r['is_anomaly'])))
