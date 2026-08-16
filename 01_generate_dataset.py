# -*- coding: utf-8 -*-
"""
=============================================================================
 TASK 1 & TASK 2: Synthetic enterprise dataset synthesis + anomaly injection
=============================================================================

TASK 1 (Design of the synthetic enterprise scenario):
  Produces a realistic corporate environment with 60 users, 4 departments, 4
  roles (RBAC), 30 resources of 4 sensitivity levels, over 14 days and ~15,000
  events. Each user has a personal behavioural baseline (typical work hours,
  preferred network zone, habitual resources), so that the next stage can
  measure deviation per user, not only per department.

TASK 2 (Injection of diverse anomalies):
  6% of the events are modified to represent 6 anomaly types (instead of the
  minimum of 5). The last 3 types (Unusual_Resource_Access, Bulk_Data_Spike,
  Privilege_Escalation) are deliberately context-dependent: no single field is
  suspicious, so they cannot be caught by static rules. The labels (is_anomaly,
  anomaly_type) form the ground truth.

Implemented purely with the standard library (csv/random/datetime), so it runs
even in environments with strict Application Control / WDAC policies, where
compiled wheels are blocked.

Output: data/synthetic_enterprise_logs.csv
=============================================================================
"""

import csv
import os
import random
from datetime import datetime, timedelta

# Create the data/ folder if it does not exist (to avoid FileNotFoundError).
os.makedirs('data', exist_ok=True)

# Fixed random seed (based on the student ID) -> full reproducibility and
# differentiation from other implementations.
SEED = 25012
random.seed(SEED)

# Scenario size parameters (exceed the assignment minimums).
N_USERS = 60
N_RESOURCES = 30
N_DAYS = 14
TOTAL_EVENTS = 15000
ANOMALY_RATE = 0.06               # 6% (within the recommended 3-10% range)
START_DATE = datetime(2026, 5, 1, 0, 0, 0)

DEPARTMENTS = ['Engineering', 'Finance', 'HR', 'Sales']
ROLES = ['Intern', 'Employee', 'Manager', 'Admin']
ROLE_WEIGHTS = [0.20, 0.50, 0.20, 0.10]     # role distribution
ZONES = ['Internal_Corporate', 'VPN_Remote', 'Public_Internet']
ACTIONS = ['Read', 'Write', 'Execute', 'Delete']

# ---------------------------------------------------------------------------
# [TASK 1] Identities (RBAC) with a personal behavioural baseline per user
# ---------------------------------------------------------------------------
users = []
for i in range(1, N_USERS + 1):
    dept = random.choice(DEPARTMENTS)
    role = random.choices(ROLES, weights=ROLE_WEIGHTS, k=1)[0]
    # Sales relies more on remote work; the others are mostly on-prem.
    home_zone_weights = {
        'Engineering': [0.75, 0.20, 0.05],
        'Finance':     [0.85, 0.13, 0.02],
        'HR':          [0.80, 0.17, 0.03],
        'Sales':       [0.55, 0.40, 0.05],
    }[dept]
    start_hour = random.randint(7, 10)          # personal work-start hour
    users.append({
        'user_id': f"USR_{i:03d}",
        'dept': dept,
        'role': role,
        'device': f"DEV_{100 + i}",             # one trusted device per user
        'zone_w': home_zone_weights,
        'start_hour': start_hour,
    })

# ---------------------------------------------------------------------------
# [TASK 1] Resources with a sensitivity level + owning department
# ---------------------------------------------------------------------------
# Confidential/Privileged resources belong to specific departments, so that
# lateral movement between departments can be detected.
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
# Top up to 30 resources with generic internal ones.
for i in range(len(resources), N_RESOURCES):
    resources.append({'res_id': f"RES_GEN_{i:02d}", 'dept': 'All', 'sensitivity': 'Internal'})

res_by_dept = {}
for r in resources:
    res_by_dept.setdefault(r['dept'], []).append(r)
# Allowed resources per department = the department's resources + the shared (All) ones.
allowed_for = lambda dept: res_by_dept.get(dept, []) + res_by_dept['All']

# Give each user a small set of habitual resources (their normal working set).
for u in users:
    pool = allowed_for(u['dept'])
    k = min(len(pool), random.randint(4, 7))
    u['habitual'] = random.sample(pool, k)

# ---------------------------------------------------------------------------
# [TASK 1] Generate the legitimate (normal) traffic
# ---------------------------------------------------------------------------
def business_hour(u):
    """Return an hour drawn from the user's normal working pattern."""
    if random.random() < 0.85:
        return max(6, min(19, int(random.gauss(u['start_hour'] + 4, 2))))
    # Small share of legitimate evening work.
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
    # Habitual resource most of the time, occasionally another allowed one.
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
# [TASK 2] Anomaly injection: 6 categories, evenly distributed
# ---------------------------------------------------------------------------
cats = ['Impossible_Travel', 'Off_Hours_Privileged', 'New_Device_Sensitive',
        'Unusual_Resource_Access', 'Bulk_Data_Spike', 'Privilege_Escalation']
per_cat = n_anomalies // len(cats)      # ~150 records per type

priv_res = [r for r in resources if r['sensitivity'] == 'Privileged']
conf_res = [r for r in resources if r['sensitivity'] in ('Confidential', 'Privileged')]

def rand_ts(day=None, hour=None):
    """Random timestamp (optionally with a fixed day or hour)."""
    day = random.randint(0, N_DAYS - 1) if day is None else day
    hour = random.randint(8, 17) if hour is None else hour
    return START_DATE + timedelta(days=day, hours=hour,
                                  minutes=random.randint(0, 59),
                                  seconds=random.randint(0, 59))

# [TASK 2] Anomaly 1 - Impossible travel: successful access from Public_Internet
#          (simulates a perimeter breach). Simple type.
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

# [TASK 2] Anomaly 2 - Off-hours privileged: access to privileged resources 01:00-04:00.
#          Simple type (caught by time-of-day + sensitivity).
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

# [TASK 2] Anomaly 3 - New-device sensitive: unknown device + Delete on a sensitive resource.
#          Simple type (caught by device trust + action severity).
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

# [TASK 2] Anomaly 4 - Unusual resource access: access to a Confidential/Privileged
#          resource of ANOTHER department, in-hours, from a trusted device.
#          CONTEXT-DEPENDENT: no field is suspicious on its own; only the
#          user-resource-department combination reveals the lateral movement.
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

# [TASK 2] Anomaly 5 - Bulk data spike: a burst of rapid Reads by the same user.
#          CONTEXT-DEPENDENT: each single Read is legitimate; only the FREQUENCY
#          (many requests within seconds) reveals the data exfiltration.
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

# [TASK 2] Anomaly 6 - Privilege escalation: a burst of failed logins -> one success.
#          CONTEXT-DEPENDENT: only the HISTORY of recent failures reveals the
#          brute-force / credential-stuffing attack.
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
# 5. Chronological ordering + event ids + save
# ---------------------------------------------------------------------------
# Chronological order is required for the temporal split and the rolling
# features of the next stage (avoiding temporal leakage).
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

# Summary for confirmation (count and distribution of anomalies).
n_anom = sum(r['is_anomaly'] for r in logs)
print(f"Generated {len(logs)} events | normal={len(logs)-n_anom} | anomalies={n_anom} "
      f"({100*n_anom/len(logs):.1f}%)")
from collections import Counter
print("Anomaly breakdown:", dict(Counter(r['anomaly_type'] for r in logs if r['is_anomaly'])))
