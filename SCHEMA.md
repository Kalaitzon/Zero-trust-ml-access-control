# Data Schema

All data is synthetic and fully reproducible (`SEED = 25012`). Re-running the
pipeline with the same random seed reproduces every CSV file and every number in
the report. Field names, values and file names are kept in English so that they
match the code exactly.

---

## 1. `synthetic_enterprise_logs.csv` (Task 1 output, 15,000 rows)

The base access-event log.

| Field | Type | Values / Range | Description |
|---|---|---|---|
| event_id | string | EVT_00000 to EVT_14999 | Unique event identifier (chronological order). |
| timestamp | datetime | 2026-05-01 to 2026-05-14 | Second-precision timestamp. |
| user_id | string | USR_001 to USR_060 | Employee identifier. |
| role | categorical | Intern, Employee, Manager, Admin | RBAC role. |
| department | categorical | Engineering, Finance, HR, Sales | Organisational unit. |
| network_zone | categorical | Internal_Corporate, VPN_Remote, Public_Internet | Origin zone of the request. |
| device_id | string | DEV_101 to DEV_160, DEV_UNKNOWN_xxxx | Device identifier (one trusted per user, unknown in some anomalies). |
| resource_id | string | RES_PUB_*, RES_INT_*, RES_ENG_*, RES_FIN_*, RES_HR_*, RES_SAL_*, RES_GEN_* | Target resource. |
| sensitivity | categorical | Public, Internal, Confidential, Privileged | Resource sensitivity level. |
| action | categorical | Read, Write, Execute, Delete | Requested action. |
| outcome | categorical | Success, Failure | Whether the request succeeded or failed. |
| is_anomaly | binary | 0, 1 | Ground-truth label (actual state). |
| anomaly_type | string | (see below) or empty | Category of the injected anomaly. |

### Organisation design
- 60 users, role distribution Intern 20% / Employee 50% / Manager 20% / Admin 10%.
- 30 resources: 3 Public, 4 shared Internal, Confidential/Privileged per department, and generic Internal.
- 14 days, ~15,000 events, second-precision timestamps.
- Each user has a **personal behavioural baseline**: a work-start hour, a network-zone
  distribution (Sales leans toward remote work) and a small set of habitual resources.

### Anomaly categories (6 types, 150 events each, 6% total)
1. **Impossible_Travel** - successful access from `Public_Internet` (perimeter breach).
2. **Off_Hours_Privileged** - access to a privileged resource at 01:00-04:00.
3. **New_Device_Sensitive** - `DEV_UNKNOWN_*` performing a `Delete` on Confidential/Privileged data.
4. **Unusual_Resource_Access** - in-hours, from a trusted device, access to a sensitive resource of
   *another* department (only the context reveals it, no single field does).
5. **Bulk_Data_Spike** - a burst of rapid `Read` actions by one user (only the frequency shows it).
6. **Privilege_Escalation** - several failed logins followed by one success (only the history of
   recent failures shows it).

Categories 4 to 6 are deliberately **context-dependent**: they cannot be caught by inspecting a
single field, and this is exactly what justifies the AI stage.

---

## 2. `baseline_decisions.csv` (Task 3 output)

| Field | Type | Description |
|---|---|---|
| event_id | string | Reference to the event. |
| baseline_risk_score | float 0-100 | Deterministic score from the weighted rules. |
| baseline_decision | categorical | ALLOW / CHALLENGE / BLOCK. |
| is_anomaly / anomaly_type | - | Carried through for the evaluation. |

Rule weights: base 10, +35 Public_Internet, +15 VPN_Remote, +20 off-hours (22:00-05:00),
+25 Privileged, +15 Confidential, +15 Delete, +5 Write, +30 unknown device, +10 failure.
Thresholds: ALLOW <45, CHALLENGE 45-74, BLOCK >=75.

---

## 3. `evaluated_risk_logs.csv` (Task 4 output)

The full log together with all engineered features, the AI risk score and the final decision.

### Engineered features (all computed causally, from the past only)

| Feature | Type | Definition |
|---|---|---|
| access_frequency | int | Number of the user's requests in the previous 5 minutes (Bulk_Data_Spike). |
| recent_failure_count | int | The user's failed events in the previous 10 minutes (Privilege_Escalation). |
| session_resource_variety | int | Distinct resources the user touched in the previous 15 minutes. |
| is_off_hours | binary | Hour in the range [22..23, 0..5]. |
| device_novelty | binary | First appearance of the user on this device, or an unknown device. |
| sensitivity_mismatch | binary | Intern/Employee touching Confidential/Privileged data. |
| peer_rarity_score | float | 1 - (department's accesses to this resource / department total), running. |
| user_hour_deviation | float | Absolute difference of the hour from the user's running mean hour. |
| zone_risk | int | 0 Internal, 1 VPN, 2 Public_Internet. |
| cross_department | binary | Resource belonging to a different department than the user (lateral movement). |
| iso_score | float | Isolation Forest anomaly score (the hybrid unsupervised signal). |

Additional columns: `calculated_risk_score_ai` (0-100), `final_decision`, `decision_reason`.

---

## 4. `dynamic_access_decisions.csv` (Task 5 output)

The final audit log (the Policy Decision Point output) - the marker-facing file.

| Field | Description |
|---|---|
| event_id | Identifier of the access attempt. |
| calculated_risk_score_ai | AI risk score 0-100. |
| final_decision | ALLOW / CHALLENGE / BLOCK. |
| decision_reason | Human-readable justification (reason code). |

---

## 5. Evaluation / fairness / drift files

- `fairness_by_department.csv`, `fairness_by_role.csv`, `fairness_by_sensitivity.csv`
  (Task 6 group breakdown and the optional fairness analysis).
- `drift_summary.csv` (Task 7: before / after / after-mitigation).
