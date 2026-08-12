# Σχήμα Δεδομένων (Data Schema)

Ολα τα δεδομένα είναι συνθετικά και πλήρως αναπαραγώγιμα (`SEED = 25012`). Η εκ νέου
εκτέλεση του pipeline με τον ίδιο σπόρο τυχαιότητας (seed) αναπαράγει κάθε αρχείο CSV
και κάθε αριθμό της αναφοράς. Τα ονόματα των πεδίων, των τιμών και των αρχείων
διατηρούνται στα αγγλικά, ωστε να ταυτίζονται ακριβώς με τον κώδικα.

---

## 1. `synthetic_enterprise_logs.csv` (έξοδος του Task 1, 15.000 γραμμές)

Το βασικό log συμβάντων πρόσβασης.

| Πεδίο | Τύπος | Τιμές / Εύρος | Περιγραφή |
|---|---|---|---|
| event_id | string | EVT_00000 έως EVT_14999 | Μοναδικό αναγνωριστικό συμβάντος (χρονολογική σειρά). |
| timestamp | datetime | 2026-05-01 έως 2026-05-14 | Χρονοσφραγίδα ακρίβειας δευτερολέπτου. |
| user_id | string | USR_001 έως USR_060 | Αναγνωριστικό εργαζομένου. |
| role | categorical | Intern, Employee, Manager, Admin | Ρόλος RBAC. |
| department | categorical | Engineering, Finance, HR, Sales | Οργανωτική μονάδα. |
| network_zone | categorical | Internal_Corporate, VPN_Remote, Public_Internet | Ζώνη προέλευσης του αιτήματος. |
| device_id | string | DEV_101 έως DEV_160, DEV_UNKNOWN_xxxx | Αναγνωριστικό συσκευής (μία έμπιστη ανά χρήστη, άγνωστη σε ορισμένες ανωμαλίες). |
| resource_id | string | RES_PUB_*, RES_INT_*, RES_ENG_*, RES_FIN_*, RES_HR_*, RES_SAL_*, RES_GEN_* | Πόρος-στόχος. |
| sensitivity | categorical | Public, Internal, Confidential, Privileged | Κατηγορία ευαισθησίας πόρου. |
| action | categorical | Read, Write, Execute, Delete | Ζητούμενη ενέργεια. |
| outcome | categorical | Success, Failure | Αν το αίτημα πέτυχε ή απέτυχε. |
| is_anomaly | binary | 0, 1 | Ετικέτα ground truth (πραγματική κατάσταση). |
| anomaly_type | string | (βλέπε παρακάτω) ή κενό | Κατηγορία εγχυθείσας ανωμαλίας. |

### Σχεδιασμός του οργανισμού
- 60 χρήστες, κατανομή ρόλων Intern 20% / Employee 50% / Manager 20% / Admin 10%.
- 30 πόροι: 3 Public, 4 κοινοί Internal, Confidential/Privileged ανά τμήμα, και generic Internal.
- 14 ημέρες, ~15.000 συμβάντα, χρονοσφραγίδες ακρίβειας δευτερολέπτου.
- Κάθε χρήστης έχει ένα **προσωπικό behavioural baseline**: μια ώρα έναρξης εργασίας, μια
  κατανομή ζώνης δικτύου (το Sales κλίνει προς τηλεργασία) και ένα μικρό σύνολο
  συνηθισμένων πόρων.

### Κατηγορίες ανωμαλιών (6 τύποι, 150 συμβάντα ο καθένας, 6% συνολικά)
1. **Impossible_Travel** - επιτυχής πρόσβαση από `Public_Internet` (παραβίαση περιμέτρου).
2. **Off_Hours_Privileged** - πρόσβαση σε privileged πόρο στις 01:00-04:00.
3. **New_Device_Sensitive** - `DEV_UNKNOWN_*` που εκτελεί `Delete` σε Confidential/Privileged δεδομένα.
4. **Unusual_Resource_Access** - εντός ωραρίου, από έμπιστη συσκευή, πρόσβαση σε ευαίσθητο πόρο
   *άλλου* τμήματος (μόνο τα συμφραζόμενα το αποκαλύπτουν, κανένα μεμονωμένο πεδίο).
5. **Bulk_Data_Spike** - ριπή γρήγορων ενεργειών `Read` από έναν χρήστη (μόνο η συχνότητα το δείχνει).
6. **Privilege_Escalation** - αρκετές αποτυχημένες συνδέσεις ακολουθούμενες από μια επιτυχία (μόνο
   το ιστορικό πρόσφατων αποτυχιών το δείχνει).

Οι κατηγορίες 4 έως 6 είναι σκόπιμα **context-dependent** (εξαρτώμενες από τα συμφραζόμενα):
δεν πιάνονται με εξέταση ενός μεμονωμένου πεδίου, και ακριβώς αυτό δικαιολογεί το στάδιο του AI.

---

## 2. `baseline_decisions.csv` (έξοδος του Task 3)

| Πεδίο | Τύπος | Περιγραφή |
|---|---|---|
| event_id | string | Αναφορά στο συμβάν. |
| baseline_risk_score | float 0-100 | Ντετερμινιστικό σκορ με σταθμισμένους κανόνες. |
| baseline_decision | categorical | ALLOW / CHALLENGE / BLOCK. |
| is_anomaly / anomaly_type | - | Μεταφέρονται για την αξιολόγηση. |

Βάρη κανόνων: βάση 10, +35 Public_Internet, +15 VPN_Remote, +20 off-hours (22:00-05:00),
+25 Privileged, +15 Confidential, +15 Delete, +5 Write, +30 άγνωστη συσκευή, +10 αποτυχία.
Κατώφλια: ALLOW <45, CHALLENGE 45-74, BLOCK >=75.

---

## 3. `evaluated_risk_logs.csv` (έξοδος του Task 4)

Το πλήρες log μαζί με όλα τα engineered features, το AI risk score και την τελική απόφαση.

### Engineered features (όλα υπολογισμένα αιτιακά, μόνο από το παρελθόν)

| Feature | Τύπος | Ορισμός |
|---|---|---|
| access_frequency | int | Πλήθος αιτημάτων του χρήστη στα προηγούμενα 5 λεπτά (Bulk_Data_Spike). |
| recent_failure_count | int | Αποτυχημένα συμβάντα του χρήστη στα προηγούμενα 10 λεπτά (Privilege_Escalation). |
| session_resource_variety | int | Διακριτοί πόροι που άγγιξε ο χρήστης στα προηγούμενα 15 λεπτά. |
| is_off_hours | binary | Ωρα στο διάστημα [22..23, 0..5]. |
| device_novelty | binary | Πρώτη εμφάνιση του χρήστη σε αυτή τη συσκευή, ή άγνωστη συσκευή. |
| sensitivity_mismatch | binary | Intern/Employee που αγγίζει Confidential/Privileged δεδομένα. |
| peer_rarity_score | float | 1 - (προσβάσεις του τμήματος σε αυτόν τον πόρο / σύνολο τμήματος), running. |
| user_hour_deviation | float | Απόλυτη διαφορά της ώρας από τη running μέση ώρα του χρήστη. |
| zone_risk | int | 0 Internal, 1 VPN, 2 Public_Internet. |
| cross_department | binary | Πόρος που ανήκει σε διαφορετικό τμήμα από τον χρήστη (lateral movement). |
| iso_score | float | Σκορ ανωμαλίας του Isolation Forest (υβριδικό unsupervised σήμα). |

Πρόσθετες στήλες: `calculated_risk_score_ai` (0-100), `final_decision`, `decision_reason`.

---

## 4. `dynamic_access_decisions.csv` (έξοδος του Task 5)

Το τελικό Audit Log (έξοδος του Policy Decision Point), αυτό που βλέπει ο διορθωτής.

| Πεδίο | Περιγραφή |
|---|---|
| event_id | Αναγνωριστικό της προσπάθειας πρόσβασης. |
| calculated_risk_score_ai | AI risk score 0-100. |
| final_decision | ALLOW / CHALLENGE / BLOCK. |
| decision_reason | Αναγνώσιμη από άνθρωπο αιτιολογία (reason code). |

---

## 5. Αρχεία αξιολόγησης / fairness / drift

- `fairness_by_department.csv`, `fairness_by_role.csv`, `fairness_by_sensitivity.csv`
  (ανάλυση ανά ομάδες του Task 6 και προαιρετική ανάλυση fairness).
- `drift_summary.csv` (Task 7: before / after / after-mitigation).