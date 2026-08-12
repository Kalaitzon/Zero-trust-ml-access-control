ΣΤΙΓΜΙΟΤΥΠΑ ΕΚΤΕΛΕΣΗΣ
=====================

Τα παρακατω screenshots αποδεικνυουν την πραγματικη εκτελεση ολοκληρου του
pipeline στο τοπικο περιβαλλον (Windows PowerShell) και επιβεβαιωνουν οτι τα
αποτελεσματα ειναι αναπαραγωγιμα και ταυτιζονται με αυτα της αναφορας.

01_execution_dataset_baseline_ai.png
  Εκτελεση των scripts 01, 02 και 03:
  - 01_generate_dataset.py  : παραγωγη 15.000 συμβαντων, 900 ανωμαλιες (6%),
                              6 τυποι ισοκατανεμημενοι (150 ο καθενας).
  - 02_baseline_policy.py   : στατικος baseline. Πιανει τους απλους τυπους (100%)
                              αλλα αστοχει τελειως (0%) στα context-dependent
                              Bulk_Data_Spike και Unusual_Resource_Access.
  - 03_ai_pipeline.py       : υβριδικο μοντελο AI. ROC-AUC=0.989, PR-AUC=0.942,
                              Recall ανωμαλιων=0.919 (εναντι baseline 0.804/0.550/0.613).

02_execution_fairness_drift.png
  Εκτελεση του script 04:
  - 04_drift_fairness_plots.py : αναλυση ανα ομαδα (τμημα/ρολο/ευαισθησια),
                                 προσομοιωση drift (precision 0.58 -> 0.15) και
                                 παραγωγη των 6 γραφηματων.
