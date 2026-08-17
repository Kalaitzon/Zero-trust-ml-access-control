EXECUTION SCREENSHOTS
=====================

The screenshots below demonstrate the actual execution of the entire pipeline in
the local environment (Windows PowerShell) and confirm that the results are
reproducible and match those in the report.

01_execution_dataset_baseline_ai.png
  Execution of scripts 01, 02 and 03:
  - 01_generate_dataset.py  : generates 15,000 events, 900 anomalies (6%),
                              6 evenly distributed types (150 each).
  - 02_baseline_policy.py   : static baseline. Catches the simple types (100%)
                              but fails completely (0%) on the context-dependent
                              Bulk_Data_Spike and Unusual_Resource_Access.
  - 03_ai_pipeline.py       : hybrid AI model. ROC-AUC=0.989, PR-AUC=0.942,
                              anomaly Recall=0.919 (vs baseline 0.804/0.550/0.613).

02_execution_fairness_drift.png
  Execution of script 04:
  - 04_drift_fairness_plots.py : group breakdown (department/role/sensitivity),
                                 drift simulation (precision 0.58 -> 0.15) and
                                 generation of the 6 figures.
