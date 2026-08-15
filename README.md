# Zero-Trust Adaptive Access-Control Engine

## What this project is

A "decision engine" that decides, for every access request an employee makes to a
corporate resource, whether to **allow** it, ask for **extra verification**, or
**block** it. It follows the Zero Trust philosophy: it trusts nothing in advance,
but instead evaluates every request based on context (who, when, from where, to
which resource).

The engine combines two ways of reasoning:

1. A simple **static rule-based** mechanism (baseline), e.g. "access from the public
   internet = suspicious". It is transparent but "blind" to complex attacks.
2. A **Machine Learning (AI)** model that learns each user's normal behaviour and
   detects deviations from it.

The full analysis, results, metrics and figures are in the **report**. This README
simply explains what each script does and how to run the project.

---

## Three key concepts (in plain language)

**SEED (random seed).** The code generates "random" data (users, times, attacks).
If randomness were left free, every run would produce different data and different
numbers. The seed is a fixed "key number" (here `25012`) that makes the randomness
repeat identically every time. So anyone who runs the code gets exactly the same
results as the report.

**HYBRID (hybrid model).** The AI consists of two parts working together. The first
(**Isolation Forest**) looks for "strange" events on its own, without knowing which
are attacks. The second (**Gradient Boosting**) is a classifier that has seen
examples of attacks and scores the risk from 0 to 100. The first feeds the second.
Beneath them sit a few fixed security rules (e.g. "access from the public internet
is never auto-approved") that act as a safety net in case the AI is wrong.

**TEMPORAL LEAKAGE (and why we avoid it).** When we train an AI, we split the data
into "training" (to learn from) and "evaluation" (to test it on things it has never
seen). If this split is done randomly, the model may accidentally "see" information
from the future during training. Then it produces perfect but fake test numbers,
because in reality the future is unknown. To avoid it, we sort all events
**chronologically** and give the model the oldest 70% for training and the newest
30% for evaluation (a "70/30 temporal split"). In addition, every feature that looks
at a user's history (e.g. "how many requests in the last 5 minutes") is computed
only from the **past**, never from the future. This is why the report's numbers are
realistic, not artificially perfect.

---

## 1. Folder structure

```
access-control/                   <- project root
|
+-- 01_generate_dataset.py        builds the data + injects attacks (task 1, 2)
+-- 02_baseline_policy.py         the simple static rule mechanism (task 3)
+-- 03_ai_pipeline.py             features + AI model + decisions (task 4, 5)
+-- 04_drift_fairness_plots.py    evaluation, fairness, drift, figures (task 6, 7, optional)
|
+-- data/                         (generated automatically when the scripts run)
|     synthetic_enterprise_logs.csv   the base dataset of 15,000 events
|     baseline_decisions.csv          score + decision of the simple mechanism
|     evaluated_risk_logs.csv         full log + features + AI score + decision
|     dynamic_access_decisions.csv    the final decisions file (audit log)
|     fairness_by_department.csv      metrics per department
|     fairness_by_role.csv            metrics per role
|     fairness_by_sensitivity.csv     metrics per resource sensitivity
|     drift_summary.csv               results of the drift scenario
|
+-- figures/                      (generated automatically) fig1..fig6, the report figures
|
+-- README.md                     this file
+-- SCHEMA.md                     detailed description of all data fields & features
+-- requirements.txt              the Python libraries needed
```

---

## 2. Requirements

Python 3.10 or newer. Install the libraries:

```bash
pip install -r requirements.txt
```

Libraries: `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `joblib`. Everything
runs locally, with no internet connection.

---

## 3. How to run (in order)

On Windows (using the `python` command), run the four scripts in this order:

```bash
python 01_generate_dataset.py       # -> data/synthetic_enterprise_logs.csv
python 02_baseline_policy.py        # -> data/baseline_decisions.csv
python 03_ai_pipeline.py            # -> evaluated_risk_logs.csv, dynamic_access_decisions.csv
python 04_drift_fairness_plots.py   # -> the figures and the remaining csv
```

**Mind the order:** each script reads the file produced by the previous one, so they
must run in exactly this order. Thanks to the seed (see above), every run gives the
same results. The scripts create the `data/` and `figures/` folders automatically if
they do not exist.

---

## 4. What each task does (and which file implements it)

### Task 1 - Design of the enterprise scenario
Builds a synthetic organisation so we have data to work with: 60 employees, 4
departments (Engineering, Finance, HR, Sales), 4 roles (Intern, Employee, Manager,
Admin) and 30 resources with different sensitivity levels. Each employee has their
own "habits" (typical hours, device, resources they use), so that later we can tell
when something deviates from their normal pattern.
**File:** `01_generate_dataset.py` -> `data/synthetic_enterprise_logs.csv`, `SCHEMA.md`

### Task 2 - Creating the attacks (anomalies)
Inside the normal data we "hide" attacks (6% of the events), to test whether the
system finds them. Six types were built:

- **Impossible_Travel** - successful login from the open internet (perimeter breach).
- **Off_Hours_Privileged** - access to a very sensitive resource at night (01:00-04:00).
- **New_Device_Sensitive** - an unknown device that deletes sensitive data.
- **Unusual_Resource_Access** - an employee accessing a sensitive resource of *another* department.
- **Bulk_Data_Spike** - one user downloads a huge number of files in seconds (data theft).
- **Privilege_Escalation** - many failed logins followed by one success (password cracking).

The last three types are "hard": no single field looks suspicious, only their
combination or history gives them away. These are exactly what the simple mechanism
cannot catch, which is why the AI is needed.
**File:** `01_generate_dataset.py` -> `data/synthetic_enterprise_logs.csv` (with labels)

### Task 3 - The simple static rule mechanism (baseline)
A simple system that assigns "penalties" to each request (e.g. +35 from the internet,
+30 for an unknown device), produces a 0-100 score and decides ALLOW / CHALLENGE /
BLOCK. It is the reference point against which we compare the AI. It catches the
obvious attacks but fails completely on the two most "hidden" ones.
**File:** `02_baseline_policy.py` -> `data/baseline_decisions.csv`

### Task 4 - The Machine Learning (AI) model
The "smart" part. First we compute 11 features for each event, e.g. "how many
requests the user made in the last 5 minutes" or "is it accessing another
department's resource?". Then we train the hybrid model (see **HYBRID** above) which
gives each event a risk score of 0-100. Everything is done carefully to avoid
temporal leakage (see **TEMPORAL LEAKAGE**).
**File:** `03_ai_pipeline.py` -> `data/evaluated_risk_logs.csv`

### Task 5 - The decision engine
Converts the AI score into a final decision. Low = ALLOW (permitted), medium =
CHALLENGE (asks for extra verification, e.g. a code on the phone / MFA), high = BLOCK
(rejected). It also has a few fixed security rules that override the model (e.g.
access from the internet always requires extra verification). Each decision comes
with an explanation of why it was made.
**File:** `03_ai_pipeline.py` -> `data/dynamic_access_decisions.csv`

### Task 6 - Evaluation (how well it works)
We measure the AI's performance and compare it with the simple mechanism, on the
exact same data. We create figures (performance curves, which features mattered
most, how well each attack type was caught) and break the results down per
department / role / sensitivity. The full numbers are in the report.
**File:** `04_drift_fairness_plots.py` -> `figures/fig1..fig4`, `data/fairness_*.csv`

### Task 7 - Test under changing conditions (drift) + governance
What happens if the environment changes? We simulate a "full remote-work week":
everyone connects from home, at different hours, from new devices. The model, trained
on the normal office routine, starts producing many false alarms. We show the
performance drop and discuss how it is handled (temporary rules, retraining, human
approval).
**File:** `04_drift_fairness_plots.py` -> `data/drift_summary.csv`, `figures/fig6_drift.png`

---

## 5. Optional task - Fairness analysis

An extra, non-mandatory part. We check whether the system is unfairly "stricter" with
certain groups of employees, i.e. whether a department or role receives far more
false alarms (false positives) than others. This relates to the responsible use of
Artificial Intelligence (fairness). We found small differences (e.g. Sales is
bothered a bit more, because it works more remotely) and propose an improvement.
**File:** `04_drift_fairness_plots.py` -> `data/fairness_by_department.csv`,
`data/fairness_by_role.csv`, `data/fairness_by_sensitivity.csv`, `figures/fig5_fairness.png`

---

## 6. Documentation

The full description (methodology, all results, metrics, figures, tables and
discussion) is in the report. The `SCHEMA.md` file describes in detail all the data
fields and the features computed by the model.
