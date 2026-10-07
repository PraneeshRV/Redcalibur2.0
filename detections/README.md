# Detections — Sigma rules for common Active Directory attacks

Detection-as-code for a set of widely-documented Active Directory attack
techniques. Each rule is written in [Sigma](https://sigmahq.io/), the vendor-
neutral detection format, and ships with sample events that prove the rule
catches the attack and stays quiet on normal activity.

The techniques here are standard, publicly-documented methods (MITRE ATT&CK),
the kind a threat hunter is expected to have detections for. Nothing here is
tied to any specific environment.

## Rules

| Rule | Technique | ATT&CK | Primary signal |
|---|---|---|---|
| `kerberoasting.yml` | Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | 4769 TGS request with RC4 (`0x17`) for a service account |
| `dcsync_ntds.yml` | DCSync / NTDS extraction | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | 4662 replication rights by a non-DC account |
| `lsass_credential_access.yml` | LSASS credential dumping | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Sysmon 10 handle to `lsass.exe` with a read access mask |
| `pass_the_hash.yml` | Pass-the-hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | 4624 LogonType 9 via `seclogo` / `Negotiate` |
| `llmnr_nbtns_poisoning.yml` | LLMNR/NBT-NS poisoning | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Sysmon 3 response from UDP 5355 / 137 |

Every rule documents its `falsepositives` and the tuning that turns a raw
heuristic into a production detection (baselining RC4 service accounts,
allow-listing replication and name-resolution infrastructure, and so on).

## How the tests work

Proving "catches the attack, quiet on normal" needs an engine that can decide
whether a given event matches a rule. Rather than stand up a SIEM, this package
ships a small offline evaluator (`evaluator.py`) that interprets the subset of
Sigma the rules use. The suite then runs three checks per rule:

1. **Valid Sigma** — [pySigma](https://github.com/SigmaHQ/pySigma) parses the
   rule, so it is real, portable detection-as-code (it converts to Splunk,
   Elastic, Sentinel, etc.), not YAML that merely looks right.
2. **True positive** — every attack event in `tests/vectors.py` fires the rule.
3. **True negative** — every benign event stays silent.

The evaluator is a test oracle only; shipping the rules anywhere uses a real
Sigma backend.

## Run

```bash
pip install -r detections/requirements.txt
cd detections && python -m pytest -q
```

## Layout

```
detections/
  sigma/            # the rules, one technique per file
  evaluator.py      # minimal offline Sigma matcher (test oracle)
  tests/
    vectors.py      # attack + benign sample events per rule
    test_detections.py
  requirements.txt
```
