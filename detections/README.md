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

## Verified against real attack captures

Synthetic vectors are not the end of the story. `tools/evtx_replay.py`
parses real Windows event logs and runs each rule's own matching logic
over them; the sample captures are committed under `tools/evtx_samples/`
(from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
master `4ceed2f4706d`). Replay results, reproduced by the test suite:

| Rule | Capture | Matched |
|---|---|---|
| `dcsync_ntds.yml` | `CA_DCSync_4662.evtx` (Mimikatz DCSync) | 3/3 records |
| `lsass_credential_access.yml` | `sysmon_10_lsass_mimikatz_logonpasswords.evtx` | 1/1 records |
| `pass_the_hash.yml` | `LM_4624_mimikatz_pth_source.evtx` (sekurlsa::pth) | 1/6 records (the one injected logon) |

The replay already paid for itself: real logs write the LSASS access mask
zero-padded (`0x00001010`), which the original plain string list missed —
the rule now uses a padding-tolerant mask regex, and the zero-padded forms
are locked into the vectors. True positives are proven on real captures;
the quiet side stays on synthetic vectors, since these samples are attack
captures, not baselines.

## Proxy hunts

`proxy/` extends the same discipline to web/proxy telemetry, and is where
detection ends and hunting begins: Sigma rules for signature-shaped
signals (non-browser user agents on trusted sites, tunnel domains, risky
downloads) and Python hunts for the signals no per-event rule can express
(C2 beaconing, rare and upload-heavy domains). See
[proxy/README.md](proxy/README.md).

## Run

```bash
pip install -r detections/requirements.txt
cd detections && python -m pytest -q
```

## Layout

```
detections/
  sigma/            # AD attack rules, one technique per file
  proxy/            # proxy-category Sigma rules + beaconing/rare-domain hunts
    sigma/            # LOTS delivery, tunnels, risky downloads
    hunts/            # beacon_hunt.py, rare_domain_hunt.py (+ sample log generator)
    tests/
  tools/
    evtx_replay.py    # replay a rule against a real .evtx capture
    evtx_samples/     # real attack samples (see SOURCES.md)
  evaluator.py      # minimal offline Sigma matcher (test oracle)
  tests/
    vectors.py      # attack + benign sample events per rule
    test_detections.py
    test_evtx_replay.py
  requirements.txt
```
