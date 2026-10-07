# Proxy hunts — where detection rules end and hunting begins

This pack answers the question a web-telemetry team will actually ask: what
do you do when the signal is not about a single event? Two kinds of tool
live here, and the split is the point:

- **Sigma rules** (`sigma/`) for signature-shaped signals — one event, one
  question. Non-browser tools pulling from trusted sites attackers abuse,
  reverse-tunnel domains, risky download extensions. Same catch/quiet test
  contract as the AD pack, over `category: proxy` events.
- **Python hunts** (`hunts/`) for time-series and counting signals no
  per-event rule can express: C2 **beaconing** (regular contact intervals
  per source and destination) and **rare / upload-heavy domains**
  (least-frequency-of-observation plus bytes-up vs bytes-down).

That split *is* the detection-vs-hunting answer: Sigma asks "is this one
event suspicious?"; a hunt asks a question about many events together. A
beacon is invisible in any single log line — only counting gaps over time
reveals it.

## Signals

| Tool | Fires on | Tuning |
|---|---|---|
| `nonbrowser_ua_trusted_sites.yml` | curl / python / PowerShell pulling from GitHub raw, Discord CDN, Telegram API, Pastebin (LOTS delivery) | allow-list CI runners and package managers |
| `tunnel_service_domains.yml` | trycloudflare, ngrok, localhost.run, Serveo | alert on first-seen per org, allow-list dev users |
| `risky_download_extension.yml` | successful GET of .iso/.lnk/.hta/.js/... | strip query strings, allow-list vendor domains |
| `beacon_hunt.py` | (src, host) pairs with ≥20 contacts, ≥30 min span, jitter (stdev/mean of gaps) ≤ 0.25 | raise/lower MAX_JITTER per environment |
| `rare_domain_hunt.py` | registrable domains seen by one source at volume, or ≥10× more bytes up than down | volume thresholds are policy, set per org |

## Try it

```bash
cd detections/proxy
python hunts/make_sample_log.py sample_data/sample_proxy_log.jsonl  # already committed
python hunts/beacon_hunt.py sample_data/sample_proxy_log.jsonl
python hunts/rare_domain_hunt.py sample_data/sample_proxy_log.jsonl
```

The sample log is deterministic and planted (see `make_sample_log.py` for
the ground truth): a 60-second C2 beacon hidden in 30 users' browsing, an
exfiltration destination pushing 15 MB up under a browser user agent, and a
one-person blog that must stay quiet at default thresholds. Note the two
hunts converge on the beacon's domain independently — two different
analytics pointing at one operator is how leads become cases.

## Field names

Events (and the sample log) use the common Sigma proxy conventions:
`src`, `cs-method`, `cs-host`, `c-uri`, `sc-status`, `UserAgent`,
`cs-bytes` (client to server), `sc-bytes` (server to client).
