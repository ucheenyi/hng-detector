# HNG Stage 3 — Anomaly Detection Engine

> A real-time DDoS and anomaly detection daemon that watches Nginx traffic, learns normal behaviour, automatically blocks attacking IPs with iptables, and serves a live metrics dashboard.

---

## Live Links

| | |
|---|---|
| **Server IP** | `40.123.244.39` |
| **Nextcloud** | `http://40.123.244.39` (accessible by IP only) |
| **Dashboard URL** | `http://ucheenyi.mooo.com` |
| **GitHub Repo** | `https://github.com/ucheenyi/hng-detector` |
| **Blog Post** | `https://dev.to/uchemira/anomaly-detector-5601` |


---

## Language Choice

**Python 3** — chosen for three reasons:

1. `collections.deque` gives an O(1) sliding window with no external libraries
2. `threading` makes it easy to run monitor, baseline, detector, dashboard and unbanner simultaneously
3. `psutil`, `flask`, and `pyyaml` are lightweight, well-documented, and pip-installable in seconds

---

## How the Sliding Window Works

Each sliding window is a `collections.deque` of Unix timestamps — one deque **per IP address** and one **global** deque covering all traffic.

**Eviction logic (how old entries are removed):**

```
On every new request:
  1. Append the current timestamp to the RIGHT of the deque
  2. While the LEFTMOST entry is older than (now - 60 seconds):
       pop it from the left
  3. rate = len(deque) / 60   → requests per second
```

This means the window always contains exactly the last 60 seconds of timestamps — no stale data, no resets, no approximation. It is a true sliding window, not a per-minute counter.

```python
from collections import deque
import time

window = deque()

def record_and_get_rate():
    now = time.time()
    window.append(now)                          # add to right
    cutoff = now - 60
    while window and window[0] < cutoff:        # evict from left
        window.popleft()
    return len(window) / 60                     # current req/s
```

---

## How the Baseline Works

The baseline answers the question: *"What is normal traffic for right now?"*

| Property | Value |
|---|---|
| **Rolling window size** | 30 minutes (1800 one-per-second samples) |
| **Recalculation interval** | Every 60 seconds |
| **Floor value** | `1.0` req/s minimum mean — prevents division-by-zero at startup |
| **Per-hour slots** | Traffic is bucketed by hour of day |
| **Hour preference** | If the current hour has ≥ 5 minutes of data (300 samples), it is used instead of the full rolling window — so rush-hour baseline stays accurate during rush hour |

Every 60 seconds the daemon computes:

```
mean   = average of all samples in the window
stddev = standard deviation of those samples
```

Both values are written to the audit log and shown live on the dashboard. They are **never hardcoded** — they emerge entirely from observed traffic.

---

## Detection Logic

An IP (or global traffic) is flagged as anomalous if **either** condition fires:

| Condition | Threshold | Description |
|---|---|---|
| Z-score | `> 3.0` | Rate is 3 standard deviations above the mean |
| Rate multiplier | `> 5× baseline mean` | Absolute spike regardless of variance |

**Error surge:** If an IP's 4xx/5xx error rate exceeds 3× the baseline error rate, both thresholds are automatically tightened by 50% for that IP.

**Response:**
- Per-IP anomaly → `iptables DROP` rule + Slack alert (within 10 seconds)
- Global anomaly → Slack alert only (no single IP to block)

**Auto-unban backoff schedule:**

| Offence | Ban Duration |
|---|---|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

---

## Repository Structure

```
hng-detector/
├── .gitignore
├── docker-compose.yml
├── README.md
├── detector/
│   ├── main.py            ← entry point, starts all threads
│   ├── monitor.py         ← tails nginx log, maintains sliding windows
│   ├── baseline.py        ← rolling 30-min mean/stddev, per-hour slots
│   ├── detector.py        ← z-score and rate anomaly checks
│   ├── blocker.py         ← iptables DROP + Slack ban alert
│   ├── unbanner.py        ← backoff unban schedule
│   ├── notifier.py        ← Slack webhook (reads SLACK_WEBHOOK_URL env var)
│   ├── dashboard.py       ← Flask live metrics UI on port 8080
│   ├── config.example.yaml ← safe to commit — placeholders only
│   └── requirements.txt
├── nginx/
│   └── nginx.conf         ← JSON access logs, X-Forwarded-For
├── docs/
│   └── architecture.png   ← system architecture diagram
└── screenshots/
    ├── Tool-running.png
    ├── Ban-slack.png
    ├── Unban-slack.png
    ├── Global-alert-slack.png
    ├── Iptables-banned.png
    ├── Audit-log.png
    └── Baseline-graph.png
```

---

## Setup Instructions (Fresh VM to Fully Running Stack)

### Prerequisites

- Ubuntu 22.04 LTS VM (minimum 2 vCPU, 2 GB RAM)
- Ports **80** and **8080** open in your firewall / security group
- A domain or subdomain pointed at your VM's public IP (for the dashboard)
- A Slack app with Incoming Webhooks enabled

---

### Step 1 — SSH into your VM

```bash
ssh uche@<YOUR_VM_PUBLIC_IP>
```

---

### Step 2 — Install system dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose python3 python3-full python3-venv git iptables
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
newgrp docker
```

---

### Step 3 — Clone the repository

```bash
git clone https://github.com/yourusername/hng-detector
cd hng-detector
```

---

### Step 4 — Create your real config

```bash
cd detector
cp config.example.yaml config.yaml
# config.yaml is in .gitignore — it will never be committed
cd ..
```

> The Slack webhook URL is set as an environment variable in the systemd service (Step 7), **not** in `config.yaml`.

---

### Step 5 — Create virtual environment and install Python dependencies

```bash
cd ~/hng-detector

# Create the venv (required on Ubuntu 22.04+ with Python 3.12)
python3 -m venv .venv
source .venv/bin/activate

pip install -r detector/requirements.txt
```

---

### Step 6 — Start Nextcloud + Nginx

```bash
docker-compose up -d

# Verify both containers are running
docker ps

# Find the real host path of the Nginx log volume
docker volume inspect hng-detector_HNG-nginx-logs
# Note the "Mountpoint" value — you'll need it in Step 7
```

Update `detector/config.yaml` with the real log path from the volume inspect output:

```yaml
log:
  path: "/var/lib/docker/volumes/hng-detector_HNG-nginx-logs/_data/hng-access.log"
  audit_path: "/var/log/detector-audit.log"
```

---

### Step 7 — Create the systemd service

```bash
sudo nano /etc/systemd/system/hng-detector.service
```

Paste the following, replacing the webhook URL and paths as needed:

```ini
[Unit]
Description=HNG Anomaly Detection Daemon
After=docker.service network.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/uche/hng-detector/detector
Environment="SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/REAL/WEBHOOK"
ExecStart=/home/uche/hng-detector/.venv/bin/python /home/uche/hng-detector/detector/main.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hng-detector
sudo systemctl start hng-detector

# Check status
sudo systemctl status hng-detector

# Watch live logs
sudo journalctl -u hng-detector -f
```

---

### Step 8 — Verify everything is working

```bash
# Nginx is writing JSON logs
docker exec nginx tail -5 /var/log/nginx/hng-access.log

# Dashboard is responding
curl http://localhost:8080/api/metrics

# Send test traffic to trigger a detection
sudo apt install -y apache2-utils
ab -n 5000 -c 50 http://localhost/

# Check iptables for a blocked IP
sudo iptables -L INPUT -n

# Check audit log
tail -20 /var/log/detector-audit.log
```

---

## Audit Log Format

Every ban, unban, and baseline recalculation is written to `/var/log/detector-audit.log` in this exact format:

```
[timestamp] ACTION ip | condition | rate | baseline | duration
```

**Examples:**

```
[2025-04-25T14:22:01] BAN 45.33.12.99 | condition=z-score=18.40 | rate=120.0000 | baseline=5.2000 | duration=10 min
[2025-04-25T14:32:01] UNBAN 45.33.12.99 | condition=z-score=18.40 | rate=120.0000 | baseline=5.2000 | duration=ban#1-expired
[2025-04-25T14:23:00] BASELINE_RECALC global | source=rolling | rate=5.2000 | baseline=5.2000 | stddev=1.3000
```

---

## Security Notes

- The real Slack webhook URL is **only** stored in the systemd `Environment=` line on the VM — never in any file committed to this repository
- `detector/config.yaml` is listed in `.gitignore` and is never committed
- `detector/config.example.yaml` contains only placeholder values and is safe to commit
- The daemon blocks IPs at the **iptables level** — no Fail2Ban, no rate-limiting libraries

---

## Screenshots

All 7 required screenshots are in the `screenshots/` folder:

| File | Shows |
|---|---|
| `Tool-running.png` | Daemon running, processing log lines |
| `Ban-slack.png` | Slack ban notification |
| `Unban-slack.png` | Slack unban notification |
| `Global-alert-slack.png` | Slack global anomaly notification |
| `Iptables-banned.png` | `sudo iptables -L -n` with a blocked IP |
| `Audit-log.png` | Structured audit log with ban, unban, and baseline events |
| `Baseline-graph.png` | Baseline mean over time showing ≥ 2 hourly slots |