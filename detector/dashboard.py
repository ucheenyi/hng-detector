# detector/dashboard.py
# A simple Flask web server that shows live metrics.
# Serves at http://<your-domain>:8080
# Auto-refreshes every 3 seconds via meta tag.

import time
import psutil
import logging
from flask import Flask, jsonify, render_template_string

log = logging.getLogger("dashboard")

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="3">
  <title>HNG Anomaly Detector — Live Dashboard</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 2em; }
    h1   { color: #58a6ff; }
    h2   { color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 4px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 1em 1.5em; margin-bottom: 1em; }
    .metric { font-size: 1.4em; color: #58a6ff; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; }
    th    { text-align: left; color: #8b949e; border-bottom: 1px solid #30363d; padding: 4px 8px; }
    td    { padding: 4px 8px; }
    tr:nth-child(even) { background: #0d1117; }
    .banned { color: #f85149; }
    .ok     { color: #3fb950; }
    .warn   { color: #d29922; }
  </style>
</head>
<body>
  <h1>🛡️ HNG Anomaly Detection Dashboard</h1>
  <p style="color:#8b949e">Auto-refreshes every 3 seconds &nbsp;|&nbsp; Uptime: {{ uptime }}</p>

  <div style="display:grid; grid-template-columns: repeat(3,1fr); gap:1em;">
    <div class="card">
      <div>Global Req/s</div>
      <div class="metric">{{ global_rps }}</div>
    </div>
    <div class="card">
      <div>Baseline Mean</div>
      <div class="metric">{{ baseline_mean }}</div>
    </div>
    <div class="card">
      <div>Baseline StdDev</div>
      <div class="metric">{{ baseline_stddev }}</div>
    </div>
    <div class="card">
      <div>CPU Usage</div>
      <div class="metric">{{ cpu }}%</div>
    </div>
    <div class="card">
      <div>Memory Usage</div>
      <div class="metric">{{ mem }}%</div>
    </div>
    <div class="card">
      <div>Banned IPs</div>
      <div class="metric banned">{{ banned_count }}</div>
    </div>
  </div>

  <h2>🚫 Banned IPs</h2>
  <div class="card">
    {% if banned_ips %}
    <table>
      <tr><th>IP</th><th>Bans</th><th>Condition</th><th>Rate</th><th>Unban At</th></tr>
      {% for ip, info in banned_ips.items() %}
      <tr>
        <td class="banned">{{ ip }}</td>
        <td>{{ info.ban_count }}</td>
        <td>{{ info.condition }}</td>
        <td>{{ "%.2f"|format(info.rate) }} req/s</td>
        <td>{{ "PERMANENT" if info.permanent else info.unban_at_str }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <span class="ok">No IPs currently banned.</span>
    {% endif %}
  </div>

  <h2>📊 Top 10 Source IPs</h2>
  <div class="card">
    <table>
      <tr><th>IP</th><th>Requests</th></tr>
      {% for ip, count in top_ips.items() %}
      <tr><td>{{ ip }}</td><td>{{ count }}</td></tr>
      {% endfor %}
    </table>
  </div>
</body>
</html>
"""


class DashboardServer:
    def __init__(self, config, shared_state):
        self.config       = config
        self.shared_state = shared_state
        self.app          = Flask(__name__)
        self.app.add_url_rule("/", "index", self._index)
        self.app.add_url_rule("/api/metrics", "metrics", self._metrics)

    def _index(self):
        with self.shared_state["lock"]:
            state = dict(self.shared_state)

        uptime_sec = int(time.time() - state["start_time"])
        h, rem     = divmod(uptime_sec, 3600)
        m, s       = divmod(rem, 60)
        uptime_str = f"{h}h {m}m {s}s"

        # Format unban times for display
        banned_display = {}
        for ip, info in state["banned_ips"].items():
            entry = dict(info)
            if info.get("unban_at"):
                entry["unban_at_str"] = time.strftime("%H:%M:%S", time.localtime(info["unban_at"]))
            else:
                entry["unban_at_str"] = "N/A"
            banned_display[ip] = entry

        return render_template_string(
            HTML,
            uptime=uptime_str,
            global_rps=state["global_rps"],
            baseline_mean=round(state["baseline_mean"], 4),
            baseline_stddev=round(state["baseline_stddev"], 4),
            cpu=round(psutil.cpu_percent(interval=None), 1),
            mem=round(psutil.virtual_memory().percent, 1),
            banned_count=len(state["banned_ips"]),
            banned_ips=banned_display,
            top_ips=state["top_ips"],
        )

    def _metrics(self):
        """JSON endpoint for programmatic access."""
        with self.shared_state["lock"]:
            state = dict(self.shared_state)
        return jsonify({
            "global_rps":      state["global_rps"],
            "baseline_mean":   state["baseline_mean"],
            "baseline_stddev": state["baseline_stddev"],
            "banned_count":    len(state["banned_ips"]),
            "cpu_percent":     psutil.cpu_percent(interval=None),
            "mem_percent":     psutil.virtual_memory().percent,
            "uptime_seconds":  int(time.time() - state["start_time"]),
        })

    def run(self):
        host = self.config["dashboard"]["host"]
        port = self.config["dashboard"]["port"]
        log.info(f"Dashboard starting at http://{host}:{port}")
        # Use werkzeug directly to suppress Flask startup banner noise
        import logging as pylog
        pylog.getLogger("werkzeug").setLevel(pylog.WARNING)
        self.app.run(host=host, port=port, threaded=True)
