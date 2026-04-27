# docs/generate_arch.py
# Run once to produce architecture.png — then commit the PNG, not this script.

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch

fig, ax = plt.subplots(figsize=(12, 7))
ax.set_xlim(0, 10)
ax.set_ylim(0, 8)
ax.axis("off")
fig.patch.set_facecolor("#0d1117")

def box(ax, x, y, w, h, label, sublabel="", color="#161b22", textcolor="#c9d1d9"):
    rect = mpatches.FancyBboxPatch((x, y), w, h,
        boxstyle="round,pad=0.1", linewidth=1.5,
        edgecolor="#58a6ff", facecolor=color)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h/2 + (0.15 if sublabel else 0), label,
            ha="center", va="center", fontsize=10, fontweight="bold", color=textcolor)
    if sublabel:
        ax.text(x + w/2, y + h/2 - 0.25, sublabel,
                ha="center", va="center", fontsize=7.5, color="#8b949e")

def arrow(ax, x1, y1, x2, y2, label=""):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle="->", color="#58a6ff", lw=1.5))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx+0.1, my, label, fontsize=7.5, color="#8b949e")

# Boxes
box(ax, 0.5, 6.2, 2.0, 0.9,  "Internet",       "HTTP Requests")
box(ax, 0.5, 4.8, 2.0, 0.9,  "Nginx",           "Reverse Proxy :80")
box(ax, 3.5, 4.8, 2.0, 0.9,  "HNG-nginx-logs",  "Docker Named Volume")
box(ax, 0.5, 3.3, 2.0, 0.9,  "Nextcloud",       "Docker Container")
box(ax, 3.5, 3.3, 2.0, 0.9,  "Monitor",         "Tails log file")
box(ax, 3.5, 2.0, 2.0, 0.9,  "Detector",        "z-score / rate check")
box(ax, 6.5, 3.3, 2.0, 0.9,  "Blocker",         "iptables DROP")
box(ax, 6.5, 2.0, 2.0, 0.9,  "Notifier",        "Slack Webhook")
box(ax, 6.5, 0.7, 2.0, 0.9,  "Unbanner",        "Backoff schedule")
box(ax, 3.5, 0.7, 2.0, 0.9,  "Dashboard",       "Flask :8080")
box(ax, 0.5, 0.7, 2.0, 0.9,  "Baseline",        "Mean / StdDev")

# Arrows
arrow(ax, 1.5, 6.2, 1.5, 5.7)
arrow(ax, 2.5, 5.25, 3.5, 5.25, "writes logs")
arrow(ax, 1.5, 4.8, 1.5, 4.2)
arrow(ax, 4.5, 4.8, 4.5, 4.2, "reads")
arrow(ax, 4.5, 3.3, 4.5, 2.9)
arrow(ax, 5.5, 2.45, 6.5, 2.45)
arrow(ax, 5.5, 3.75, 6.5, 3.75)
arrow(ax, 7.5, 3.3, 7.5, 2.9)
arrow(ax, 7.5, 2.0, 7.5, 1.6)
arrow(ax, 4.5, 2.0, 4.5, 1.6)
arrow(ax, 4.5, 2.0, 1.5, 1.6, "samples rps")

ax.set_title("HNG Anomaly Detection — Architecture",
             fontsize=13, color="#58a6ff", pad=10)

plt.tight_layout()
plt.savefig("docs/architecture.png", dpi=150, bbox_inches="tight",
            facecolor=fig.get_facecolor())
print("Saved docs/architecture.png")
