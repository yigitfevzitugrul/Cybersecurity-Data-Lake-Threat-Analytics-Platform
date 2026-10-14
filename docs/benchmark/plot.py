"""benchmark_60d.json'dan tespit süresi grafiğini çizer (docs/benchmark/detection_time.png).

matplotlib projenin bağımlılığı değildir; bu betik yalnızca rapor grafiği içindir:
    pip install matplotlib && python docs/benchmark/plot.py
"""
import json
from pathlib import Path

import matplotlib.pyplot as plt

HERE = Path(__file__).parent
SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
FULL, INCREMENTAL = "#eb6834", "#2a78d6"  # kategorik sıra: 1 mavi, 2 turuncu

report = json.loads((HERE / "benchmark_60d.json").read_text(encoding="utf-8"))
days = report["per_day"]
x = [d["total_events"] / 1000 for d in days]

fig, ax = plt.subplots(figsize=(8, 4.2), dpi=150, facecolor=SURFACE)
ax.set_facecolor(SURFACE)
for key, color, label in (("full_ms", FULL, "Tam tespit (bütün geçmiş)"),
                          ("incremental_ms", INCREMENTAL, "Artımlı tespit (yeni gün + 24 saat)")):
    y = [d[key] for d in days]
    ax.plot(x, y, color=color, linewidth=2, label=label)
    ax.annotate(f"{y[-1]} ms", (x[-1], y[-1]), xytext=(6, 0), textcoords="offset points",
                va="center", color=INK, fontsize=9)

ax.set_xlabel("Veritabanındaki toplam olay (bin)", color=MUTED, fontsize=9)
ax.set_ylabel("Günlük tespit süresi (ms)", color=MUTED, fontsize=9)
ax.set_title(f"{report['parameters']['days']} günlük yükleme: tespit süresi ve veri hacmi",
             color=INK, fontsize=11, loc="left")
ax.grid(axis="y", color=GRID, linewidth=0.8)
ax.set_axisbelow(True)
for side in ("top", "right"):
    ax.spines[side].set_visible(False)
for side in ("left", "bottom"):
    ax.spines[side].set_color(GRID)
ax.tick_params(colors=MUTED, labelsize=8)
ax.set_ylim(bottom=0)
ax.set_xlim(left=0, right=max(x) * 1.08)
ax.legend(frameon=False, fontsize=9, labelcolor=INK, loc="upper left")
fig.tight_layout()
fig.savefig(HERE / "detection_time.png", facecolor=SURFACE)
print(HERE / "detection_time.png")
