"""Haftalık güvenlik raporu: bir haftanın etkinliğini tek dosyalık bir HTML rapora özetler.

Hafta pazartesi 00:00'dan sonraki pazartesi 00:00'a kadardır (UTC, olay zamanına göre).
Rapor; temel sayıları ve önceki haftaya göre değişimi, günlük saldırı grafiğini, alarm ve
MITRE ATT&CK özetini, kritik alarmları, en çok saldıran IP'leri, yetki yükseltme
girişimlerini ve o haftanın verisini taşıyan pipeline çalıştırmalarının veri kalitesini içerir.
Aynı sayılar JSON olarak da yazılır.

Kullanım:
    python -m src.reporting.weekly [--week-ending YYYY-MM-DD] [--telegram]
"""
import argparse
import json
import os
from datetime import date, datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Optional

from src.etl.pipeline import DATA_DIR
from src.utils.db import apply_schema, get_connection

REPORT_DIR = DATA_DIR / "curated" / "reports"
TOP_N = 10
DAY_NAMES = ["Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz"]
SEVERITIES = ["critical", "high", "medium", "low"]


def last_monday(today: Optional[date] = None) -> date:
    """Bugünden önceki (bugün pazartesiyse bugünkü) pazartesi: tamamlanmış son haftanın sonu."""
    today = today or datetime.now(timezone.utc).date()
    return today - timedelta(days=today.weekday())


def week_bounds(week_ending: date) -> tuple[datetime, datetime]:
    end = datetime.combine(week_ending, datetime.min.time())
    return end - timedelta(days=7), end


def _rows(conn, sql: str, params: dict) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def _one(conn, sql: str, params: dict) -> tuple:
    return _rows(conn, sql, params)[0]


def kpis(conn, start: datetime, end: datetime) -> dict:
    p = {"start": start, "end": end}
    failed, success, ips, users = _one(conn, """
        SELECT COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_failed'), 0),
               COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_success'), 0),
               COUNT(DISTINCT source_ip) FILTER (WHERE event_type = 'login_failed'),
               COUNT(DISTINCT username) FILTER (WHERE event_type = 'login_failed')
        FROM auth_events WHERE event_time >= %(start)s AND event_time < %(end)s""", p)
    privilege_failures, = _one(conn, """
        SELECT COALESCE(SUM(attempts), 0) FROM privilege_events
        WHERE event_time >= %(start)s AND event_time < %(end)s
          AND event_type IN ('sudo_auth_failure', 'sudo_not_allowed', 'su_failure')""", p)
    alerts, critical, high = _one(conn, """
        SELECT COUNT(*), COUNT(*) FILTER (WHERE severity = 'critical'), COUNT(*) FILTER (WHERE severity = 'high')
        FROM alerts WHERE window_start >= %(start)s AND window_start < %(end)s""", p)
    return {
        "failed_attempts": int(failed), "successful_logins": int(success),
        "attacking_ips": ips, "targeted_usernames": users,
        "privilege_failures": int(privilege_failures),
        "alerts": alerts, "critical_alerts": critical, "high_alerts": high,
    }


def collect(conn, week_ending: date) -> dict:
    """Raporun bütün sayıları (JSON'a yazılabilir)."""
    start, end = week_bounds(week_ending)
    p = {"start": start, "end": end, "top": TOP_N}
    current = kpis(conn, start, end)
    previous = kpis(conn, start - timedelta(days=7), start)

    daily = {row[0]: row[1:] for row in _rows(conn, """
        SELECT event_time::date,
               COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_failed'), 0),
               COALESCE(SUM(repeat_count) FILTER (WHERE event_type = 'login_success'), 0)
        FROM auth_events WHERE event_time >= %(start)s AND event_time < %(end)s
        GROUP BY 1""", p)}
    daily_alerts = dict(_rows(conn, """
        SELECT window_start::date, COUNT(*) FROM alerts
        WHERE window_start >= %(start)s AND window_start < %(end)s GROUP BY 1""", p))
    days = []
    for i in range(7):
        day = (start + timedelta(days=i)).date()
        failed, success = daily.get(day, (0, 0))
        days.append({"date": day.isoformat(), "failed_attempts": int(failed), "successful_logins": int(success),
                     "alerts": daily_alerts.get(day, 0)})

    by_severity = dict(_rows(conn, """
        SELECT severity, COUNT(*) FROM alerts
        WHERE window_start >= %(start)s AND window_start < %(end)s GROUP BY 1""", p))
    by_rule = _rows(conn, """
        SELECT rule, COUNT(*), COUNT(*) FILTER (WHERE severity IN ('critical', 'high'))
        FROM alerts WHERE window_start >= %(start)s AND window_start < %(end)s
        GROUP BY 1 ORDER BY 2 DESC, 1""", p)
    techniques = _rows(conn, """
        SELECT t.tactic, t.technique_id, t.name, t.url, COUNT(*)
        FROM alerts a CROSS JOIN LATERAL unnest(a.mitre_techniques) AS tid
        JOIN attack_techniques t ON t.technique_id = tid
        WHERE a.window_start >= %(start)s AND a.window_start < %(end)s
        GROUP BY t.tactic_id, t.tactic, t.technique_id, t.name, t.url
        ORDER BY t.tactic_id, 5 DESC""", p)
    critical = _rows(conn, """
        SELECT window_start, rule, COALESCE(host(source_ip), '-'), COALESCE(username, '(birden çok)'),
               array_to_string(mitre_techniques, ', '),
               COALESCE((SELECT string_agg(r, ', ') FROM jsonb_array_elements_text(details->'reasons') r), '')
        FROM alerts
        WHERE severity = 'critical' AND window_start >= %(start)s AND window_start < %(end)s
        ORDER BY window_start""", p)
    top_ips = _rows(conn, """
        SELECT host(e.source_ip),
               COALESCE(g.country_name, CASE WHEN g.is_global = false THEN 'özel / ayrılmış adres' END, ''),
               SUM(e.repeat_count),
               COUNT(DISTINCT e.username),
               (SELECT COUNT(*) FROM alerts a WHERE a.source_ip = e.source_ip
                  AND a.window_start >= %(start)s AND a.window_start < %(end)s)
        FROM auth_events e LEFT JOIN ip_geolocation g ON g.ip = e.source_ip
        WHERE e.event_type = 'login_failed' AND e.event_time >= %(start)s AND e.event_time < %(end)s
        GROUP BY e.source_ip, g.country_name, g.is_global
        ORDER BY 3 DESC, 1 LIMIT %(top)s""", p)
    top_users = _rows(conn, """
        SELECT username, SUM(repeat_count), COUNT(DISTINCT source_ip), bool_or(is_invalid_user)
        FROM auth_events
        WHERE event_type = 'login_failed' AND event_time >= %(start)s AND event_time < %(end)s
        GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT %(top)s""", p)
    privilege = _rows(conn, """
        SELECT username,
               COALESCE(SUM(attempts) FILTER (WHERE event_type IN ('sudo_auth_failure', 'sudo_not_allowed', 'su_failure')), 0),
               COUNT(*) FILTER (WHERE event_type = 'sudo_command'),
               COUNT(*) FILTER (WHERE event_type = 'su_success')
        FROM privilege_events WHERE event_time >= %(start)s AND event_time < %(end)s
        GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT %(top)s""", p)
    sensitive = _rows(conn, """
        SELECT window_start, username, array_to_string(mitre_techniques, ', '),
               COALESCE((SELECT string_agg(c, ' | ') FROM jsonb_array_elements_text(details->'commands') c), '')
        FROM alerts
        WHERE rule = 'sensitive_command' AND window_start >= %(start)s AND window_start < %(end)s
        ORDER BY window_start""", p)

    # Veri kalitesi: bu haftanın olaylarını yükleyen pipeline çalıştırmaları.
    quality = _one(conn, """
        WITH runs AS (
            SELECT DISTINCT run_id FROM auth_events WHERE event_time >= %(start)s AND event_time < %(end)s
            UNION
            SELECT DISTINCT run_id FROM privilege_events WHERE event_time >= %(start)s AND event_time < %(end)s
        )
        SELECT COUNT(*), COALESCE(SUM(lines_read), 0), COALESCE(SUM(lines_rejected), 0),
               COUNT(*) FILTER (WHERE status = 'failed')
        FROM pipeline_runs WHERE run_id IN (SELECT run_id FROM runs)""", p)
    reject_reasons = _rows(conn, """
        WITH runs AS (
            SELECT DISTINCT run_id FROM auth_events WHERE event_time >= %(start)s AND event_time < %(end)s
            UNION
            SELECT DISTINCT run_id FROM privilege_events WHERE event_time >= %(start)s AND event_time < %(end)s
        )
        SELECT reject_reason, COUNT(*) FROM rejected_events
        WHERE run_id IN (SELECT run_id FROM runs) GROUP BY 1 ORDER BY 2 DESC, 1""", p)
    runs, lines_read, lines_rejected, failed_runs = quality

    return {
        "week_start": start.date().isoformat(),
        "week_end": (end - timedelta(days=1)).date().isoformat(),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "kpis": current,
        "previous_kpis": previous,
        "daily": days,
        "alerts_by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "alerts_by_rule": [{"rule": r, "alerts": n, "high_or_critical": hc} for r, n, hc in by_rule],
        "attack_techniques": [{"tactic": ta, "technique": tid, "name": n, "url": u, "alerts": c}
                              for ta, tid, n, u, c in techniques],
        "critical_alerts": [{"time": t.isoformat(sep=" ", timespec="minutes"), "rule": r, "source_ip": ip,
                             "username": u, "techniques": te, "reasons": re}
                            for t, r, ip, u, te, re in critical],
        "top_attacking_ips": [{"ip": ip, "country": c, "failed_attempts": int(f), "usernames": n, "alerts": a}
                              for ip, c, f, n, a in top_ips],
        "top_targeted_usernames": [{"username": u, "failed_attempts": int(f), "source_ips": n, "invalid_user": inv}
                                   for u, f, n, inv in top_users],
        "privilege_by_user": [{"username": u, "failures": int(f), "sudo_commands": s, "su_success": su}
                              for u, f, s, su in privilege],
        "sensitive_commands": [{"time": t.isoformat(sep=" ", timespec="minutes"), "username": u,
                                "techniques": te, "commands": c} for t, u, te, c in sensitive],
        "data_quality": {
            "pipeline_runs": runs, "failed_runs": failed_runs, "lines_read": int(lines_read),
            "lines_rejected": int(lines_rejected),
            "reject_ratio": round(int(lines_rejected) / int(lines_read), 4) if lines_read else 0.0,
            "reject_reasons": dict(reject_reasons),
        },
    }


# --- HTML -----------------------------------------------------------------------------

CSS = """
:root { --surface: #fcfcfb; --card: #ffffff; --ink: #0b0b0b; --muted: #52514e; --line: #e4e3df;
  --accent: #2a78d6; --critical: #d03b3b; --serious: #ec835a; --warning: #fab219; --good: #0ca30c; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--surface); color: var(--ink);
  font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 32px 0 12px; padding-top: 16px; border-top: 1px solid var(--line); }
.sub { color: var(--muted); margin: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 20px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
.tile .label { color: var(--muted); font-size: 12px; }
.tile .value { font-size: 24px; font-weight: 600; font-variant-numeric: tabular-nums; }
.tile .delta { font-size: 12px; color: var(--muted); }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line);
  border-radius: 8px; overflow: hidden; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 500; font-size: 12px; background: #f6f5f2; }
td.num, th.num { text-align: right; }
tr:last-child td { border-bottom: 0; }
.sev { display: inline-flex; align-items: center; gap: 6px; }
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.empty { color: var(--muted); font-style: italic; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; align-items: start; }
code { font-size: 12px; }
a { color: var(--accent); }
.chart { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
.chart svg { width: 100%; height: auto; display: block; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
"""

SEVERITY_COLORS = {"critical": "var(--critical)", "high": "var(--serious)", "medium": "var(--warning)",
                   "low": "var(--accent)"}
KPI_LABELS = [
    ("failed_attempts", "Başarısız deneme"),
    ("attacking_ips", "Saldıran IP"),
    ("successful_logins", "Başarılı giriş"),
    ("alerts", "Alarm"),
    ("critical_alerts", "Kritik alarm"),
    ("privilege_failures", "Başarısız yetki girişimi"),
]


def _n(value) -> str:
    return f"{value:,}".replace(",", ".")


def _delta(current: int, previous: int) -> str:
    if previous == 0:
        return "önceki hafta: 0" if current == 0 else "önceki hafta veri yok"
    change = (current - previous) / previous * 100
    arrow = "▲" if change > 0 else ("▼" if change < 0 else "■")
    return f"{arrow} %{abs(change):.0f} (önceki: {_n(previous)})"


def _table(headers: list[str], rows: list[list[str]], numeric: set[int] = frozenset(), empty: str = "Kayıt yok.") -> str:
    if not rows:
        return f'<p class="empty">{empty}</p>'
    head = "".join(f'<th class="num">{h}</th>' if i in numeric else f"<th>{h}</th>" for i, h in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(f'<td class="num">{c}</td>' if i in numeric else f"<td>{c}</td>" for i, c in enumerate(r))
        + "</tr>" for r in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _severity(sev: str) -> str:
    return f'<span class="sev"><span class="dot" style="background:{SEVERITY_COLORS.get(sev, "#999")}"></span>{escape(sev)}</span>'


def nice_axis(peak: int, ticks: int = 4) -> tuple[int, int]:
    """Eksen için yuvarlak adım (1, 2, 5 × 10^n) ve bu adımla ulaşılan üst sınır."""
    raw = max(peak, 1) / ticks
    magnitude = 10 ** (len(str(int(raw))) - 1)
    step = next(m * magnitude for m in (1, 2, 5, 10) if m * magnitude >= raw)
    return step, step * -(-max(peak, 1) // step)


def daily_chart(days: list[dict]) -> str:
    """Günlük başarısız denemeler: tek serili sütun grafiği (satır içi SVG)."""
    width, height, left, bottom, top = 640, 220, 44, 28, 16
    tick_step, peak = nice_axis(max((d["failed_attempts"] for d in days), default=0))
    step = (width - left - 8) / len(days)
    bar = min(48, step * 0.6)
    ticks = range(0, peak + 1, tick_step)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Günlük başarısız deneme sayıları">']
    for t in ticks:
        y = height - bottom - (height - bottom - top) * t / peak
        parts.append(f'<line x1="{left}" x2="{width - 8}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e4e3df"/>')
        parts.append(f'<text x="{left - 6}" y="{y + 4:.1f}" text-anchor="end" font-size="11" fill="#52514e">{_n(t)}</text>')
    for i, d in enumerate(days):
        value = d["failed_attempts"]
        h = (height - bottom - top) * value / peak
        x = left + step * i + (step - bar) / 2
        y = height - bottom - h
        day = date.fromisoformat(d["date"])
        label = f'{DAY_NAMES[day.weekday()]} {day.day:02d}.{day.month:02d}'
        if value:
            parts.append(
                f'<path d="M{x:.1f},{height - bottom} V{y + 4:.1f} Q{x:.1f},{y:.1f} {x + 4:.1f},{y:.1f} '
                f'H{x + bar - 4:.1f} Q{x + bar:.1f},{y:.1f} {x + bar:.1f},{y + 4:.1f} V{height - bottom} Z" '
                f'fill="#2a78d6"><title>{label}: {_n(value)} başarısız deneme, {d["alerts"]} alarm</title></path>'
            )
            parts.append(f'<text x="{x + bar / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle" font-size="11" '
                         f'fill="#0b0b0b">{_n(value)}</text>')
        parts.append(f'<text x="{x + bar / 2:.1f}" y="{height - 8}" text-anchor="middle" font-size="11" '
                     f'fill="#52514e">{label}</text>')
    parts.append(f'<line x1="{left}" x2="{width - 8}" y1="{height - bottom}" y2="{height - bottom}" stroke="#c9c8c3"/>')
    parts.append("</svg>")
    return "".join(parts)


def render_html(r: dict) -> str:
    k, prev = r["kpis"], r["previous_kpis"]
    tiles = "".join(
        f'<div class="tile"><div class="label">{label}</div><div class="value">{_n(k[key])}</div>'
        f'<div class="delta">{_delta(k[key], prev[key])}</div></div>'
        for key, label in KPI_LABELS
    )
    severity_rows = [[_severity(s), _n(n)] for s, n in r["alerts_by_severity"].items()]
    rule_rows = [[f"<code>{escape(x['rule'])}</code>", _n(x["alerts"]), _n(x["high_or_critical"])]
                 for x in r["alerts_by_rule"]]
    technique_rows = [[escape(x["tactic"]), f'<a href="{escape(x["url"])}">{escape(x["technique"])}</a>',
                       escape(x["name"]), _n(x["alerts"])] for x in r["attack_techniques"]]
    critical_rows = [[escape(x["time"]), f"<code>{escape(x['rule'])}</code>", escape(x["source_ip"]),
                      escape(x["username"]), escape(x["techniques"]), escape(x["reasons"])]
                     for x in r["critical_alerts"]]
    ip_rows = [[f"<code>{escape(x['ip'])}</code>", escape(x["country"]) or "—", _n(x["failed_attempts"]),
                _n(x["usernames"]), _n(x["alerts"])] for x in r["top_attacking_ips"]]
    user_rows = [[escape(x["username"]) + (" <span class='empty'>(sistemde yok)</span>" if x["invalid_user"] else ""),
                  _n(x["failed_attempts"]), _n(x["source_ips"])] for x in r["top_targeted_usernames"]]
    privilege_rows = [[escape(x["username"]), _n(x["failures"]), _n(x["sudo_commands"]), _n(x["su_success"])]
                      for x in r["privilege_by_user"]]
    sensitive_rows = [[escape(x["time"]), escape(x["username"]), escape(x["techniques"]),
                       f"<code>{escape(x['commands'])}</code>"] for x in r["sensitive_commands"]]
    q = r["data_quality"]
    reason_rows = [[f"<code>{escape(reason)}</code>", _n(n)] for reason, n in q["reject_reasons"].items()]
    has_countries = any(x["country"] for x in r["top_attacking_ips"])

    return f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Haftalık güvenlik raporu {r['week_start']}</title><style>{CSS}</style></head>
<body><main>
<h1>Haftalık güvenlik raporu</h1>
<p class="sub">{r['week_start']} – {r['week_end']} (UTC, olay zamanına göre) · üretildi: {r['generated_at']}</p>
<div class="tiles">{tiles}</div>

<h2>Günlük başarısız giriş denemeleri</h2>
<div class="chart">{daily_chart(r['daily'])}</div>

<h2>Alarmlar</h2>
<div class="grid2">
{_table(["Önem", "Alarm"], severity_rows, {1})}
{_table(["Kural", "Alarm", "High / critical"], rule_rows, {1, 2}, "Bu hafta alarm yok.")}
</div>

<h2>MITRE ATT&amp;CK teknikleri</h2>
{_table(["Taktik", "Teknik", "Ad", "Alarm"], technique_rows, {3}, "Bu hafta alarm yok.")}

<h2>Kritik alarmlar</h2>
{_table(["Zaman", "Kural", "Kaynak IP", "Hesap", "ATT&amp;CK", "Sebep"], critical_rows, set(), "Bu hafta kritik alarm yok.")}

<h2>En çok saldıran IP'ler</h2>
{_table(["IP", "Ülke", "Başarısız deneme", "Denenen kullanıcı", "Alarm"], ip_rows, {2, 3, 4})}

<h2>En çok hedeflenen kullanıcı adları</h2>
{_table(["Kullanıcı adı", "Başarısız deneme", "Kaynak IP"], user_rows, {1, 2})}

<h2>Yetki yükseltme</h2>
<div class="grid2">
{_table(["Hesap", "Başarısız yetki girişimi", "sudo komutu", "Başarılı su"], privilege_rows, {1, 2, 3}, "Bu hafta sudo / su kaydı yok.")}
{_table(["Zaman", "Hesap", "ATT&amp;CK", "Hassas komutlar"], sensitive_rows, set(), "Hassas komut alarmı yok.")}
</div>

<h2>Veri kalitesi</h2>
<p>Bu haftanın olaylarını yükleyen {q['pipeline_runs']} pipeline çalıştırması ({q['failed_runs']} başarısız):
{_n(q['lines_read'])} satır okundu, {_n(q['lines_rejected'])} satır karantinaya alındı
(%{q['reject_ratio'] * 100:.2f}).</p>
{_table(["Red sebebi", "Satır"], reason_rows, {1}, "Reddedilen satır yok.")}

<footer>Cybersecurity Data Lake &amp; Threat Analytics Platform · <code>python -m src.reporting.weekly</code>
{'· IP konum verisi: IP Geolocation by DB-IP (CC BY 4.0)' if has_countries else ''}</footer>
</main></body></html>
"""


def summary_text(r: dict) -> str:
    """Telegram mesajı için kısa özet."""
    k = r["kpis"]
    lines = [
        f"Haftalık güvenlik raporu {r['week_start']} – {r['week_end']}",
        f"Başarısız deneme: {_n(k['failed_attempts'])} ({_n(k['attacking_ips'])} IP)",
        f"Alarm: {_n(k['alerts'])} (kritik {k['critical_alerts']}, high {k['high_alerts']})",
        f"Başarısız yetki girişimi: {_n(k['privilege_failures'])}",
    ]
    if r["top_attacking_ips"]:
        top = r["top_attacking_ips"][0]
        where = f" ({top['country']})" if top["country"] else ""
        lines.append(f"En çok saldıran: {top['ip']}{where}, {_n(top['failed_attempts'])} deneme")
    return "\n".join(lines)


def write_report(conn, week_ending: date, out_dir: Path = REPORT_DIR) -> tuple[Path, dict]:
    report = collect(conn, week_ending)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"weekly_{report['week_start']}"
    html_path = out_dir / f"{stem}.html"
    html_path.write_text(render_html(report), encoding="utf-8")
    (out_dir / f"{stem}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return html_path, report


def send_to_telegram(html_path: Path, report: dict) -> bool:
    """TELEGRAM_BOT_TOKEN ve TELEGRAM_CHAT_ID tanımlıysa raporu gönderir; değilse False döndürür."""
    from src.utils.telegram import send_document

    token, chat_id = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (token and chat_id):
        return False
    send_document(token, chat_id, html_path, caption=summary_text(report))
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Haftalık güvenlik raporu üretir.")
    ap.add_argument("--week-ending", type=date.fromisoformat, default=None,
                    help="Haftanın bittiği pazartesi (hariç), YYYY-MM-DD. Varsayılan: son pazartesi")
    ap.add_argument("--out-dir", type=Path, default=REPORT_DIR)
    ap.add_argument("--telegram", action="store_true", help="Raporu Telegram'a da gönder (.env'deki TELEGRAM_*)")
    args = ap.parse_args()

    week_ending = args.week_ending or last_monday()
    conn = get_connection()
    try:
        apply_schema(conn)
        path, report = write_report(conn, week_ending, args.out_dir)
    finally:
        conn.close()
    print(summary_text(report))
    print(f"Rapor: {path}")
    if args.telegram:
        print("Telegram'a gönderildi." if send_to_telegram(path, report)
              else "Telegram ayarı yok (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID).")


if __name__ == "__main__":
    main()
