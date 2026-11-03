"""Versioned, deterministic reports for supported SSH authentication records."""

import json
from html import escape
from pathlib import Path


LIMITATIONS = (
    "Only supported OpenSSH Accepted/Failed password/publickey messages are counted. "
    "Skipped lines can include normal activity as well as unsupported or malformed records.",
    "Burst detection uses traditional English syslog dates, one explicitly supplied year, "
    "and one unspecified time basis. ISO dates, timezone offsets, and year rollover are unsupported.",
    "Duplicate records count again. Invalid UTF-8 bytes are replaced while reading.",
    "Frequent failures do not prove an attack. These records do not identify a person, "
    "establish log authenticity, or prove a completed SSH session.",
)


def percentage(part: int, whole: int) -> float | None:
    """Use null for an undefined ratio, rather than implying a measured zero."""
    return round(100 * part / whole, 2) if whole else None


def build_report(counts, skipped, *, source_name, burst_settings=None,
                 alerts=(), excluded_failed_records=None):
    """Build schema 1.0 without raw log lines, full paths, or a wall-clock date."""
    successful = sum(row["success"] for row in counts.values())
    failed = sum(row["failed"] for row in counts.values())
    events = successful + failed
    enabled = burst_settings is not None
    addresses = [
        {
            "ip": address, "successful": row["success"], "failed": row["failed"],
            "total": row["success"] + row["failed"],
            "failed_percent": percentage(row["failed"], row["success"] + row["failed"]),
        }
        for address, row in sorted(counts.items(), key=lambda item: (-item[1]["failed"], item[0]))
    ]
    return {
        "schema_version": "1.0",
        "source": {"name": source_name},
        "summary": {
            "successful": successful, "failed": failed, "events": events,
            "unique_ips": len(counts), "skipped_lines": skipped,
            "total_lines": events + skipped,
            "parsed_line_percent": percentage(events, events + skipped),
            "failed_event_percent": percentage(failed, events),
        },
        "addresses": addresses,
        "burst_check": {
            "enabled": enabled,
            "year": burst_settings["year"] if enabled else None,
            "threshold": burst_settings["threshold"] if enabled else None,
            "window_seconds": burst_settings["window_seconds"] if enabled else None,
            "time_basis": "unspecified; one calendar year" if enabled else None,
            "excluded_failed_records": excluded_failed_records if enabled else None,
            "eligible_failed_records": failed - excluded_failed_records if enabled else None,
            "alerts": [
                {
                    "rule": "ssh.failed_burst", "ip": alert.address,
                    "failures": alert.failures,
                    "start": alert.start.isoformat(), "end": alert.end.isoformat(),
                    "observed_span_seconds": int((alert.end - alert.start).total_seconds()),
                }
                for alert in sorted(alerts, key=lambda item: (-item.failures, item.address))
            ] if enabled else [],
        },
        "limitations": list(LIMITATIONS),
    }


def save_json(path: Path, report) -> None:
    """Write stable UTF-8 JSON; reject non-standard NaN and Infinity values."""
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                    encoding="utf-8")


STYLE = """
:root { color-scheme: dark; --bg:#0b1120; --panel:#121d30; --line:#2a3a53;
  --text:#edf3ff; --muted:#b0c1d9; --blue:#8bbdff; --green:#76dfc0; --amber:#ffd58a; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
main { max-width:1140px; margin:auto; padding:48px 28px; }
.eyebrow { color:var(--green); font-size:12px; font-weight:750; letter-spacing:.16em; }
h1 { font-size:clamp(32px,5vw,52px); letter-spacing:-.04em; line-height:1.15; margin:16px 0; }
h2 { font-size:22px; margin:0 0 8px; letter-spacing:-.02em; }
h3 { font-size:17px; margin:0 0 8px; }
p { margin:8px 0; } .muted, small { color:var(--muted); }
.source { overflow-wrap:anywhere; color:var(--blue); }
.badge { display:inline-block; border:1px solid var(--line); border-radius:20px;
  padding:4px 12px; font-size:12px; color:var(--muted); margin:4px 6px 4px 0; }
.metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:28px 0; }
.metric,section { background:var(--panel); border:1px solid var(--line); border-radius:16px; }
.metric { padding:20px; } .label { font-size:13px; color:var(--muted); }
.value { display:block; font-size:34px; font-weight:730; letter-spacing:-.04em; }
.good { color:var(--green); } .warn { color:var(--amber); }
section { margin:18px 0; padding:26px; }
.notice { border-left:3px solid var(--amber); padding:10px 16px; margin-top:18px; background:#1b2537; }
.alert { border:1px solid #6f5734; border-radius:12px; padding:18px; margin-top:16px; }
.alert code { color:var(--amber); }
code { font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; overflow-wrap:anywhere; }
.table-wrap { overflow-x:auto; margin-top:18px; }
table { width:100%; border-collapse:collapse; text-align:left; font-size:14px; }
caption { text-align:left; color:var(--muted); margin-bottom:10px; }
th,td { padding:14px 12px; border-bottom:1px solid var(--line); vertical-align:middle; }
th { color:var(--muted); font-weight:600; font-size:12px; }
.number { text-align:right; font-variant-numeric:tabular-nums; }
meter { width:90px; height:10px; margin-right:8px; accent-color:var(--amber); }
ul { padding-left:22px; } li { margin:9px 0; color:var(--muted); }
footer { font-size:12px; color:var(--muted); margin-top:28px; }
@media(max-width:680px) { main { padding:28px 16px; } .metrics { grid-template-columns:repeat(2,minmax(0,1fr)); }
  section { padding:20px; } .metric { padding:16px; } }
@media print { :root { color-scheme:light; --bg:#fff; --panel:#fff; --line:#bbb;
  --text:#111; --muted:#444; --blue:#164d82; --green:#12634a; --amber:#754900; }
  main { padding:0; } .notice { background:#fff; } .alert, .metric { break-inside:avoid; } }
"""


def render_html(report) -> str:
    """Render escaped report data without JavaScript, remote assets, or telemetry."""
    summary, check = report["summary"], report["burst_check"]
    source = escape(str(report["source"]["name"]))
    failure_rate = summary["failed_event_percent"]
    failure_label = f"{failure_rate:g}% of supported events" if failure_rate is not None else "No supported events"
    coverage = summary["parsed_line_percent"]
    coverage_label = f"{coverage:g}% of input lines parsed" if coverage is not None else "Input is empty"
    metrics = "".join(
        f'<div class="metric"><span class="label">{label}</span>'
        f'<strong class="value {color}">{value:,}</strong><small>{detail}</small></div>'
        for label, value, color, detail in (
            ("Successful logins", summary["successful"], "good", "Supported Accepted messages"),
            ("Failed logins", summary["failed"], "warn", failure_label),
            ("Source IPs", summary["unique_ips"], "", "Normalized IPv4 / IPv6"),
            ("Skipped lines", summary["skipped_lines"], "", coverage_label),
        )
    )
    if not check["enabled"]:
        check_body = '<p class="muted">Burst detection was not run. This report contains aggregate counts only.</p>'
    else:
        check_body = (
            f'<p class="muted">Rule <code>ssh.failed_burst</code> · '
            f'At least {check["threshold"]} failures within {check["window_seconds"]} seconds. '
            'Both time boundaries are included.</p>'
            f'<p>{check["eligible_failed_records"]} of {summary["failed"]} failed records were eligible; '
            f'{check["excluded_failed_records"]} had no supported timestamp.</p>'
            f'<p class="muted">Supplied year: {check["year"]}. Times have no timezone; '
            'all input must use the same time basis and calendar year.</p>'
        )
        if not check["alerts"]:
            check_body += '<p class="notice">No failure bursts found among timestamped records. This does not establish that the input is safe.</p>'
        for alert in check["alerts"]:
            check_body += (
                '<article class="alert"><h3>Repeated authentication failures · review needed</h3>'
                f'<p><code>{escape(str(alert["ip"]))}</code> · <strong>{alert["failures"]} failures</strong>'
                f' over {alert["observed_span_seconds"]} seconds.</p>'
                f'<p class="muted">{escape(str(alert["start"]))} → {escape(str(alert["end"]))}</p>'
                '<p class="muted">This is the largest failure window for this IP; equal maxima keep '
                'the earliest window. Possible explanations include password guessing, a misconfigured '
                'client, or a user retrying credentials. Corroborate with other records.</p></article>'
            )
    rows = "".join(
        f'<tr><td><code>{escape(str(row["ip"]))}</code></td>'
        f'<td class="number">{row["successful"]:,}</td><td class="number">{row["failed"]:,}</td>'
        f'<td class="number">{row["total"]:,}</td><td class="number">'
        f'<meter min="0" max="100" value="{row["failed_percent"]}" '
        f'aria-label="Failed event percentage">{row["failed_percent"]}%</meter>'
        f'{row["failed_percent"]:g}%</td></tr>'
        for row in report["addresses"]
    )
    if not rows:
        rows = '<tr><td colspan="5">No supported authentication events were found.</td></tr>'
    limitations = "".join(f"<li>{escape(str(item))}</li>" for item in report["limitations"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>SSH Log Analyzer · {source}</title><style>{STYLE}</style></head>
<body><main>
<header><div class="eyebrow">SSH LOG ANALYZER / LOCAL REPORT</div>
<h1>Authentication, explained.</h1>
<p class="muted">A review of supported login records from <strong class="source">{source}</strong>.</p>
<span class="badge">Offline · no external assets</span><span class="badge">Report schema 1.0</span>
</header><div class="metrics">{metrics}</div>
<section><h2>Failure burst investigation</h2>{check_body}</section>
<section><h2>Activity by source IP</h2><p class="muted">Most failed attempts first; ties are ordered by IP text.</p>
<div class="table-wrap"><table><caption>Counts describe matching log messages, including duplicates.</caption>
<thead><tr><th scope="col">SOURCE IP</th><th scope="col" class="number">SUCCESS</th>
<th scope="col" class="number">FAILED</th><th scope="col" class="number">TOTAL</th>
<th scope="col" class="number">FAILED %</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section><h2>Coverage &amp; interpretation</h2>
<p>{summary["events"]} supported events from {summary["total_lines"]} input lines.
{summary["skipped_lines"]} lines were skipped.</p><ul>{limitations}</ul></section>
<footer>Generated locally by SSH Log Analyzer. Reports contain operational data; share them with care.
No raw log lines or full source path are embedded. No network requests are made by this report.</footer>
</main></body></html>
"""


def save_html(path: Path, report) -> None:
    path.write_text(render_html(report), encoding="utf-8")
