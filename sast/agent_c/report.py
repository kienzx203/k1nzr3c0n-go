#!/usr/bin/env python3
"""
Agent C — Report generator (Tuần 4).

Renders an Orchestrator result into a self-contained HTML report: ranked
verified findings with verdict badges, the inter-procedural source→sink path,
the code snippet, and the coverage ledger (potential misses).

    python3 agent_c/report.py <dir> [--lang L] [--out report.html]
"""
import argparse
import html
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import orchestrator  # noqa: E402

BADGE = {"confirmed": "#f85149", "likely": "#e3933c",
         "needs-review": "#d2b24b", "false_positive": "#6e7681"}


def _esc(s):
    return html.escape(str(s or ""))


def render(result):
    s = result["summary"]
    rows = []
    for i, f in enumerate(result["findings"], 1):
        color = BADGE.get(f["verdict"], "#6e7681")
        path = " &rarr; ".join(_esc(p) for p in f["bundle"]["path"])
        code = _esc(f["bundle"].get("code", ""))
        rows.append(f"""
        <div class="finding">
          <div class="fh">
            <span class="badge" style="background:{color}">{_esc(f['verdict'])}</span>
            <span class="cat">{_esc(f['category'])}</span>
            <span class="sink mono">{_esc(f['sink'])}()</span>
            <span class="score">score {f['verify_score']}</span>
            {'<span class="flow">inter-procedural</span>' if f.get('interproc') else ''}
          </div>
          <div class="row"><b>sink</b> {_esc(f['sink_note'])} &middot; {_esc(f['func'])} &middot; line {_esc(f['line'])}</div>
          <div class="row"><b>source</b> {_esc(f['source'])}</div>
          <div class="row"><b>path</b> <span class="mono">{path}</span></div>
          <div class="row"><b>why</b> {_esc(f['verify_reason'])}</div>
          <pre class="code">{code}</pre>
        </div>""")

    breaks = result["ledger"]["taint_breaks"]
    ledger_rows = "".join(
        f"<li class='mono'>{_esc(u['caller'])} &rarr; {_esc(u['call'])} "
        f"(line {_esc(u['line'])}, {_esc(u['reason'])})</li>" for u in breaks) \
        or "<li>none — every call resolved or handled by the spec</li>"

    bv = " ".join(f"{k}:{v}" for k, v in s["by_verdict"].items()) or "—"
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAST_k1nz report — {_esc(s['language'])}</title>
<style>
:root{{color-scheme:dark}} *{{box-sizing:border-box}}
body{{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}}
header{{padding:16px 22px;background:#161b22;border-bottom:1px solid #2a3139}}
h1{{margin:0;font-size:20px}} h1 span{{color:#58a6ff}}
.sub{{color:#8b949e;font-size:13px;margin-top:4px}}
.chips{{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap}}
.chip{{background:#1c2330;border:1px solid #2a3139;border-radius:20px;padding:3px 11px;font-size:12px;color:#8b949e}}
.chip b{{color:#e6edf3}}
main{{padding:18px 22px;max-width:1000px;margin:0 auto}}
.finding{{background:#161b22;border:1px solid #2a3139;border-left:4px solid #30363d;border-radius:8px;padding:12px 14px;margin-bottom:12px}}
.fh{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}}
.badge{{color:#0d1117;font-weight:700;font-size:11px;padding:2px 9px;border-radius:5px;text-transform:uppercase}}
.cat{{font-weight:700}} .sink{{color:#ffb4ae}} .score{{color:#8b949e;font-size:12px}}
.flow{{background:#1f6feb33;color:#a5c8ff;border-radius:4px;padding:0 7px;font-size:11px}}
.row{{color:#c9d1d9;font-size:13px;margin:2px 0}} .row b{{color:#8b949e;font-weight:600;margin-right:4px}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace}}
.code{{background:#0d1117;border:1px solid #2a3139;border-radius:6px;padding:8px;overflow:auto;font-family:ui-monospace,monospace;font-size:12px;color:#c9d1d9;margin-top:8px}}
.ledger{{background:#161b22;border:1px solid #2a3139;border-radius:8px;padding:12px 14px;margin-top:18px}}
.ledger h2{{font-size:15px;margin:0 0 6px}} .ledger ul{{margin:6px 0;padding-left:18px;color:#8b949e;font-size:12px}}
.muted{{color:#8b949e;font-size:12px}}
</style></head><body>
<header>
  <h1>SAST<span>_k1nz</span> — report</h1>
  <div class="sub">{_esc(result['target'])} &middot; {_esc(s['language'])} &middot; engine {_esc(s['engine'])}</div>
  <div class="chips">
    <span class="chip">funcs <b>{s['functions']}</b></span>
    <span class="chip">edges <b>{s['edges']}</b></span>
    <span class="chip">candidates <b>{s['candidates']}</b></span>
    <span class="chip">verdicts <b>{_esc(bv)}</b></span>
    <span class="chip">taint-breaks <b>{s['taint_breaks']}</b></span>
  </div>
</header>
<main>
  <h2 style="font-size:16px">Findings ({len(result['findings'])})</h2>
  {''.join(rows) if rows else '<p class="muted">No tainted source→sink flow found.</p>'}
  <div class="ledger">
    <h2>Coverage ledger — potential misses (taint-breaks)</h2>
    <p class="muted">{_esc(result['ledger']['note'])}</p>
    <ul>{ledger_rows}</ul>
  </div>
  <p class="muted" style="margin-top:16px">Generated by SAST_k1nz Agent C (orchestrator + verify + ledger).
  Verdicts from the heuristic verifier; each finding carries an LLM-ready prompt bundle for an optional LLM pass.</p>
</main></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--lang")
    ap.add_argument("--db", default=os.path.join(os.path.dirname(HERE), "taint_spec.db"))
    ap.add_argument("--out", default="report.html")
    args = ap.parse_args()
    result = orchestrator.orchestrate(args.target, args.lang, args.db)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render(result))
    print(f"wrote {args.out}  ({len(result['findings'])} findings, "
          f"{result['summary']['taint_breaks']} taint-breaks)")


if __name__ == "__main__":
    main()
