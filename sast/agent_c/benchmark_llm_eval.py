#!/usr/bin/env python3
"""
Measure whether LLM-verify (Claude subscription) actually cuts false positives,
on a balanced sample of OWASP Benchmark findings (Tuần 3 depth).

    python3 agent_c/benchmark_llm_eval.py <csv> <findings.json> <testdir> [n_per_group]

Picks N findings on REAL-vuln tests (should be kept) + N on NON-vuln tests
(should be dropped), runs the LLM verifier, and reports:
  TP-keep rate  = of real-vuln findings, how many the LLM kept (confirmed/likely)
  FP-drop rate  = of non-vuln findings, how many the LLM marked false_positive
"""
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import orchestrator          # snippet helpers
import llm_verify            # subscription LLM

FLOW = {"sqli", "cmdi", "xss", "pathtraver", "ldapi", "xpathi"}
TOOLMAP = {"SQLI": "sqli", "INJECTION": "sqli", "NOSQLI": "sqli", "CMDI": "cmdi",
           "XSS": "xss", "PATH": "pathtraver", "LDAPI": "ldapi", "XPATHI": "xpathi"}
TEST_RE = re.compile(r"(BenchmarkTest\d+)")


def main():
    csv_path, json_path, testdir = sys.argv[1], sys.argv[2], sys.argv[3]
    n = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    model = sys.argv[5] if len(sys.argv) > 5 else "haiku"
    radius = int(sys.argv[6]) if len(sys.argv) > 6 else 5
    truth = {}
    for row in csv.reader(open(csv_path)):
        if row and not row[0].startswith("#"):
            truth[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")
    findings = json.load(open(json_path))

    realg, fakeg = [], []
    for f in findings:
        m = TEST_RE.search(f.get("pos", ""))
        mc = TOOLMAP.get(f.get("category", ""))
        if not m or not mc:
            continue
        t = m.group(1)
        if t not in truth:
            continue
        cat, real = truth[t]
        if cat not in FLOW or mc != cat:
            continue
        (realg if real else fakeg).append(f)

    sample = realg[:n] + fakeg[:n]
    items = []
    for i, f in enumerate(sample):
        items.append({"index": i, "category": f["category"], "source": f.get("source"),
                      "sink": f.get("sink"), "sink_note": f.get("sink_note"),
                      "path": [f.get("func")],
                      "code": orchestrator.snippet_for(f, radius=radius)})
    print(f"sampling {len(realg[:n])} real-vuln + {len(fakeg[:n])} non-vuln findings; "
          f"calling LLM ("+model+")…", flush=True)
    verdicts = llm_verify.verify_findings(items, model=model, batch=8, timeout=300)

    keep_real = drop_fake = decided_real = decided_fake = 0
    for i, f in enumerate(sample):
        v = verdicts.get(i)
        if not v:
            continue
        is_real = i < len(realg[:n])
        if is_real:
            decided_real += 1
            if v["verdict"] in ("confirmed", "likely"):
                keep_real += 1
        else:
            decided_fake += 1
            if v["verdict"] == "false_positive":
                drop_fake += 1
    print(f"\nLLM verdicts returned: {len(verdicts)}/{len(sample)}")
    if decided_real:
        print(f"TP-keep rate : {keep_real}/{decided_real} = {keep_real/decided_real:.1%}  "
              f"(real vulns the LLM kept)")
    if decided_fake:
        print(f"FP-drop rate : {drop_fake}/{decided_fake} = {drop_fake/decided_fake:.1%}  "
              f"(non-vuln findings the LLM marked false_positive)")
    # estimated precision after LLM filter on this balanced sample
    kept_real = keep_real
    kept_fake = decided_fake - drop_fake
    if kept_real + kept_fake:
        print(f"precision on sample after LLM filter: "
              f"{kept_real/(kept_real+kept_fake):.1%}  (raw sample precision 50%)")


if __name__ == "__main__":
    main()
