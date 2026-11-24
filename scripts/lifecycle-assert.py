#!/usr/bin/env python3
"""Checks the captured lifecycle reports against the expected conclusions.

Run after scripts/lifecycle-reports.sh. Exits non-zero on any mismatch.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(os.path.dirname(HERE), "reports")


def load(name):
    with open(os.path.join(REPORTS, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def check(spec, problems):
    report = load(spec["report"])
    entries = [e for e in report["Secrets"] if e["RuleID"] == spec["rule"]]

    def expect(cond, msg):
        if not cond:
            problems.append(f"{spec['report']}: {msg}")

    expect(len(entries) == spec["entries"],
           f"expected {spec['entries']} entries, got {len(entries)}")
    expect(sorted(e["Status"] for e in entries) == sorted(spec["statuses"]),
           f"statuses are {[e['Status'] for e in entries]}, expected {spec['statuses']}")

    if "historyComplete" in spec:
        expect(report["History"]["Complete"] == spec["historyComplete"],
               f"History.Complete is {report['History']['Complete']}")
    if "shallow" in spec:
        expect(report["Repository"]["Shallow"] == spec["shallow"],
               f"Repository.Shallow is {report['Repository']['Shallow']}")
    if "files" in spec:
        files = sorted({l["File"] for e in entries for l in e["Locations"]})
        expect(files == spec["files"], f"files are {files}")
    if "locations" in spec:
        count = sum(len(e["Locations"]) for e in entries)
        expect(count == spec["locations"], f"locations are {count}")
    if "mergedRefs" in spec:
        refs = sorted({n for e in entries for n in e.get("MergedRefs", [])})
        expect(refs == sorted(spec["mergedRefs"]), f"merged refs are {refs}")
    if "historicalRefs" in spec:
        refs = sorted({n for e in entries for n in e.get("HistoricalRefs", [])})
        expect(refs == sorted(spec["historicalRefs"]), f"historical refs are {refs}")
    if spec.get("firstSeenDistinct"):
        commits = {e["FirstSeen"]["Commit"] for e in entries}
        expect(len(commits) == spec["entries"], f"first-seen commits are {commits}")

    print(f"checked {spec['report']}")


def check_determinism(problems):
    pairs = [
        ("determinism-run1.lifecycle.json", "determinism-run2.lifecycle.json"),
        ("determinism-run1.findings.json", "determinism-run2.findings.json"),
    ]
    for a, b in pairs:
        with open(os.path.join(REPORTS, a), "rb") as fa, open(os.path.join(REPORTS, b), "rb") as fb:
            if fa.read() != fb.read():
                problems.append(f"{a} and {b} are not byte-identical")
    print("checked determinism")


def check_no_plaintext(problems):
    # The lifecycle report must never carry a plaintext secret: it names
    # secrets only by salted digest. (The primary findings report keeps its
    # existing behavior and is redacted with --redact, not by this feature.)
    for name in os.listdir(REPORTS):
        if not name.endswith(".lifecycle.json"):
            continue
        with open(os.path.join(REPORTS, name), "r", encoding="utf-8") as fh:
            text = fh.read()
        if "LCK_" in text:
            problems.append(f"{name} contains a plaintext fixture secret")
        if "glsk_" in text and any(len(part) < 20 for part in text.split("glsk_")[1:]):
            problems.append(f"{name} has a malformed SecretID")
    print("checked plaintext")


def main():
    spec = load("assertions.json")
    problems = []
    for item in spec["checks"]:
        check(item, problems)
    check_determinism(problems)
    check_no_plaintext(problems)
    if problems:
        for p in problems:
            print("FAIL:", p, file=sys.stderr)
        return 1
    print("all lifecycle report assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
