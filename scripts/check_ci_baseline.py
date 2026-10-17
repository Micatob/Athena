#!/usr/bin/env python3
"""Baseline gate for CI: fail only on NEW lint/security findings.

The repo carries ~1000 pre-existing flake8 warnings and bandit findings
(codebase style: try/except/pass guards, long HTML strings).  CI used to
run with zero tolerance, so lint+security were red from day one and the
test job (needs: [lint, security]) never ran.

This tool snapshots the known findings into a baseline file and fails
only when the current run contains entries the baseline does not cover.
Line numbers and digits in messages are masked so moving code never
looks like a new finding; counts are compared so e.g. a third copy of
the same warning in one file IS new.

Usage:
  python scripts/check_ci_baseline.py write flake8 current.out baseline.txt
  python scripts/check_ci_baseline.py check flake8 current.out baseline.txt
  python scripts/check_ci_baseline.py write bandit bandit.json baseline.txt
  python scripts/check_ci_baseline.py check bandit bandit.json baseline.txt

Exit codes: 0 ok (or warnings only), 1 new blocking findings,
2 usage/input error.

Bandit severity floor: by default only NEW HIGH/UNDEFINED findings fail
(--floor any for zero tolerance, --floor HIGH default).  New mediums and
lows print as warnings - the codebase legitimately adds B104/B110-style
findings (bind-all servers, try/except/pass guards).
"""
import collections
import json
import re
import sys

_DIGITS = re.compile(r"\d+")


def _norm(text: str) -> str:
    """Mask digits so message length changes never count as new."""
    return _DIGITS.sub("#", str(text).strip())


def _norm_path(path: str) -> str:
    p = str(path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def parse_flake8(path: str):
    entries = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("|", 2)
            if len(parts) != 3:
                continue
            fpath, code, text = parts
            entries.append((f"{_norm_path(fpath)}|{code}|{_norm(text)}", None))
    return entries


def parse_bandit(path: str):
    with open(path, encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    entries = []
    for res in data.get("results") or []:
        sev = str(res.get("issue_severity") or "UNDEFINED").upper()
        key = (f"{sev}|{_norm_path(res.get('filename'))}|"
               f"{res.get('test_id')}|{_norm(res.get('issue_text'))}")
        entries.append((key, sev))
    return entries


def main(argv):
    if len(argv) < 4 or argv[1] not in ("write", "check"):
        print(__doc__)
        return 2
    mode, kind, current_path, baseline_path = argv[1], argv[2], argv[3], argv[4]
    floor = "HIGH"
    if "--floor" in argv:
        try:
            floor = argv[argv.index("--floor") + 1].upper()
        except IndexError:
            return 2
    parse = parse_flake8 if kind == "flake8" else parse_bandit
    try:
        current = parse(current_path)
    except Exception as exc:  # noqa: BLE001 - report, never traceback
        print(f"error: cannot read {current_path}: {exc}")
        return 2
    baseline = []
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            baseline = [(line.rstrip("\n"), None) for line in fh if line.strip()]
    except FileNotFoundError:
        if mode == "write":
            pass
        else:
            print(f"error: baseline {baseline_path} not found "
                  f"(run 'write' first)")
            return 2
    cur_keys = [k for k, _ in current]
    base_keys = [k for k, _ in baseline]
    sev_of = {k: s for k, s in current if s}
    if mode == "write":
        # Counts matter: a warning that appears 3x today must stay 3x in
        # the baseline or the gate would flag its own snapshot.
        with open(baseline_path, "w", encoding="utf-8", newline="\n") as fh:
            for key in sorted(cur_keys):
                fh.write(key + "\n")
        print(f"wrote {len(cur_keys)} entries "
              f"({len(set(cur_keys))} unique) to {baseline_path}")
        return 0
    new = collections.Counter(cur_keys) - collections.Counter(base_keys)
    fixed = collections.Counter(base_keys) - collections.Counter(cur_keys)
    if not new:
        print(f"ok: no new {kind} findings "
              f"({len(cur_keys)} current, {len(base_keys)} baseline, "
              f"{sum(fixed.values())} fixed)")
        return 0
    blocking = []
    warnings = []
    for key, count in sorted(new.items()):
        sev = sev_of.get(key, "")
        if kind == "bandit":
            is_block = sev in ("HIGH", "UNDEFINED") if floor == "HIGH" else True
        else:
            is_block = True
        (blocking if is_block else warnings).append((key, count))
    for key, count in warnings:
        print(f"warning: new {kind} (non-blocking): {key} x{count}")
    if blocking:
        print(f"FAIL: {sum(c for _, c in blocking)} new blocking "
              f"{kind} finding(s):")
        for key, count in blocking:
            print(f"  NEW x{count}: {key}")
        return 1
    print(f"ok: {len(blocking)} blocking, {len(warnings)} warning-only "
          f"new {kind} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
