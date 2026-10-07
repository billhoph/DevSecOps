#!/usr/bin/env python3
"""Jev-powered triage layer for DevSecOps scan findings.

Reduces operator noise by asking TypeSafe AI's Jev (System-One) to make typed,
confidence-scored decisions over the scanners' findings:
  • ops_priority (score P4..P1)   • likely_noise (noul 0..1)   • route (choice)

Design guardrails (Jev is advisory only):
  • Jev never *finds* vulnerabilities — the scanners do; Jev only re-prioritizes.
  • Jev never suppresses a finding (full SARIF still goes to the Security tab) and
    never overrides the deterministic Security Gate.
  • Only SANITIZED, structured metadata is sent (scanner/id/severity/cvss/category/
    component) — never free-form finding text — to resist Jev's known prompt-injection
    weakness. Critical/High are never auto-collapsed as noise.

Usage: JEV_API_KEY=... jev_triage.py <sarif-dir> [--summary out.md] [--json out.json]
Exits 0 even on API errors (triage is best-effort and must not break the pipeline).
"""
import glob
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

API = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
MAX_SIGNATURES = 150          # cap unique Jev calls to bound CI time/cost
NOISE_CONF = 0.85             # min noul probability to treat Low/Med as collapsible noise
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
PRIO_LABELS = ["P4 — informational", "P3 — backlog", "P2 — schedule", "P1 — fix now"]
SAFE = re.compile(r"[^A-Za-z0-9 ._/@:+-]")

QUESTIONS = {
    "likely_noise": {
        "type": "noul",
        "instructions": ("Given ONLY these structured fields, is this finding likely "
                         "LOW-PRIORITY NOISE in a production security backlog (informational, "
                         "non-exploitable config, or a dev/test-only dependency)? Return the "
                         "probability that it is noise."),
    },
    "ops_priority": {
        "type": "score",
        "instructions": "Operational remediation priority for this finding in production.",
        "criteria": [
            "P4 - informational, safe to ignore",
            "P3 - backlog, low urgency",
            "P2 - schedule a fix soon",
            "P1 - fix now, likely exploitable or high impact",
        ],
    },
    "route": {
        "type": "choice",
        "instructions": "Best handling action for this finding.",
        "criteria": {
            "fix": "Remediate now (patch, upgrade, or code fix)",
            "review": "Needs human security review",
            "accept": "Acceptable or low risk; document and move on",
            "duplicate": "Likely a duplicate or shares a root cause with many others",
        },
    },
}


def clean(s, n=80):
    return SAFE.sub("", str(s or ""))[:n]


# ---- SARIF parsing (mirrors sarif_summary bucketing) ----
def rules_index(run):
    idx = {}
    tool = run.get("tool", {})
    for comp in [tool.get("driver", {})] + tool.get("extensions", []):
        for rule in comp.get("rules", []) or []:
            if rule.get("id"):
                idx[rule["id"]] = rule
    return idx


def bucket(result, ridx, is_secrets):
    if is_secrets:
        return "High"
    rid = result.get("ruleId")
    ss = ridx.get(rid, {}).get("properties", {}).get("security-severity")
    if ss is None:
        ss = result.get("properties", {}).get("security-severity")
    if ss is not None:
        try:
            v = float(ss)
            return "Critical" if v >= 9 else "High" if v >= 7 else "Medium" if v >= 4 else "Low"
        except (TypeError, ValueError):
            pass
    lvl = result.get("level") or ridx.get(rid, {}).get("defaultConfiguration", {}).get("level") or "warning"
    return {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}.get(lvl, "Medium")


def category_for(driver, fname):
    d, f = (driver or "").lower(), fname.lower()
    if "gitleaks" in d:
        return "secret"
    if "semgrep" in d:
        return "code"
    if "grype" in d or "image" in f:
        return "image"
    if "trivy" in d:
        return "image" if "image" in f else "dependency"
    return "other"


def component_of(result):
    try:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        return uri.rsplit("/", 1)[-1]
    except (KeyError, IndexError, TypeError):
        return ""


def load_findings(directory):
    findings = []
    for path in sorted(glob.glob(os.path.join(directory, "**", "*.sarif"), recursive=True)):
        try:
            sarif = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
            is_secrets = driver.lower() == "gitleaks"
            ridx = rules_index(run)
            cat = category_for(driver, os.path.basename(path))
            for r in run.get("results", []):
                rid = r.get("ruleId", "")
                sev = bucket(r, ridx, is_secrets)
                ss = ridx.get(rid, {}).get("properties", {}).get("security-severity")
                findings.append({
                    "scanner": clean(driver, 20),
                    "id": clean(rid, 60),
                    "severity": sev,
                    "cvss": clean(ss, 6) if ss else "",
                    "category": cat,
                    "component": clean(component_of(r), 60),
                })
    return findings


# ---- Jev ----
def ask_jev(state, key):
    body = json.dumps({"model": MODEL, "state": state, "questions": QUESTIONS})
    try:
        p = subprocess.run(
            ["curl", "-sS", "--max-time", "30", "-X", "POST", API,
             "-H", "Authorization: Bearer " + key,
             "-H", "Content-Type: application/json", "-d", body],
            capture_output=True, timeout=40)
        if p.returncode != 0:
            return None
        return json.loads(p.stdout.decode("utf-8", "replace")).get("answers", {})
    except Exception:
        return None


def decide(ans):
    """Map Jev answers → (priority_index 0..3, priority_label, route, route_conf, noise_prob)."""
    noise = float(ans.get("likely_noise", {}).get("noul", 0.0)) if ans else 0.0
    sc = ans.get("ops_priority", {}) if ans else {}
    pidx = int(round(sc.get("score", 1))) if "score" in sc else 1
    pidx = max(0, min(3, pidx))
    ro = ans.get("route", {}) if ans else {}
    return pidx, PRIO_LABELS[pidx], ro.get("choice", "review"), round(float(ro.get("confidence", 0)), 2), round(noise, 2)


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    summary_out = None
    json_out = None
    for i, a in enumerate(sys.argv):
        if a == "--summary" and i + 1 < len(sys.argv):
            summary_out = sys.argv[i + 1]
        if a == "--json" and i + 1 < len(sys.argv):
            json_out = sys.argv[i + 1]
    key = os.environ.get("JEV_API_KEY", "").strip()

    findings = load_findings(directory)
    total = len(findings)
    out = []

    if not key:
        out.append("## 🧠 Jev triage\n\n_JEV_API_KEY not configured — skipping triage._\n")
        emit(out, summary_out)
        return
    if total == 0:
        out.append("## 🧠 Jev triage\n\n_No findings to triage._\n")
        emit(out, summary_out)
        return

    # Dedupe by signature so we make far fewer Jev calls
    sigs = {}
    for f in findings:
        sig = (f["scanner"], f["id"], f["severity"])
        sigs.setdefault(sig, f)
    unique = list(sigs.items())
    # Prioritise reviewing the most severe signatures if we exceed the cap
    unique.sort(key=lambda kv: SEV_ORDER.index(kv[1]["severity"]))
    review = unique[:MAX_SIGNATURES]

    key_of = lambda f: (f["scanner"], f["id"], f["severity"])
    results = {}

    def work(item):
        sig, rec = item
        ans = ask_jev(rec, key)
        results[sig] = decide(ans)

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(work, review))

    # Default (uncalled / failed) signatures → severity-based fallback
    def fallback(sev):
        pidx = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}.get(sev, 1)
        return pidx, PRIO_LABELS[pidx], "review", 0.0, 0.0

    buckets = {0: 0, 1: 0, 2: 0, 3: 0}
    collapsed = 0
    enriched = []
    for f in findings:
        sig = key_of(f)
        pidx, plabel, route, rconf, noise = results.get(sig) or fallback(f["severity"])
        is_noise = (pidx == 0) or (noise >= NOISE_CONF and f["severity"] in ("Low", "Medium"))
        # never collapse Critical/High
        if f["severity"] in ("Critical", "High"):
            is_noise = False
        buckets[pidx] += 1
        if is_noise:
            collapsed += 1
        enriched.append({**f, "priority": plabel, "priority_index": pidx,
                         "route": route, "route_confidence": rconf,
                         "noise_probability": noise, "collapsed": is_noise})

    actionable = buckets[3] + buckets[2]
    out.append("## 🧠 Jev triage — noise reduction\n")
    out.append(f"Reviewed **{len(review)}** unique signatures (of {len(unique)}) across "
               f"**{total}** findings via Jev System-One (`jev-latest`).\n")
    out.append("| Priority | Count |")
    out.append("|---|--:|")
    out.append(f"| 🔴 P1 — fix now | {buckets[3]} |")
    out.append(f"| 🟠 P2 — schedule | {buckets[2]} |")
    out.append(f"| 🟡 P3 — backlog | {buckets[1]} |")
    out.append(f"| ⚪ P4 — informational | {buckets[0]} |")
    out.append("")
    pct = round(collapsed * 100.0 / total) if total else 0
    out.append(f"**🔇 Noise reduced:** {collapsed} of {total} findings ({pct}%) deprioritized as "
               f"low-value — operators focus on **{actionable}** actionable (P1+P2) items.\n")

    top = sorted([e for e in enriched if e["priority_index"] >= 2],
                 key=lambda e: (-e["priority_index"], SEV_ORDER.index(e["severity"])))
    # dedupe the top list by signature for readability
    seen, rows = set(), []
    for e in top:
        s = key_of(e)
        if s in seen:
            continue
        seen.add(s)
        rows.append(e)
    if rows:
        out.append("### Top items to action")
        out.append("| Priority | Scanner | ID | Severity | Component | Jev route (conf) |")
        out.append("|---|---|---|---|---|---|")
        for e in rows[:20]:
            out.append(f"| {e['priority']} | {e['scanner']} | {e['id'][:38]} | {e['severity']} | "
                       f"{e['component'][:34] or '—'} | {e['route']} ({e['route_confidence']}) |")
        out.append("")
    out.append("> Advisory only: Jev re-prioritizes and collapses noise; it never suppresses "
               "findings (full results remain in the **Security** tab) and never overrides the "
               "Security Gate. Only sanitized structured fields are sent to Jev (no finding text) "
               "to resist prompt injection.")

    emit(out, summary_out)
    if json_out:
        with open(json_out, "w") as f:
            json.dump({"total": total, "reviewed": len(review), "buckets": buckets,
                       "collapsed": collapsed, "findings": enriched}, f, indent=1)


def emit(lines, summary_out):
    text = "\n".join(lines)
    print(text)
    if summary_out:
        with open(summary_out, "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
