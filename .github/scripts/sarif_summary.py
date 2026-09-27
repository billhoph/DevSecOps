#!/usr/bin/env python3
"""Render SARIF scan results as GitHub-flavored Markdown tables.

Modes
-----
detail  <label> <emoji> <sarif>   Per-stage section: counts + a findings table.
aggregate <dir>                   Scan a directory of *.sarif (+ CycloneDX SBOMs)
                                  and print one summary table across all stages.

Severity is bucketed from the SARIF `security-severity` (CVSS) property when
present, otherwise from the SARIF `level`. Output goes to stdout so callers can
redirect it into $GITHUB_STEP_SUMMARY.
"""
import json
import os
import sys
import glob

SEV_ORDER = ["Critical", "High", "Medium", "Low"]
SEV_EMOJI = {"Critical": "🟥", "High": "🟧", "Medium": "🟨", "Low": "🟦"}
MAX_ROWS = 25


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def rules_index(run):
    idx = {}
    tool = run.get("tool", {})
    for comp in [tool.get("driver", {})] + tool.get("extensions", []):
        for rule in comp.get("rules", []) or []:
            if rule.get("id"):
                idx[rule["id"]] = rule
    return idx


def sev_of(result, ridx):
    rid = result.get("ruleId")
    rule = ridx.get(rid, {})
    ss = rule.get("properties", {}).get("security-severity")
    if ss is None:
        ss = result.get("properties", {}).get("security-severity")
    if ss is not None:
        try:
            v = float(ss)
            if v >= 9.0:
                return "Critical"
            if v >= 7.0:
                return "High"
            if v >= 4.0:
                return "Medium"
            return "Low"
        except (TypeError, ValueError):
            pass
    lvl = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}.get(lvl, "Medium")


def location(result):
    try:
        pl = result["locations"][0]["physicalLocation"]
        uri = pl.get("artifactLocation", {}).get("uri", "")
        line = pl.get("region", {}).get("startLine")
        return f"{uri}:{line}" if line else uri
    except (KeyError, IndexError, TypeError):
        return ""


def msg(result):
    return (result.get("message", {}) or {}).get("text", "")


def parse(sarif):
    """Return (counts dict, list of finding dicts, driver name)."""
    counts = {s: 0 for s in SEV_ORDER}
    findings = []
    driver = "Unknown"
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {}).get("name", driver)
        ridx = rules_index(run)
        for r in run.get("results", []):
            sev = sev_of(r, ridx)
            counts[sev] += 1
            findings.append({"sev": sev, "id": r.get("ruleId", ""),
                             "loc": location(r), "msg": msg(r)})
    return counts, findings, driver


def counts_line(counts):
    total = sum(counts.values())
    parts = [f"{SEV_EMOJI[s]} {s}: {counts[s]}" for s in SEV_ORDER]
    return total, f"**{total} finding(s)** — " + " · ".join(parts)


def detail(label, emoji, path):
    out = [f"### {emoji} {label}", ""]
    sarif = load(path)
    if sarif is None:
        out += ["_No report produced._", ""]
        print("\n".join(out))
        return
    counts, findings, _ = parse(sarif)
    total, line = counts_line(counts)
    out += [line, ""]
    if total == 0:
        out += ["✅ No findings.", ""]
        print("\n".join(out))
        return
    findings.sort(key=lambda f: SEV_ORDER.index(f["sev"]))
    out += ["| Severity | ID | Location | Detail |", "|---|---|---|---|"]
    for f in findings[:MAX_ROWS]:
        detail_txt = esc(f["msg"])[:100]
        out.append(f"| {SEV_EMOJI[f['sev']]} {f['sev']} | {esc(f['id'])[:40]} | "
                   f"{esc(f['loc'])[:60]} | {detail_txt} |")
    if total > MAX_ROWS:
        out.append(f"\n_…and {total - MAX_ROWS} more (see the Security tab)._")
    out.append("")
    print("\n".join(out))


def sbom_components(path):
    data = load(path)
    if not data:
        return None
    return len(data.get("components", []))


def stage_for(filename, driver):
    fn = filename.lower()
    d = (driver or "").lower()
    if "gitleaks" in d or "gitleaks" in fn:
        return "Secrets", "Gitleaks"
    if "semgrep" in d or "semgrep" in fn:
        return "SAST", "Semgrep"
    if "grype" in d or "grype" in fn or "results.sarif" in fn:
        return "Image", "Grype"
    if "trivy" in d or "trivy" in fn:
        if "image" in fn:
            return "Image", "Trivy"
        return "SCA (deps)", "Trivy"
    return "Other", driver or "Unknown"


def aggregate(directory):
    rows = []
    grand = {s: 0 for s in SEV_ORDER}
    for path in sorted(glob.glob(os.path.join(directory, "**", "*.sarif"), recursive=True)):
        sarif = load(path)
        if sarif is None:
            continue
        counts, _, driver = parse(sarif)
        stage, tool = stage_for(os.path.basename(path), driver)
        rows.append((stage, tool, counts))
        for s in SEV_ORDER:
            grand[s] += counts[s]

    out = ["## 🧪 Security scan summary", ""]
    if not rows:
        out += ["_No SARIF reports were found to summarize._", ""]
        print("\n".join(out))
        return
    out += ["| Stage | Tool | 🟥 Critical | 🟧 High | 🟨 Medium | 🟦 Low | Total |",
            "|---|---|--:|--:|--:|--:|--:|"]
    # de-dupe identical (stage,tool) by keeping the one with more findings
    for stage, tool, c in rows:
        total = sum(c.values())
        out.append(f"| {stage} | {tool} | {c['Critical']} | {c['High']} | "
                   f"{c['Medium']} | {c['Low']} | {total} |")
    gtotal = sum(grand.values())
    out.append(f"| **Total** | | **{grand['Critical']}** | **{grand['High']}** | "
               f"**{grand['Medium']}** | **{grand['Low']}** | **{gtotal}** |")
    out.append("")

    # SBOM component counts (informational)
    sbom_bits = []
    for label, pat in [("source", "sbom.source.cyclonedx.json"),
                       ("image", "sbom.image.cyclonedx.json")]:
        for p in glob.glob(os.path.join(directory, "**", pat), recursive=True):
            n = sbom_components(p)
            if n is not None:
                sbom_bits.append(f"{label}: **{n}** components")
                break
    if sbom_bits:
        out.append("**SBOM (Syft, CycloneDX):** " + " · ".join(sbom_bits))
        out.append("")
    out.append("> Findings are report-only (Juice Shop is intentionally vulnerable). "
               "Full details are in the **Security ▸ Code scanning** tab and attached to the release.")
    print("\n".join(out))


def main():
    if len(sys.argv) >= 5 and sys.argv[1] == "detail":
        detail(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) >= 3 and sys.argv[1] == "aggregate":
        aggregate(sys.argv[2])
    else:
        sys.stderr.write("usage: sarif_summary.py detail <label> <emoji> <sarif> | "
                         "aggregate <dir>\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
