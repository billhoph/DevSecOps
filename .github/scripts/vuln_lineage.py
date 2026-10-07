#!/usr/bin/env python3
"""Vulnerability lineage: trace each finding through the pipeline to runtime.

Correlates the scanners' SARIF + the source/image SBOMs to answer, per
vulnerability, the question operators actually care about:

    Where did it enter, which stages saw it, and does it reach the
    PRODUCTION RUNTIME image?

Stage model:
    Source (commit)      Trivy-fs, Semgrep, Gitleaks, Syft source SBOM
    Build / Image        Trivy image scan, Syft image SBOM
    Image Scan           Grype
    Runtime (Cloud Run)  == whatever is in the final image

A dependency/image CVE seen by an IMAGE-stage scanner (or whose package is in the
image SBOM) reaches runtime. One seen only at source but absent from the image was
stopped at build (e.g. a devDependency pruned by `npm install --omit=dev`).

Usage: vuln_lineage.py <dir> [--summary out.md] [--json out.json]
Best-effort; exits 0 even on partial inputs.
"""
import glob
import json
import os
import re
import sys

SEV_ORDER = ["Critical", "High", "Medium", "Low"]
VULN_ID = re.compile(r"(CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", re.I)
PKG_GRYPE = re.compile(r"package:\s*([A-Za-z0-9._@/+-]+)", re.I)
PKG_TRIVY = re.compile(r"Package:\s*([^\n|]+)", re.I)


def load(path):
    try:
        return json.load(open(path, encoding="utf-8"))
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


def sev_of(result, ridx, is_secrets):
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
    lvl = result.get("level") or "warning"
    return {"error": "High", "warning": "Medium", "note": "Low"}.get(lvl, "Medium")


def vuln_id(result):
    m = VULN_ID.search(result.get("ruleId") or "")
    if m:
        return m.group(1).upper()
    m = VULN_ID.search((result.get("message", {}) or {}).get("text", ""))
    return m.group(1).upper() if m else None


def package_of(result, driver):
    txt = (result.get("message", {}) or {}).get("text", "")
    rx = PKG_GRYPE if "grype" in driver.lower() else PKG_TRIVY
    m = rx.search(txt)
    if m:
        return m.group(1).strip().lower().lstrip("@").split("/")[-1]
    # grype encodes the package as a suffix on the ruleId (GHSA-xxxx-xxxx-xxxx-<pkg>)
    rid = result.get("ruleId") or ""
    parts = rid.split("-")
    if "grype" in driver.lower() and len(parts) > 4 and rid.upper().startswith("GHSA"):
        return parts[-1].lower()
    return ""


def sbom_components(path):
    data = load(path)
    out = {}
    if data:
        for c in data.get("components", []):
            n = (c.get("name") or "").lower()
            if n:
                out.setdefault(n, set()).add(c.get("version") or "")
    return out


SOURCE_SCANNERS = {"trivy": "Trivy-fs"}  # fs scans resolve to source; image handled separately


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    summary_out = json_out = None
    for i, a in enumerate(sys.argv):
        if a == "--summary" and i + 1 < len(sys.argv):
            summary_out = sys.argv[i + 1]
        if a == "--json" and i + 1 < len(sys.argv):
            json_out = sys.argv[i + 1]

    src_sbom = {}
    img_sbom = {}
    for p in glob.glob(os.path.join(directory, "**", "sbom.source.cyclonedx.json"), recursive=True):
        src_sbom = sbom_components(p)
        break
    for p in glob.glob(os.path.join(directory, "**", "sbom.image.cyclonedx.json"), recursive=True):
        img_sbom = sbom_components(p)
        break

    vulns = {}       # id -> record
    code_count = 0   # SAST findings (live in source code)
    secret_count = 0
    source_config = 0  # Trivy-fs non-CVE findings at source (IaC misconfig / secrets)

    for path in sorted(glob.glob(os.path.join(directory, "**", "*.sarif"), recursive=True)):
        sarif = load(path)
        if not sarif:
            continue
        fname = os.path.basename(path).lower()
        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
            dlow = driver.lower()
            is_secrets = dlow == "gitleaks"
            ridx = rules_index(run)
            # classify stage of this scanner
            if is_secrets:
                secret_count += len(run.get("results", []))
                continue
            if "semgrep" in dlow:
                code_count += len(run.get("results", []))
                continue
            is_image = ("grype" in dlow) or ("image" in fname)
            stage = "image" if is_image else "source"
            scanner_label = ("Grype" if "grype" in dlow else
                             "Trivy-image" if is_image else "Trivy-fs")
            for r in run.get("results", []):
                vid = vuln_id(r)
                if not vid:
                    if stage == "source":
                        source_config += 1  # Trivy-fs IaC misconfig / secret (not a CVE)
                    continue
                rec = vulns.setdefault(vid, {
                    "id": vid, "severity": "Low", "package": "",
                    "source_scanners": set(), "image_scanners": set()})
                sev = sev_of(r, ridx, False)
                if SEV_ORDER.index(sev) < SEV_ORDER.index(rec["severity"]):
                    rec["severity"] = sev
                pkg = package_of(r, driver)
                if pkg and not rec["package"]:
                    rec["package"] = pkg
                rec["source_scanners" if stage == "source" else "image_scanners"].add(scanner_label)

    # Derive lineage per vuln
    rows = []
    reach = stopped = 0
    for rec in vulns.values():
        pkg = rec["package"]
        in_src = bool(rec["source_scanners"]) or (pkg and pkg in src_sbom)
        in_img_scan = bool(rec["image_scanners"])
        in_img_sbom = bool(pkg and pkg in img_sbom)
        reaches = in_img_scan or in_img_sbom
        if reaches:
            status = "🔴 reaches runtime"
            reach += 1
        elif in_src:
            status = "🛑 stopped at build"
            stopped += 1
        else:
            status = "—"
        rows.append({**rec,
                     "source_scanners": sorted(rec["source_scanners"]),
                     "image_scanners": sorted(rec["image_scanners"]),
                     "in_source_sbom": bool(pkg and pkg in src_sbom),
                     "in_image_sbom": in_img_sbom,
                     "reaches_runtime": reaches, "status": status})

    rows.sort(key=lambda r: (not r["reaches_runtime"], SEV_ORDER.index(r["severity"]), r["id"]))
    total = len(rows)

    out = ["## 🧬 Vulnerability lineage — source → build → runtime\n"]
    out.append("```mermaid")
    out.append("flowchart LR")
    out.append(f'  S["Source<br/>Trivy-fs · Semgrep · Gitleaks · SBOM"] --> B["Build + Image<br/>Trivy-image · Syft image SBOM"]')
    out.append('  B --> G["Image Scan<br/>Grype"]')
    out.append(f'  G --> R["Runtime · Cloud Run<br/>{reach} CVEs reach production"]')
    out.append(f'  S -. "{stopped} stopped at build" .-> X["Not shipped<br/>(dev-only / pruned)"]')
    out.append("```")
    out.append("")
    out.append(f"**{total}** unique dependency/image CVEs correlated across stages: "
               f"**🔴 {reach} reach the production runtime image**, "
               f"**🛑 {stopped} were stopped at build** (in source but not in the shipped image).\n")
    out.append("**Other findings by stage (not dependency CVEs):**\n")
    out.append(f"- 🧩 **Source IaC / config & secrets** (Trivy-fs): {source_config} — "
               "infra/config definitions scanned in the repo; terraform etc. is **not** part of "
               "the app container, so these do not reach this runtime.")
    out.append(f"- 🔍 **SAST code** (Semgrep): {code_count} — live in the application source, which "
               "ships inside the image → present in runtime.")
    out.append(f"- 🔑 **Secrets** (Gitleaks): {secret_count} — committed in the repo; some sit in "
               "files the Dockerfile prunes at build.\n")
    out.append("> 💡 Lineage insight: dependency CVEs are first observed at the **image stage** — "
               "the source filesystem scan sees the manifest, but the full vulnerable dependency "
               "tree only materializes after `npm install` in the build, which is exactly what the "
               "image scanners (Trivy-image, Grype) and image SBOM inspect.\n")

    runtime_rows = [r for r in rows if r["reaches_runtime"]]
    out.append("### CVEs that reach production runtime\n")
    out.append("| Severity | CVE / GHSA | Package | Source stage | Image stage | In image SBOM |")
    out.append("|---|---|---|---|---|---|")
    for r in runtime_rows[:25]:
        src = ", ".join(r["source_scanners"]) or "—"
        img = ", ".join(r["image_scanners"]) or "—"
        out.append(f"| {r['severity']} | {r['id']} | {r['package'] or '—'} | {src} | {img} | "
                   f"{'✅' if r['in_image_sbom'] else '—'} |")
    if len(runtime_rows) > 25:
        out.append(f"\n_…and {len(runtime_rows) - 25} more reaching runtime._")
    out.append("")

    stopped_rows = [r for r in rows if r["status"].startswith("🛑")]
    if stopped_rows:
        out.append("### Stopped at build (did not ship — deprioritize)\n")
        out.append("| Severity | CVE / GHSA | Package | Seen at source |")
        out.append("|---|---|---|---|")
        for r in stopped_rows[:15]:
            out.append(f"| {r['severity']} | {r['id']} | {r['package'] or '—'} | "
                       f"{', '.join(r['source_scanners']) or 'source SBOM'} |")
        if len(stopped_rows) > 15:
            out.append(f"\n_…and {len(stopped_rows) - 15} more stopped at build._")
        out.append("")

    out.append("> Lineage correlates CVE/GHSA ids across source scans, image scans and the "
               "source/image SBOMs. \"Reaches runtime\" = present in the built-and-pushed image "
               "(image scan or image SBOM); \"stopped at build\" = in source but absent from the "
               "shipped image. Code/secret findings are reported separately as they live in the repo.")

    text = "\n".join(out)
    print(text)
    if summary_out:
        open(summary_out, "w").write(text + "\n")
    if json_out:
        json.dump({"total": total, "reaches_runtime": reach, "stopped_at_build": stopped,
                   "code_findings": code_count, "secret_findings": secret_count,
                   "vulns": rows}, open(json_out, "w"), indent=1)


if __name__ == "__main__":
    main()
