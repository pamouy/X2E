"""Outputs of an analysis: Excel workbook, findings report (Markdown), evidence pack."""
from __future__ import annotations

import io
import json
import zipfile

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

HEAD_FILL = PatternFill("solid", fgColor="1F2937")
HEAD_FONT = Font(bold=True, color="FFFFFF")
SEV_FILL = {"Blocker": "F8D7DA", "High": "FDE7C8", "Medium": "FFF4C2", "Info": "E3ECF7"}
APP_COLUMNS = ["wave", "waveName", "label", "pattern", "kind", "status", "tier", "score", "effortDays", "migrationClass", "critical", "signIns",
               "distinctUsers", "lastSignIn", "assignedUsers", "directAssignments", "provisioning", "complexClaims", "groupClaims", "customNameId",
               "encryptedAssertion", "flags", "galleryMatch", "galleryTemplate", "existsInEntra", "policy", "retireReason", "scoreReasons", "notes",
               "owner", "ownerHint", "trackStatus", "trackNote", "proposedWave", "appId"]
TABLE_TITLES = {"policies": "Policies", "zones": "Zones", "mfaMethods": "MfaMethods", "groupRules": "GroupRules", "automations": "Automations",
                "apis": "Apis", "federation": "Federation", "userStores": "UserStores", "manualChecks": "ManualChecks"}


def _cell(value):
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value)
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
        return "'" + value          # never let collected text become a formula
    return value


def _sheet(wb: Workbook, title: str, rows: list[dict], columns: list[str] | None = None, severity_col: str | None = None) -> None:
    ws = wb.create_sheet(title)
    if not rows and not columns:
        ws.append(["(empty)"])
        return
    cols = columns or list(rows[0].keys())
    ws.append([c[:1].upper() + c[1:] for c in cols])
    for c in ws[1]:
        c.fill, c.font = HEAD_FILL, HEAD_FONT
    for r in rows:
        ws.append([_cell(r.get(c)) for c in cols])
        if severity_col and r.get(severity_col) in SEV_FILL:
            ws.cell(row=ws.max_row, column=cols.index(severity_col) + 1).fill = PatternFill("solid", fgColor=SEV_FILL[r[severity_col]])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for i, c in enumerate(cols, start=1):
        width = max([len(str(c))] + [len(str(_cell(r.get(c)) or "")) for r in rows[:200]])
        ws.column_dimensions[get_column_letter(i)].width = max(8, min(60, width + 2))
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(vertical="top", wrap_text=isinstance(c.value, str) and len(c.value) > 60)


def workbook(analysis: dict, project_name: str) -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    s, st, idn = analysis["summary"], analysis["state"], analysis["identity"]
    lines = [("Project", project_name), ("Source platform", s["platform"]), ("Organisation", s["org"]), ("Collected (UTC)", s["collectedAt"]),
             ("Analysed (UTC)", s["analysedAt"]), ("Tool version", s["toolVersion"]), ("", ""),
             ("Starting state", f"{st['state']}{' (mixed)' if st['mixed'] else ''}"), ("What it means", st["description"])]
    lines += [(f"Evidence {i + 1}", e) for i, e in enumerate(st["evidence"])]
    lines += [("", ""), ("Active users", idn.get("active")), ("Users with a platform-only password", idn.get("localPasswordActive")),
              ("Applications", s["apps"]), ("Applications to migrate", s["appsToMigrate"]), ("Proposed for retirement", s["appsToRetire"]),
              ("Blockers", s["blockers"]), ("High findings", s["high"]), ("Medium findings", s["medium"]),
              ("Estimated app migration effort (days)", s["effortDays"]),
              ("Effort model", "Calibrated" if s["effortCalibrated"] else "PLACEHOLDER values: not calibrated on real engagements"),
              ("Usage data", f"{s['usageDays']} days" if s["usageKnown"] else "Not available"),
              ("Target tenant collected", "Yes" if s["targetCollected"] else "No"), ("API requests", s["requests"]),
              ("Secret values redacted at collection", s["redactedValues"])]
    for k, v in lines:
        ws.append([k, _cell(v)])
    for c in ws["A"]:
        c.font = Font(bold=True)
    ws.column_dimensions["A"].width = 40
    ws.column_dimensions["B"].width = 110
    for c in ws["B"]:
        c.alignment = Alignment(wrap_text=True, vertical="top")
    _sheet(wb, "Findings", analysis["findings"], ["id", "severity", "area", "title", "count", "evidence", "recommendation", "phase"], "severity")
    _sheet(wb, "Waves", analysis["waves"])
    _sheet(wb, "Apps", analysis["apps"], APP_COLUMNS)
    for key, title in TABLE_TITLES.items():
        rows = analysis["tables"].get(key) or []
        if rows:
            _sheet(wb, title, rows)
    if analysis.get("unmatched"):
        _sheet(wb, "Unmatched", analysis["unmatched"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _md(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def findings_report(analysis: dict, project_name: str) -> str:
    s, st, idn, tgt = analysis["summary"], analysis["state"], analysis["identity"], analysis["target"]
    out = [f"# Migration assessment: {s['platform']} to Entra ID", "",
           f"Project: {project_name}  ", f"Source: {s['org']}  ", f"Collected: {s['collectedAt']} (UTC)  ", f"Tool: Entra Migration Workbench {s['toolVersion']}", "",
           "## Result", "",
           f"- Starting state **{st['state']}**{' (mixed)' if st['mixed'] else ''}: {st['description']}",
           f"- **{s['blockers']} blockers**, {s['high']} high, {s['medium']} medium findings.",
           f"- {s['appsToMigrate']} applications to migrate, {s['appsToRetire']} proposed for retirement, of {s['apps']} in total.",
           f"- Estimated application effort: {s['effortDays']} days" + ("." if s["effortCalibrated"] else " (placeholder effort values, not calibrated)."), ""]
    out += ["## Evidence for the starting state", ""] + [f"- {e}" for e in st["evidence"]] + [""]
    if idn.get("known"):
        out += ["## Identities", "", f"- {idn['active']} active users of {idn['total']}; {idn['localPasswordActive']} with a password only on the source platform.",
                "- Active users by source: " + ", ".join(f"{k} {v}" for k, v in idn["activeBySource"].items()) + "."]
        if idn.get("matching"):
            m = idn["matching"]
            out.append(f"- Matching against Entra: {m['byUpn']} by UPN, {m['byMail']} by mail, {m['ambiguous']} ambiguous, {m['unmatched']} unmatched, of {m['compared']} compared.")
        out.append("")
    else:
        out += ["## Identities", "", f"- {idn.get('note')}", ""]
    if tgt.get("collected"):
        ca = tgt.get("conditionalAccess")
        out += ["## Target tenant", "", f"- Tenant: {tgt.get('tenant')}; directory sync enabled: {tgt.get('syncEnabled')}; federated domains: {', '.join(tgt.get('federatedDomains') or []) or 'none'}.",
                f"- Conditional Access: {ca['enabled']} enabled, {ca['reportOnly']} report-only, {ca['disabled']} disabled." if ca else "- Conditional Access policies were not readable (optional permission).", ""]
    out += ["## Findings", "", "| ID | Severity | Area | Finding | Count | Evidence | Recommendation | Phase |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for f in analysis["findings"]:
        out.append(f"| {f['id']} | {f['severity']} | {_md(f['area'])} | {_md(f['title'])} | {_md(f['count'])} | {_md(f['evidence'])[:400]} | {_md(f['recommendation'])} | {f['phase']} |")
    out += ["", "## Wave proposal", "", "| Wave | Content | Apps | Low | Medium | High | Effort (days) | Critical |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for w in analysis["waves"]:
        out.append(f"| {w['wave']} | {_md(w['name'])} | {w['apps']} | {w['low']} | {w['medium']} | {w['high']} | {w['effortDays']} | {w['critical']} |")
    out += ["", "## What this report cannot see", ""]
    if s["collectionErrors"]:
        out.append(f"- {s['collectionErrors']} collection step(s) failed; each is listed as COL-01. The report is silent on those areas, not clean.")
    if s["notAvailable"]:
        out.append(f"- Not available on this platform or licence: {', '.join(s['notAvailable'])}.")
    out.append(f"- {len(analysis['tables'].get('manualChecks') or [])} items are not exposed by the API and are captured by hand (Manual checks).")
    out.append("- The collector reads configuration and aggregated usage. It does not test applications and does not see custom code.")
    return "\n".join(out) + "\n"


def evidence_pack(project: dict, items: list[dict], audit: list[dict]) -> bytes:
    """One zip per project: per connector the manifest, analysis, report and workbook; plus gates and the audit trail."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("project.json", json.dumps({k: project.get(k) for k in ("id", "name", "client", "description", "created", "gates")}, indent=2))
        z.writestr("audit-trail.json", json.dumps(audit, indent=2))
        for it in items:
            base = it["folder"]
            z.writestr(f"{base}/manifest.json", json.dumps(it["manifest"], indent=2))
            if it.get("analysis"):
                z.writestr(f"{base}/analysis.json", json.dumps(it["analysis"], indent=2, default=str))
                z.writestr(f"{base}/findings-report.md", findings_report(it["analysis"], project.get("name", "")))
                z.writestr(f"{base}/assessment.xlsx", workbook(it["analysis"], project.get("name", "")))
    return buf.getvalue()
