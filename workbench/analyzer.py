"""Platform-neutral analysis: scoring, waves, starting state, findings."""
from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from . import __version__
from .core import as_list, finding, get, iso, norm_name, parse_time, utcnow

WAVES = {
    "P": "Platform: Microsoft 365 federation track", "1": "Gallery SAML and bookmarks", "2": "Custom SAML", "3": "OIDC",
    "4": "Apps with provisioning", "5": "Password-vaulted apps", "6": "Legacy protocols", "7": "APIs and their clients (last)", "R": "Retire or archive (decision)",
}
WAVE_ORDER = ["P", "1", "2", "3", "4", "5", "6", "7", "R"]
FLAG_FINDINGS = {
    "password-grant": ("Blocker", "Clients using the password grant", "The resource owner password flow does not work with MFA or Conditional Access. Redesign to an interactive or client-credentials flow."),
    "uma-authorization": ("Blocker", "Clients using the platform's authorization services", "No Entra equivalent. Move authorization decisions into the application or a separate policy engine."),
    "ws-trust": ("Blocker", "Connections using WS-Trust", "Identify the active clients behind each one. Entra covers WS-Trust only for a few legacy Microsoft flows."),
    "custom-mapper": ("High", "Apps with scripted or custom claim logic", "Rewrite as Entra claims transformations where possible; the rest needs a custom claims provider or an application change."),
    "directory-lookup": ("High", "Apps whose claims are read from a data store at sign-in", "Sync those attributes to Entra first (directory extensions), or the claims arrive empty."),
    "header-based": ("Medium", "Apps behind the platform's access gateway", "Publish through application proxy with header-based single sign-on, or keep the gateway with Entra as token provider."),
    "implicit-flow": ("Medium", "Clients with the implicit flow enabled", "Move to authorization code with PKCE during migration."),
}
SEVERITY_ORDER = {"Blocker": 0, "High": 1, "Medium": 2, "Info": 3}
LEGACY = {"RADIUS", "SAML 1.1", "WS-Fed", "Other"}


def merge_config(base: dict, override: dict | None) -> dict:
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def _apps(inv: dict, entra, cfg: dict, tracking: dict) -> list[dict]:
    active_users = sum(1 for u in inv["users"] if u["status"] == "ACTIVE")
    gallery_known = bool(entra and entra.has("applicationTemplates"))
    gallery: dict[str, dict] = {}
    if gallery_known:
        for t in entra.rows("applicationTemplates"):
            n = norm_name(t.get("displayName"))
            if n and n not in gallery:
                gallery[n] = t
    existing = {norm_name(s.get("displayName")) for s in entra.rows("servicePrincipals")} if entra and entra.has("servicePrincipals") else set()
    m = cfg["modifiers"]
    out = []
    for app in inv["apps"]:
        flags = list(app["flags"])
        match, template = "unknown", None
        if gallery_known:
            match = "none"
            norm = norm_name(app["label"])
            if norm and norm in gallery:
                match, template = "exact", gallery[norm]
            elif len(norm) >= 4:
                cands = sorted((k for k in gallery if k.startswith(norm) or (len(k) >= 4 and norm.startswith(k))), key=len)
                if cands:
                    match, template = "probable", gallery[cands[0]]
        in_gallery = match in ("exact", "probable") if gallery_known else app["catalogHint"] is True
        sign_ins, distinct = app["signIns"], app["distinctUsers"]
        if inv["usageKnown"] and sign_ins is None:
            sign_ins, distinct = 0, 0
        critical = distinct is not None and active_users > 0 and (distinct / active_users) >= cfg["criticalUserShare"]

        pattern = app["pattern"]
        score = int(cfg["patternBase"].get(pattern, cfg["patternBase"]["Other"]))
        reasons = [f"{pattern} base {score}"]

        def add(points: int, text: str) -> None:
            nonlocal score
            score += points
            reasons.append(f"{text} {points:+d}")

        if pattern == "SAML" and match == "exact":
            add(m["galleryExact"], "gallery template")
        if app["provisioning"] in ("Outbound", "Both"):
            add(m["provisioningOutbound"], "outbound provisioning")
        if app["provisioning"] in ("Inbound", "Both"):
            add(m["provisioningInbound"], "inbound provisioning")
        if app["complexClaims"] >= m["complexClaimsManyFrom"]:
            add(m["complexClaimsMany"], f"{app['complexClaims']} claim expressions")
        elif app["complexClaims"] > 0:
            add(m["complexClaimsFew"], f"{app['complexClaims']} claim expression(s)")
        if app["groupClaims"]:
            add(m["groupClaims"], "group or role claims")
        if app["customNameId"]:
            add(m["customNameId"], "custom NameID")
        if app["encrypted"]:
            add(m["encryptedAssertion"], "encrypted assertion")
        if app["directAssignments"] is not None and app["directAssignments"] > cfg["directAssignmentThreshold"]:
            add(m["manyDirectAssignments"], f"{app['directAssignments']} direct assignments")
        for f in flags:
            pts = int(cfg["flagScores"].get(f, 0))
            if pts:
                add(pts, f)
        score = max(1, score)
        tier = "Low" if score <= cfg["tiers"]["lowMax"] else "Medium" if score <= cfg["tiers"]["mediumMax"] else "High"

        retire = None
        if app["status"] != "ACTIVE":
            retire = "Inactive on the source platform"
        elif inv["usageKnown"] and sign_ins == 0 and not app["isMachine"] and not app["isPlatform"]:
            retire = f"No sign-ins in {inv['usageDays']} days"
        legacy = pattern in LEGACY or "ws-trust" in flags
        wave = ("P" if app["isPlatform"] else "R" if retire else "6" if legacy else "5" if pattern == "SWA" else "4" if app["provisioning"] != "None"
                else "3" if pattern == "OIDC" else "1" if pattern == "Bookmark" or in_gallery else "2")
        gap = pattern in ("RADIUS", "Other") or any(f in ("uma-authorization", "ws-trust", "password-grant") for f in flags)
        rebuild = (pattern in ("SWA", "SAML 1.1", "WS-Fed") or app["provisioning"] != "None" or app["complexClaims"] > 0 or app["groupClaims"] > 0
                   or app["customNameId"] or any(f in ("custom-mapper", "directory-lookup", "header-based") for f in flags))
        cls = "Rebuild" if app["isPlatform"] else "Decision" if retire else "Gap" if gap else "Rebuild" if rebuild else "Generate"

        notes = list(app["notes"])
        if critical and wave not in ("P", "R"):
            notes.append("Business-critical by usage: not first in its wave")
        if app["isMachine"]:
            notes.append("No interactive sign-in: usage is not visible in user sign-in events")
        if app["usesClientSecret"]:
            notes.append("New client secret must be set in the app")
        if pattern == "SWA" and template and "saml" in as_list(template.get("supportedSingleSignOnModes")):
            notes.append(f"Gallery template '{template.get('displayName')}' supports SAML: upgrade candidate")
        in_entra = norm_name(app["label"]) in existing if existing else None
        if in_entra:
            notes.append("An enterprise application with this name already exists in the target tenant")

        track = tracking.get(str(app["id"]), {})
        planned = track.get("wave") or wave
        out.append({
            "appId": app["id"], "label": app["label"], "pattern": pattern, "kind": app["kind"], "status": app["status"],
            "wave": planned, "waveName": WAVES.get(planned, planned), "proposedWave": wave,
            "tier": "" if wave in ("P", "R") else tier, "score": None if wave in ("P", "R") else score,
            "effortDays": None if planned in ("P", "R") else float(cfg["effortDays"][tier]),
            "migrationClass": cls, "critical": bool(critical), "signIns": sign_ins, "distinctUsers": distinct, "lastSignIn": app["lastSignIn"],
            "assignedUsers": app["assignedUsers"], "directAssignments": app["directAssignments"], "provisioning": app["provisioning"],
            "complexClaims": app["complexClaims"], "groupClaims": app["groupClaims"], "customNameId": bool(app["customNameId"]),
            "encryptedAssertion": bool(app["encrypted"]), "flags": flags, "galleryMatch": match,
            "galleryTemplate": template.get("displayName") if template else None, "existsInEntra": in_entra, "policy": app["policy"],
            "retireReason": retire, "scoreReasons": "; ".join(reasons), "notes": "; ".join(notes),
            "ownerHint": app["owner"], "owner": track.get("owner") or "", "trackStatus": track.get("status") or "Not started",
            "trackNote": track.get("note") or "",
        })
    order = {w: i for i, w in enumerate(WAVE_ORDER)}
    out.sort(key=lambda a: (order.get(a["wave"], 99), a["critical"], a["score"] or 0, a["label"].lower()))
    return out


def _identity(inv: dict, entra, cfg: dict, collected) -> dict:
    stale_days = int(cfg["staleDays"])
    if not inv["usersKnown"]:
        return dict(known=False, note=inv["usersNote"], total=None, active=None, localPasswordActive=None, localPasswordShare=0,
                    neverSignedInActive=None, staleActive=None, staleDays=stale_days, activeBySource={}, matching=None, unmatched=[])
    cut = collected - timedelta(days=stale_days)
    users = inv["users"]
    active = [u for u in users if u["status"] == "ACTIVE"]
    by_source = dict(Counter(str(u["source"]) for u in active).most_common())
    local = [u for u in active if u["localPassword"] is True]
    never = stale = None
    if inv["lastLoginKnown"]:
        never = sum(1 for u in active if u["lastLogin"] is None)
        stale = sum(1 for u in active if u["lastLogin"] is not None and (parse_time(u["lastLogin"]) or collected) < cut)
    elif inv["staleActiveEstimate"] is not None:
        stale = int(inv["staleActiveEstimate"])
    matching, unmatched = None, []
    if entra and entra.has("users"):
        by_upn: dict[str, dict] = {}
        by_mail: dict[str, list] = {}
        for e in entra.rows("users"):
            upn, mail = str(e.get("userPrincipalName") or "").lower(), str(e.get("mail") or "").lower()
            if upn:
                by_upn[upn] = e
            if mail:
                by_mail.setdefault(mail, []).append(e)
        how = Counter()
        live = [u for u in users if u["status"] != "DELETED"]
        for u in live:
            login, email = str(u["login"] or "").lower(), str(u["email"] or "").lower()
            if (login and login in by_upn) or (email and email in by_upn):
                how["upn"] += 1
                continue
            cands = by_mail.get(email) if email and email in by_mail else by_mail.get(login) if login else None
            if cands and len(cands) == 1:
                how["mail"] += 1
            elif cands:
                how["ambiguous"] += 1
                unmatched.append(dict(login=u["login"], email=u["email"], status=u["status"], source=u["source"], reason="Several Entra users share this mail address"))
            else:
                how["unmatched"] += 1
                unmatched.append(dict(login=u["login"], email=u["email"], status=u["status"], source=u["source"], reason="No Entra user with this UPN or mail"))
        matching = dict(compared=len(live), byUpn=how["upn"], byMail=how["mail"], ambiguous=how["ambiguous"], unmatched=how["unmatched"])
    return dict(known=True, note=inv["usersNote"], total=len(users), active=len(active), activeBySource=by_source, localPasswordActive=len(local),
                localPasswordShare=round(len(local) / len(active), 3) if active else 0, neverSignedInActive=never, staleActive=stale,
                staleDays=stale_days, matching=matching, unmatched=unmatched)


def _state(inv: dict, entra, cfg: dict, identity: dict) -> dict:
    p = inv["platform"]
    evidence = [e for e in inv["stateEvidence"] if e]
    federated_domains: list[str] = []
    if entra and entra.has("domains"):
        federated_domains = [str(d.get("id")) for d in entra.rows("domains") if d.get("authenticationType") == "Federated"]
        evidence.append(f"Entra reports federated domain(s): {', '.join(federated_domains)}" if federated_domains else "Entra reports no federated domain")
    if identity["known"]:
        evidence.append(f"{identity['localPasswordActive']} of {identity['active']} active users ({round(100 * identity['localPasswordShare'], 1)}%) have their password only on {p}")
    else:
        evidence.append(f"{p} holds no users of its own: passwords live in the data stores behind it")
    federated = inv["m365Federated"] is True or bool(federated_domains)
    state = "C" if identity["known"] and identity["localPasswordShare"] >= cfg["localPasswordShareForStateC"] else "A" if federated else "B"
    text = {"A": f"Microsoft 365 is federated to {p} and most passwords live in a directory: staged rollout, Entra plugged into the old platform, app waves, convert the domain last.",
            "B": f"{p} and Entra run side by side without federation: app waves only.",
            "C": f"{p} is the source of truth for most users: new Entra credentials for every user and rebuilt provisioning."}[state]
    mixed = state != "C" and identity["known"] and (identity["localPasswordActive"] or 0) > 0
    if mixed:
        text += f" {identity['localPasswordActive']} users with a platform-only password additionally need the credential path of state C."
    return dict(state=state, mixed=bool(mixed), federated=bool(federated), description=text, evidence=evidence)


def _findings(inv: dict, snap, entra, cfg: dict, apps: list[dict], identity: dict, target: dict) -> list[dict]:
    out: list[dict] = []
    live = [a for a in apps if a["wave"] != "R"]
    p = inv["platform"]
    labels = lambda rows: ", ".join(r["label"] for r in rows)  # noqa: E731

    for e in snap.errors:
        out.append(finding("COL-01", "High", "Collection", f"Not collected: {e.get('step')}", None, e.get("message"),
                           "Grant the missing permission and collect again. Until then the report is silent on this area, not clean.", "Assess"))
    if not (entra and entra.has("users")):
        out.append(finding("COL-03", "Medium", "Collection", "Target tenant not collected", None, "No snapshot of the Entra tenant in this project.",
                           "Configure the target connector and collect it to enable identity matching, gallery matching and federation evidence.", "Assess"))
    elif entra.errors:
        out.append(finding("COL-04", "Medium", "Collection", "Target tenant only partly collected", len(entra.errors),
                           "; ".join(f"{e.get('step')}: {e.get('message')}" for e in entra.errors), "Grant the missing Graph permission and collect the target again.", "Assess"))
    if not inv["usageKnown"]:
        out.append(finding("USE-01", "High", "Collection", "No usage data: nothing can be proposed for retirement", None, inv["usageNote"],
                           "Provide usage data before the wave plan is fixed; unused apps are the cheapest effort reduction.", "Assess"))

    if identity["known"]:
        if identity["localPasswordActive"]:
            out.append(finding("ID-01", "Blocker", "Credentials", f"Active users whose password exists only on {p}", identity["localPasswordActive"],
                               f"{round(100 * identity['localPasswordShare'], 1)}% of active users. {identity['note']}".strip(),
                               "Decide the credential path in Design: Temporary Access Pass with passkey or Authenticator registration is the default.", "Design"))
        mt = identity["matching"]
        if mt:
            if mt["unmatched"]:
                out.append(finding("ID-02", "Blocker", "Identities", "Users without a matching Entra user", mt["unmatched"], "No Entra user with the same UPN or mail. See the unmatched list.",
                                   "Create or correct the Entra identities before the first cohort moves; check alias domains.", "Foundation"))
            if mt["ambiguous"]:
                out.append(finding("ID-03", "High", "Identities", "Users matching several Entra users", mt["ambiguous"], "Several Entra users share the mail address.",
                                   "Resolve duplicates in Entra.", "Foundation"))
        idle = int(identity["staleActive"] or 0) + int(identity["neverSignedInActive"] or 0)
        if idle:
            ev = (f"{identity['staleActive']} stale, {identity['neverSignedInActive']} never signed in." if identity["neverSignedInActive"] is not None
                  else "Estimated from sign-in events: enabled users without a login in the event window.")
            out.append(finding("ID-04", "Medium", "Identities", "Active users without a recent sign-in", idle, ev,
                               "Confirm with HR and deactivate before migration; every removed user is one MFA registration less.", "Assess"))

    gap_mfa = [x for x in inv["mfaMethods"] if x["status"] == "ACTIVE" and x["migrationClass"] == "Gap"]
    if gap_mfa:
        out.append(finding("MFA-01", "High", "MFA", "Active authentication methods without a like-for-like Entra method", len(gap_mfa),
                           ", ".join(x["method"] for x in gap_mfa), "Decide per method: replace, bridge through external MFA, or retire.", "Design"))
    f = inv["factorSummary"]
    if f:
        if f["usersWithoutFactor"]:
            out.append(finding("MFA-02", "Medium", "MFA", "Active users with no enrolled factor", f["usersWithoutFactor"], f"Of {f['usersChecked']} users checked.",
                               "These users need onboarding with a Temporary Access Pass in any case; plan help-desk capacity.", "Pilot"))
        out.append(finding("MFA-03", "Info", "MFA", "Users who already hold a phishing-resistant factor", f["usersWithPhishingResistantFactor"], f"Of {f['usersChecked']}.",
                           "Use the migration to raise the method, not only to move it.", "Design"))

    swa = [a for a in live if a["pattern"] == "SWA"]
    if swa:
        out.append(finding("APP-01", "High", "Applications", "Password-vaulted apps", len(swa), labels(swa),
                           "Upgrade to SAML or OIDC where the vendor allows; the rest go to password-based single sign-on or a password manager.", "Design"))
    prov = [a for a in live if a["provisioning"] != "None" and a["wave"] != "P"]
    if prov:
        out.append(finding("APP-02", "High", "Applications", "Apps with provisioning to rebuild", len(prov), labels(prov),
                           "Rebuild attribute mappings in the Entra provisioning service; inbound apps are identity sources and belong to the provisioning design.", "Design"))
    legacy = [a for a in live if a["proposedWave"] == "6"]
    if legacy:
        out.append(finding("APP-03", "Blocker", "Applications", "Apps on protocols without a direct Entra target", len(legacy),
                           ", ".join(f"{a['label']} ({a['pattern']})" for a in legacy), "Assess each consumer and decide: replace, proxy, or keep outside Entra.", "Design"))
    retire = [a for a in apps if a["wave"] == "R"]
    if retire:
        out.append(finding("APP-05", "Medium", "Applications", "Apps proposed for retirement instead of migration", len(retire),
                           "; ".join(f"{a['label']}: {a['retireReason'] or 'set by hand'}" for a in retire), "Confirm with owners. Each retired app is effort removed from the plan.", "Assess"))
    direct = [a for a in live if a["directAssignments"] is not None and a["directAssignments"] > cfg["directAssignmentThreshold"]]
    if direct:
        out.append(finding("APP-06", "Medium", "Applications", f"Apps with more than {cfg['directAssignmentThreshold']} direct user assignments", len(direct),
                           ", ".join(f"{a['label']} ({a['directAssignments']})" for a in direct), "Move to group-based assignment before or during migration.", "Foundation"))
    no_owner = [a for a in live if a["wave"] != "P" and not a["owner"]]
    if no_owner:
        hinted = sum(1 for a in no_owner if a["ownerHint"])
        out.append(finding("APP-07", "Medium", "Applications", "Apps without a confirmed owner", len(no_owner),
                           f"{hinted} carry a hint from the source platform (a note or description); none is confirmed in the tracker.",
                           "Name an owner per app before G2; an app without an owner cannot enter a wave.", "Design"))
    claims = [a for a in live if a["complexClaims"] > 0 or a["customNameId"]]
    if claims:
        out.append(finding("APP-08", "Medium", "Applications", "Apps with claim expressions or a custom NameID", len(claims),
                           ", ".join(f"{a['label']} ({a['complexClaims']})" for a in claims), "Translate by hand and compare the tokens or assertions before cutover.", "Migrate"))
    for n, (flag, (sev, title, rec)) in enumerate(FLAG_FINDINGS.items(), start=1):
        hit = [a for a in live if flag in a["flags"]]
        if hit:
            out.append(finding(f"FLG-{n:02d}", sev, "Applications", title, len(hit), labels(hit), rec, "Design"))

    weak = [r for r in inv["policies"] if r["status"] == "ACTIVE" and r["authentication"] in ("No MFA", "1FA", "MFA only if enrolled") and r["access"] != "DENY"]
    if weak:
        out.append(finding("POL-01", "High", "Policies", "Active rules that allow access without enforced MFA", len(weak),
                           "; ".join(f"{r['policy']} / {r['rule']}" for r in weak), "Do not reproduce by default. Each one needs an explicit decision in the parity checklist.", "Design"))
    if inv["policies"]:
        out.append(finding("POL-02", "Info", "Policies", "Policy rows to work through in the parity checklist", len(inv["policies"]), "See the Policies table.",
                           "Every row gets a Conditional Access equivalent or a recorded decision to drop it.", "Design"))
    manual_rules = [r for r in inv["groupRules"] if r["translation"] == "Manual" and r["status"] == "ACTIVE"]
    if manual_rules:
        out.append(finding("GRP-01", "Medium", "Groups", "Membership rules that need manual translation", len(manual_rules), f"Of {len(inv['groupRules'])} rules.",
                           "Rewrite as dynamic membership rules; check that the attributes exist in Entra.", "Foundation"))
    auto_gap = [x for x in inv["automations"] if x["status"] == "ACTIVE" and x["migrationClass"] == "Gap"]
    if auto_gap:
        out.append(finding("AUT-01", "Blocker", "Automations", "Active custom logic without an Entra equivalent", len(auto_gap),
                           ", ".join(f"{x['name']} [{x['kind']}]" for x in auto_gap), "Each one needs a redesign or an accepted loss of function.", "Design"))
    auto_other = [x for x in inv["automations"] if x["status"] == "ACTIVE" and x["migrationClass"] != "Gap" and x["kind"] != "API token"]
    if auto_other:
        out.append(finding("AUT-02", "High", "Automations", "Active integrations to rebuild", len(auto_other),
                           ", ".join(f"{x['name']} [{x['kind']}]" for x in auto_other), "Find the consumer of each one and give it an Entra or Graph source.", "Design"))
    apis = [x for x in inv["apis"] if x["status"] == "ACTIVE" and x["migrationClass"] != "Generate"]
    if apis:
        out.append(finding("API-01", "High", "APIs", "APIs and authorization servers to rebuild as app registrations", len(apis),
                           ", ".join(x["name"] for x in apis), "APIs and their clients change together. Plan as the last wave.", "Design"))
    if inv["federation"]:
        out.append(finding("IDP-01", "Medium", "Federation", "Inbound identity providers", len(inv["federation"]),
                           ", ".join(f"{x['name']} ({x['type']})" for x in inv["federation"]),
                           "Rebuild as B2B collaboration, cross-tenant access or external identity provider federation.", "Design"))
    store_gap = [x for x in inv["userStores"] if x["migrationClass"] == "Gap"]
    if store_gap:
        out.append(finding("STO-01", "Blocker", "Identities", "User stores that Entra cannot sync from directly", len(store_gap),
                           ", ".join(f"{x['name']} ({x['type']})" for x in store_gap),
                           "Decide where these identities and their attributes will live: Active Directory, inbound provisioning, or cloud-only users.", "Design"))
    if inv["manualChecks"]:
        out.append(finding("MAN-01", "Medium", "Collection", f"Items the {p} API does not expose: capture by hand", len(inv["manualChecks"]), "See the Manual checks table.",
                           "Complete the questionnaire before G1; the parity check is incomplete without it.", "Assess"))

    if target.get("collected"):
        ad_store = any("Active Directory" in x["type"] for x in inv["userStores"])
        if ad_store and target.get("syncEnabled") is not True:
            out.append(finding("TGT-01", "High", "Target", "Directory synchronisation is not enabled in the target tenant", None,
                               "Users come from Active Directory on the source platform, but the tenant reports no directory sync.",
                               "Deploy Entra Connect Sync or Cloud Sync with password hash sync in Foundation.", "Foundation"))
        ca = target.get("conditionalAccess")
        if ca is not None and ca.get("enabled", 0) == 0:
            out.append(finding("TGT-02", "Medium", "Target", "No Conditional Access policy is enabled in the target tenant", ca.get("total", 0),
                               f"{ca.get('reportOnly', 0)} in report-only, {ca.get('disabled', 0)} disabled.",
                               "Deploy the baseline in report-only during Foundation and enable it before the pilot.", "Foundation"))
    out.extend(x for x in inv["findings"] if x)
    out.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], x["id"]))
    return out


def _target(entra) -> dict:
    if not entra:
        return {"collected": False}
    org = entra.obj("organization")
    out: dict[str, Any] = {"collected": True, "tenant": org.get("displayName"), "collectedAt": get(entra.manifest or {}, "collectedAtUtc"),
                           "syncEnabled": org.get("onPremisesSyncEnabled"), "users": len(entra.rows("users")) if entra.has("users") else None,
                           "federatedDomains": [d.get("id") for d in entra.rows("domains") if d.get("authenticationType") == "Federated"],
                           "galleryTemplates": len(entra.rows("applicationTemplates")) if entra.has("applicationTemplates") else None,
                           "enterpriseApps": len(entra.rows("servicePrincipals")) if entra.has("servicePrincipals") else None, "conditionalAccess": None}
    if entra.has("conditionalAccessPolicies"):
        states = Counter(str(p.get("state")) for p in entra.rows("conditionalAccessPolicies"))
        out["conditionalAccess"] = {"total": sum(states.values()), "enabled": states.get("enabled", 0),
                                    "reportOnly": states.get("enabledForReportingButNotEnforced", 0), "disabled": states.get("disabled", 0)}
    return out


def analyse(snap, normalizer, entra=None, scoring: dict | None = None, tracking: dict | None = None) -> dict:
    """Turn one source snapshot (and the target snapshot, when there is one) into the assessment."""
    from .core import DEFAULT_SCORING
    cfg = merge_config(DEFAULT_SCORING, scoring)
    inv = normalizer(snap, cfg)
    collected = snap.started
    apps = _apps(inv, entra, cfg, tracking or {})
    identity = _identity(inv, entra, cfg, collected)
    state = _state(inv, entra, cfg, identity)
    target = _target(entra)
    findings = _findings(inv, snap, entra, cfg, apps, identity, target)

    waves = []
    for w in WAVE_ORDER:
        rows = [a for a in apps if a["wave"] == w]
        if rows:
            waves.append({"wave": w, "name": WAVES[w], "apps": len(rows), "low": sum(1 for a in rows if a["tier"] == "Low"),
                          "medium": sum(1 for a in rows if a["tier"] == "Medium"), "high": sum(1 for a in rows if a["tier"] == "High"),
                          "effortDays": round(sum(a["effortDays"] or 0 for a in rows), 1), "critical": sum(1 for a in rows if a["critical"]),
                          "done": sum(1 for a in rows if a["trackStatus"] in ("Validated", "Retired"))})
    sev = Counter(x["severity"] for x in findings)
    live = [a for a in apps if a["wave"] not in ("R",)]
    summary = {
        "platform": inv["platform"], "org": inv["orgName"], "collectedAt": iso(collected), "analysedAt": iso(utcnow()), "toolVersion": __version__,
        "state": state["state"], "mixed": state["mixed"], "apps": len(apps), "appsToMigrate": len([a for a in apps if a["wave"] not in ("R", "P")]),
        "appsToRetire": len([a for a in apps if a["wave"] == "R"]), "activeUsers": identity["active"], "localPasswordUsers": identity["localPasswordActive"],
        "blockers": sev.get("Blocker", 0), "high": sev.get("High", 0), "medium": sev.get("Medium", 0), "info": sev.get("Info", 0),
        "effortDays": round(sum(a["effortDays"] or 0 for a in live), 1), "effortCalibrated": bool(cfg["effortDays"].get("calibrated")),
        "usageKnown": inv["usageKnown"], "usageDays": inv["usageDays"], "targetCollected": target["collected"],
        "byClass": dict(Counter(a["migrationClass"] for a in apps)), "byPattern": dict(Counter(a["pattern"] for a in apps)),
        "requests": get(snap.manifest or {}, "requests"), "redactedValues": get(snap.manifest or {}, "redactedValues"),
        "collectionErrors": len(snap.errors), "notAvailable": [x.get("step") for x in snap.not_available],
    }
    tables = {k: inv[k] for k in ("policies", "zones", "mfaMethods", "groupRules", "automations", "apis", "federation", "userStores", "manualChecks")}
    return {"summary": summary, "state": state, "identity": {k: v for k, v in identity.items() if k != "unmatched"}, "unmatched": identity["unmatched"],
            "factorSummary": inv["factorSummary"], "target": target, "apps": apps, "waves": waves, "findings": findings, "tables": tables,
            "scoring": cfg}
