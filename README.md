# Entra Migration Workbench

One application to assess and track migrations to Microsoft Entra ID from **Okta, Keycloak, PingFederate, PingOne and OneLogin**.
It replaces the two PowerShell toolkits (`o2e-toolkit`, `x2e-toolkit`): same collection and analysis logic, now behind a web UI,
with several client projects side by side.

**Status: 0.2.1, tested against mock tenants only.** Every collector was written from the vendors' API documentation and is exercised
end to end against mock APIs in `tests/mocks`. None has run against a real tenant yet. Expect to adjust field names and paging details
on first contact; the collectors record what they could not read instead of failing.

## What it does

1. **Projects.** One project per client engagement. Each has its own encryption key.
2. **Source connectors.** One or more per project (for example PingFederate and PingOne of the same client, or two Keycloak realms).
3. **Target connector.** The client's Entra tenant, read through Microsoft Graph.
4. **Collection.** Read-only snapshot of configuration and aggregated usage. Runs in the background; several projects at once.
5. **Analysis.** Starting state (A, B or C), findings with severity and phase, application scoring and wave proposal, policy parity
   checklist, identity matching against the target, gallery matching, items to capture by hand.
6. **Tracking.** Owner, status and wave per application; parity decision per policy rule; answers to manual checks; sign-off of gates G1 to G6.
7. **Outputs.** Excel workbook, findings report (Markdown), analysis (JSON), and an evidence pack (zip) with manifests and the audit trail.

## Demo project

"Load demo project" on the Projects page creates a complete Okta-to-Entra project from snapshots of the mock Okta org and the mock
Entra tenant that ship with the application (`workbench/demo`). Nothing is contacted and no real person appears in it. The project is
stored encrypted like any other, comes with owners, statuses, parity decisions and a signed G1, and can be changed or deleted freely.

## Run it

```bash
docker compose up --build -d
docker compose logs workbench        # shows the one-time setup code
# open http://127.0.0.1:8080, enter the setup code, choose the shared passphrase
```

Without Docker (Python 3.11 or newer):

```bash
pip install -r requirements.txt
WORKBENCH_DATA=./data python -m workbench
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `WORKBENCH_DATA` | `./data` (`/data` in the container) | Directory of the SQLite database |
| `WORKBENCH_HOST`, `WORKBENCH_PORT` | `127.0.0.1`, `8080` | Listen address |
| `WORKBENCH_TLS_CERT`, `WORKBENCH_TLS_KEY` | none | Serve https directly |
| `WORKBENCH_COOKIE_SECURE` | `0` | Set to `1` when the UI is served over https |
| `WORKBENCH_WORKERS` | `4` | Collections that run at the same time |

The compose file publishes the port on the loopback interface only. On a jump host, put a TLS reverse proxy in front and restrict who can reach it.

## Two ways to run it

| | Self-hosted (server mode) | Vercel (serverless mode) |
| --- | --- | --- |
| Start | `docker compose up` or `python -m workbench` | Deploy this directory; `app.py` is the entrypoint |
| Database | SQLite file on a volume | Postgres through `DATABASE_URL` |
| Vault key | Derived at sign-in, carried in the session cookie, sealed with a per-process secret. A restart seals everything | Same, sealed with `WORKBENCH_SESSION_SECRET` so that any instance can read the cookie |
| Collections | Background threads, several at once | Inside a request that the signed-in browser starts; limited by the function's maximum duration (300 s configured) |
| Reach | Whatever the host can reach, including internal Keycloak and PingFederate | Public internet only. Hosts on private addresses are refused |
| Uploads | 200 MB per file | About 4.5 MB per request on Vercel; the UI gzips log files before upload |

In both modes the server holds no key at rest: the database is ciphertext, and the key exists only in the signed-in browser's cookie
(sealed) and in memory while a request runs. That is why there is no unattended worker or queue: a worker would need the key stored on the server.

### Deploy on Vercel

1. Create the project and deploy this directory (`vercel deploy`, or import the Git repository). The framework preset is FastAPI.
2. Storage tab: add a Postgres database (Neon) and connect it to the project, so that `DATABASE_URL` is set. Choose an EU region.
3. Environment variables: `WORKBENCH_SESSION_SECRET` (long random value, type Sensitive) and `WORKBENCH_SETUP_CODE` (one-time code for the first sign-in).
4. Keep Deployment Protection (Vercel Authentication) on, so that the URL is reachable only by members of the Vercel account.
5. Redeploy, open the URL, enter the setup code and choose the passphrase. Then remove `WORKBENCH_SETUP_CODE`.

Limits on Vercel: a collection must finish within the function's maximum duration, and the browser tab must stay signed in until it has started;
a run that stops reporting is closed as "interrupted" after 15 minutes (`WORKBENCH_RUN_SILENCE`). On-premises admin APIs are not reachable.
Client credentials and snapshots then sit in a third-party cloud database, encrypted, behind a public URL: check this against the client contract before use.

## Security model

- **One shared passphrase.** A key is derived from it with scrypt. It is never stored on the server: it travels in the session cookie, sealed, and is in memory only while a request runs. "Lock" ends every session.
  There is no recovery if the passphrase is lost.
- **One key per project.** Project name, connector credentials, uploaded files, snapshots, analyses and decisions are encrypted with AES-256-GCM
  under the project's own key, which is stored wrapped by the passphrase key. Ciphertext is bound to its place in the database.
- **Deleting a project destroys its key** and removes its rows.
- **Collectors only read.** The HTTP client can send GET requests, and POST only to a token endpoint. It refuses any URL outside the hosts
  configured on the connector, so a paging link cannot carry credentials elsewhere.
- **Secrets in collected configuration are replaced by `[REDACTED]`** before storage (client secrets, bind passwords, signing keys, hook credentials).
- **Minimal personal data.** Per user: id, login, mail, status, source, last sign-in. Sign-in events are aggregated per application; no event is stored.
- **Tamper evidence.** Every snapshot item has a SHA-256 in the manifest; the analyzer refuses a snapshot that does not match.
- **Web hardening.** HttpOnly SameSite=Strict session cookie, a required custom header on every state-changing request, strict Content-Security-Policy,
  no external resources, login throttling shared across instances, 30-minute idle timeout, 12-hour session limit.
- **Audit trail** per project (who is not recorded: there is one shared login).

What it does not do: per-user accounts and roles, single sign-on to the workbench itself, key storage in an HSM or key vault.

## Access each connector needs

| Platform | Read-only access |
| --- | --- |
| Okta | API service app with a key (private_key_jwt, DPoP off), the `okta.*.read` scopes, Read-only Administrator role. Or an API token of a Read-only Administrator. |
| Keycloak | Confidential client with a service account holding `view-realm`, `view-users`, `view-clients`, `view-identity-providers`, `view-events` of `realm-management`. One connector per realm. |
| PingFederate | Local admin account with the Auditor role. Upload the `audit.log` files of every engine node for usage. |
| PingOne | Worker application with read-only roles (Environment Admin read-only where available, Identity Data Read Only). One connector per environment. |
| OneLogin | API credential with scope Read All. |
| Entra ID | App registration with Graph application permissions `User.Read.All`, `Domain.Read.All`, `Organization.Read.All`, `Application.Read.All`; optional `Policy.Read.All`. |

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q                                             # server mode, SQLite
WB_TEST_MODE=serverless WB_TEST_DB=postgres python -m pytest tests -q   # as on Vercel; needs a local Postgres (WB_TEST_PG)
```

22 tests, about 195 assertions, 40 s per run. All four combinations pass: server or serverless mode, SQLite or Postgres 16.
The suite starts three mock servers (Okta; Keycloak, PingFederate, PingOne and OneLogin; Microsoft Graph) and drives the real application:
five platforms in four projects, results compared with the mocks' ground truth, no write request sent, nothing readable in the database,
planted secrets absent from decrypted snapshots, project isolation, tamper detection, tracking, exports, drift, pruning, cancellation,
deletion, passphrase change, restart, lock, two instances sharing only the database, and the network rules of a public deployment.

## Layout

```
workbench/
  main.py          HTTP API and static UI
  service.py       vault state, projects, connectors, runs, analyses, exports
  vault.py         encryption
  store.py         SQLite
  httpc.py         read-only HTTP client
  snapshot.py      snapshot and manifest
  analyzer.py      platform-neutral analysis
  report.py        workbook, findings report, evidence pack
  core.py          inventory model, redaction, default scoring
  collectors/      okta, keycloak, pingfederate, pingone, onelogin, entra
  static/          single-page UI (no framework, no external resources)
tests/             end-to-end tests and mock tenants
```

Adding a platform: one module in `collectors/` with a `Connector` class (fields, `test`, `collect`) and a `normalize` function that fills
the inventory model in `core.py`. The analyzer, the UI and the reports need no change.

## Known limits

- Effort days per tier are placeholders (`effortDays.calibrated: false`) until calibrated on real engagements. Set them per project under Settings.
- Okta: DPoP-bound tokens are not implemented; Workflows cannot be exported through the API.
- Keycloak: client roles are not collected; one realm per connector.
- PingFederate: usage needs the audit log files in the default pipe-delimited layout; OGNL expressions are counted, not parsed.
- PingOne: DaVinci flows are not collected.
- OneLogin: user security policies are not exposed by the API and are captured by hand.
- Snapshots are held in memory while a collection runs. Very large tenants (several hundred thousand users) need a streaming writer.
- The last five snapshots per connector are kept; older ones keep their manifest only.
