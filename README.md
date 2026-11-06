# webaudit

A concurrent website health and compliance monitor. Give it a list of sites and it
checks each one's DNS, domain registration, TLS certificate, security headers, redirect
path, links and accidentally public files, then writes JSON reports and an HTML summary.

> **Only scan sites you own or are authorized to test.** The checks are read-only, but
> the exposure check requests paths such as `/.env`, which shows up in server logs and
> can trigger security alerts.

## Setup

Requires Python 3.11 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Dashboard (GUI)

Prefer a graphical interface? Launch the local web dashboard:

```powershell
webaudit gui
```

It starts a small server on `http://127.0.0.1:8765`, opens your browser, and gives you
target entry, check selection, options, live progress, a results table with expandable
findings, links to the HTML reports, and a history of past scans. Keep the terminal
window open while you use it; press Ctrl+C to stop.

Options: `--port 9000`, `--host 127.0.0.1`, `-o reports`, `--no-browser`.

The dashboard is for local use only. It binds to `127.0.0.1`, requires a one-time token
(handed out in the URL it opens) on every API call, and rejects non-local hosts — so
other sites open in your browser, and other machines, can't drive it. Don't bind it to a
public address: anyone who could reach it could make the tool scan arbitrary hosts.

## Usage (command line)

```powershell
# Audit a list, 3 sites at a time
webaudit scan targets.txt --concurrency 3

# Audit single sites
webaudit scan -u example.com -u https://example.org/

# Tighter timeouts, gentler on the servers
webaudit scan targets.txt --timeout 5 --site-timeout 60 --per-site-requests 2 --delay 0.5

# Choose checks. Traceroute is off by default because it is slow.
webaudit scan targets.txt --only tls,headers
webaudit scan targets.txt --skip exposure --traceroute

# For CI: exit with code 1 if anything high or critical is found
webaudit scan targets.txt --fail-on high
```

`webaudit list-checks` shows every check, and `webaudit scan --help` shows every option.
See `targets.example.txt` for the file format. Sites without a scheme try https first,
then http.

| Exit code | Meaning |
|---|---|
| 0 | Run finished |
| 1 | A finding met the `--fail-on` threshold |
| 2 | Bad usage, such as no valid targets or an unknown check |
| 130 | Interrupted with Ctrl-C (finished sites are still saved) |

## Checks

| Check | What it covers |
|---|---|
| `dns` | A/AAAA resolution, nameservers, CAA, SPF, DMARC |
| `whois` | Registrar and domain expiry, using RDAP with a WHOIS (port 43) fallback |
| `tls` | Trust chain, expiry, hostname match, protocol, weak keys and signatures |
| `headers` | HSTS, CSP quality, X-Frame-Options, nosniff, Referrer-Policy, version leaks, cookie flags |
| `routing` | Availability, the full redirect chain, https enforcement, https-to-http downgrades |
| `links` | Crawls up to `--max-pages` same-origin pages and verifies up to `--max-links` links |
| `exposure` | 24 sensitive paths, including `.env`, `.env.example`, `.git`, SQL dumps and config backups |
| `traceroute` | Network path through the system `tracert` or `traceroute` (opt-in) |

## Reports

Each run gets its own folder, so earlier reports are never overwritten:

```
reports/20261104-191847/
  summary.html        Open this one. Self-contained, worst sites first.
  summary.json        The same data for scripts
  sites/<site>.json   Full detail for each site, saved as soon as it finishes
```

Sites start at 100 and lose points per finding: critical 40, high 15, medium 6, low 2.
Any critical finding caps the score at 49, which is a grade of F. Grades are A (90+),
B (80+), C (70+), D (60+) and F.

A site's status is one of:

- `completed`: every check ran
- `partial`: a check timed out or crashed, so the score may be missing issues
- `unreachable`: the site could not be fetched
- `failed`: the audit itself failed

Reports describe weaknesses in real sites, so treat them as sensitive. `reports/` is in
`.gitignore`.

## Architecture

```
targets.py    Parse and validate the target list
engine.py     Worker pool over a queue; time limits at every level
context.py    Per-site state: throttled HTTP, private-network guard, cached homepage
checks/       One module per check, registered with a decorator
reporting.py  JSON and HTML output
cli.py        Arguments, progress display, exit codes
web/          The dashboard: Starlette app (app.py), scan runner (runner.py),
              browser launcher (server.py), and the single-page UI under static/
```

The dashboard reuses the exact same engine, checks and reporting as the CLI — it only
adds a thin async layer that streams progress to the browser and serves the reports.

**Concurrency.** The queue is filled before the workers start, and `--concurrency`
workers drain it, so a worker can never block waiting for more work. Within a site, all
checks run at once, sharing a limit of `--per-site-requests` HTTP requests.

**Nothing can hang.** Time limits are nested:

1. Network phases are limited by `--timeout`.
2. Each request gets a total deadline of twice that, which catches servers that drip
   bytes slowly enough to dodge a read timeout.
3. Each check is limited by `--check-timeout`.
4. Each site is limited by `--site-timeout`.

A check that hits a limit keeps whatever data it had already gathered.

**Failure isolation.** A check that crashes or times out is recorded in its own result.
The site's other checks and all other sites carry on.

**Keep the event loop free.** Everything shares one event loop, so blocking it delays
every site's timers and can make healthy sites look down. The CA bundle takes over a
second to parse, so it is loaded once per run, in a thread, before any site starts.
`test_tls_checks_do_not_stall_the_event_loop` guards this.

**Safety:**

- *File contents are never stored.* The exposure check keeps only the path and sample
  size, so reports don't become a second copy of a leaked secret. Cookie values aren't
  stored either.
- *No false alarms from catch-all sites.* A file only counts as exposed if its content
  matches a signature, so sites that answer 200 for everything don't trigger findings.
- *Private-network guard.* A public site can't use links or redirects to make the
  scanner call `localhost`, your LAN or a cloud metadata address. Scanning an internal
  target directly is still allowed.
- *Safe HTML.* Scanned content is escaped, and the report's own CSP blocks scripts.

### Adding a check

Create a module in `webaudit/checks/` and import it in `checks/__init__.py`:

```python
@register("robots", "Checks that robots.txt exists")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    home = await ctx.require_home()
    ...
    result.add(Severity.LOW, "Title", "Detail", "Recommendation")
```

## Limitations

- This is a configuration audit, not a penetration test. It doesn't look for
  application flaws such as SQL injection or XSS.
- The TLS check sees the protocol the server prefers. It doesn't list every protocol
  and cipher the server would accept.
- Links are checked with a plain HTTP client, so links created by JavaScript aren't
  found. Sites with bot protection may give different answers than they give browsers.
  Responses such as 403 and 429 are listed as `unverified`, not broken.
- Domain names are sent to `rdap.org` for registration lookups. Use `--skip whois` to
  avoid that.
- The private-network guard checks DNS before each request, so a hostile DNS server
  could still answer differently at connection time (DNS rebinding).
- Traceroute results are limited to 20 hops, and many networks drop the probes.

## Tests

```powershell
python -m pytest
```

The suite runs against real local servers, including TLS servers with generated
expired, mismatched and self-signed certificates, and a server that accepts connections
but never answers. It needs no internet access.
