# Ghostfolio on a NAS

Self-host [Ghostfolio](https://github.com/ghostfolio/ghostfolio) on a home NAS, load a sample portfolio into it, and connect an MCP server so an AI assistant can read it.

The sample data is synthetic: a demo user's activity history priced from public market data. No real holdings, balances, or account identifiers appear anywhere in this repository.

Scope: a working setup path with the parts that are not obvious from the upstream README written down — compose files, first run, a sample import, an MCP server, and a bounded procedure for letting an assistant record activities.

---

## ⚠️ Read this first: never hand an assistant a raw statement

Everything in this repository that involves an AI assistant assumes one thing has already happened: **the document it reads has been sanitized on your machine, with a names file, before it goes anywhere.**

A brokerage statement or trade confirmation carries your legal name, account numbers, address, phone number and sometimes your national identifier. A cloud model does not need any of that to turn a confirmation into a Ghostfolio activity — it needs the symbol, the quantity, the price, the date and the total. Sending the rest is a leak with no upside. And a PDF with black boxes drawn on it is **not** redacted: the text is still in the file.

[`sanitize/`](sanitize/) contains a script that extracts a PDF's text, replaces identifiers with stable pseudonyms (`[ACCT-7f3a]` stays `[ACCT-7f3a]` on every page), throws the PDF container away, and re-scans its own output. The part that matters most is the **names file**: patterns catch account numbers, but only you can tell the script that *Homer Simpson* is you and *Evergreen Terrace* is your street.

```bash
cp sanitize/pii-names.example.txt .local/pii-names.txt     # then replace every fictional entry with your own
python sanitize/sanitize_pdf.py confirmation.pdf --names .local/pii-names.txt --strict
# read confirmation.sanitized.md BEFORE you paste it anywhere
```

Full instructions, the trust model and what the script cannot do: [`sanitize/README.md`](sanitize/README.md). The same kit ships in the companion [firefly-nas-setup](https://github.com/ANPC86/firefly-nas-setup) repository for bank statements.

---

## 0. Hardware and platform

Measured on the reference setup, not taken from a spec sheet.

| | Reference setup | Minimum that would work |
|---|---|---|
| Host | **UGREEN DXP4800 Plus** (Intel x86-64, 6 threads, 40 GB RAM) running UGOS Pro (Debian 12 base) with Docker 29 | Any x86-64 or arm64 machine that runs Docker Compose — a NAS with a Docker app, a mini PC, a Raspberry Pi 4/5 with 4 GB |
| RAM, steady state | Ghostfolio app **0.3–1.3 GB** (grows with the price cache), Postgres ~50 MB, Redis ~15 MB | 2 GB free for the three containers |
| Disk | Images ~1.5 GB (`ghostfolio` 940 MB, `postgres` 460 MB, `redis` 150 MB); the database stays small — daily dumps of several years of activity are ~70 MB compressed | 5 GB |
| CPU | Idle most of the time; short bursts when gathering market data or recomputing performance | 2 cores |
| Network | Outbound HTTPS to Yahoo Finance (or your chosen data provider); no inbound ports needed for LAN use | — |

A UGREEN NAS with Docker is the suggested route if you are buying hardware for this: the Docker app is built in, it is on all day anyway, and the same box can hold the backup sidecar and the reverse proxy. Nothing here is UGREEN-specific, though — the compose file is upstream's.

---

## 1. Setting up Ghostfolio

Verified against Ghostfolio **3.63.0** (2026-08-28). Upstream's own instructions are in the [Self-hosting](https://github.com/ghostfolio/ghostfolio#self-hosting) section of its README; what follows is the shorter path plus the gotchas.

### 1.1 Compose stack

[`compose/ghostfolio/`](compose/ghostfolio/) holds a ready-to-run stack — Ghostfolio, Postgres 18, Redis, and an opt-in daily backup sidecar — derived from upstream's `docker/docker-compose.yml` with pinned tags. Copy its `.env.example` to `.env` and fill in the four random values. The minimum `.env`:

```dotenv
COMPOSE_PROJECT_NAME=ghostfolio
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=<random>
POSTGRES_DB=ghostfolio-db
POSTGRES_USER=user
POSTGRES_PASSWORD=<random>
ACCESS_TOKEN_SALT=<random 64 chars>
JWT_SECRET_KEY=<random 64 chars>
DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?connect_timeout=300
```

```bash
cd compose/ghostfolio && cp .env.example .env    # edit the <random> values
docker compose --profile backup up -d            # omit --profile backup to skip the dump sidecar
curl -f http://localhost:3333/api/v1/health      # {"status":"OK"}
```

Things worth knowing before the first `up`:

| Topic | What to do | Why |
|---|---|---|
| `ACCESS_TOKEN_SALT` / `JWT_SECRET_KEY` | Generate real random values **before** first start. | Every user's security token is derived from the salt. Changing it later invalidates all logins; a placeholder string left in place is a permanent weakness. |
| Postgres major version | Pin the tag (`postgres:15-alpine`, or 18 if you are starting fresh). | Postgres does not upgrade data directories across major versions on its own. Note `postgres:18` mounts data at `/var/lib/postgresql`, not the pre-18 `/var/lib/postgresql/data`. |
| Backups | Run a dump sidecar (e.g. `prodrigestivill/postgres-backup-local`) against the database. | A daily `ghostfolio-latest.sql.gz` is also what lets you stand up an isolated **analysis clone** later (see §4) without touching production. |
| Auto-update | Decide explicitly. | Ghostfolio moves fast (3.59 → 3.63 in one week of August 2026). If anything else depends on its API shape or its database schema, pin the tag on that dependent. |
| Reverse proxy | Set `ROOT_URL` to the public hostname if you use the built-in MCP or OIDC. | Its hostname is the allowed host/origin for browser clients. |

### 1.2 First run

1. Open `http://<host>:3333`, choose **Get started → Create account**. The first user becomes admin. Ghostfolio hands you a **security token**; that token *is* the login — store it in a password manager, there is no reset path.
2. **Admin Control → Settings**: set the base currency (`CAD` here) and confirm the data provider. Yahoo Finance is the default for equities and ETFs; Canadian listings resolve as `HDIV.TO` (TSX) and `QDAY.NE` (Cboe Canada / NEO).
3. **Admin Control → Users** to create a second, non-admin user for demos. That user gets its own security token; use it — never the admin token — for anything an AI tool or a screenshot will see.
4. Under the demo user: **Accounts → Add account** (platform, currency). Activities are booked against an account, so this comes before any import.

### 1.3 Loading the sample portfolio

[`fixtures/demo-activities.import.json`](fixtures/demo-activities.import.json) is a sample activity history in Ghostfolio's import format — 374 BUY/SELL activities across 29 Canadian-listed ETFs and stocks, 2023-12-19 to 2026-08-28. Import it under the demo user via **Portfolio → Activities → Import**, choose the account, and confirm the preview. The same file also works against the API:

```bash
# JWT from the security token
JWT=$(curl -s -X POST http://localhost:3333/api/v1/auth/anonymous \
      -H 'Content-Type: application/json' -d '{"accessToken":"<demo-user-token>"}' | jq -r .authToken)
# Dry run first
curl -s -X POST "http://localhost:3333/api/v1/import?dryRun=true" \
     -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
     -d @fixtures/demo-activities.import.json
```

The import needs each activity's `accountId` when sent through the API; the UI's account picker adds it for you. Symbols use the Yahoo suffixes above, and prices are in CAD.

After import, **Admin Control → Market Data** shows one row per symbol. Ghostfolio gathers history on its own schedule; if a chart looks empty in the first hour, use *Gather all data* rather than re-importing.

### 1.4 Screenshot tour

Captured from the demo user with [`tools/screenshots.mjs`](tools/screenshots.mjs) (Playwright; it logs in through Ghostfolio's `/en/auth/<jwt>` route, so the security token never touches the browser, and takes full-page captures). Every value shown comes from the synthetic sample portfolio.

| | |
|---|---|
| [Holdings](docs/screenshots/02-holdings.png) — positions with quantity, value, allocation and performance | [Allocations](docs/screenshots/05-allocations.png) — platform, currency, asset class, per-holding |
| [Overview](docs/screenshots/01-home.png) and [Summary](docs/screenshots/03-summary.png) | [Activities](docs/screenshots/06-activities.png) — the 374 imported BUY/SELL rows |
| [X-ray](docs/screenshots/07-xray.png) — Ghostfolio's built-in concentration and cluster-risk rules | [FIRE](docs/screenshots/08-fire.png) — the 4%-rule calculator |
| [Accounts](docs/screenshots/09-accounts.png) | [Settings](docs/screenshots/10-settings.png) and [Access](docs/screenshots/11-access.png) — where an MCP access is created |

Run it yourself: `GF_URL=https://your-ghostfolio GF_JWT_CMD="<command printing a JWT>" node tools/screenshots.mjs` (set `PLAYWRIGHT_MODULE` to an existing Playwright install's `index.mjs` if you do not want a local `npm install playwright`).

---

## 2. Connecting an AI assistant (MCP)

Two routes exist as of 3.63.0. They are not equivalent.

| | Built-in (`ENABLE_FEATURE_MCP=true`) | [`mhajder/ghostfolio-mcp`](https://github.com/mhajder/ghostfolio-mcp) sidecar |
|---|---|---|
| Ships | Inside the Ghostfolio API at `/mcp` (Streamable HTTP), since 3.59.1 | Separate container, stdio or HTTP |
| Tools | `get-portfolio`, `get-activities` | ~36: accounts, activities, holdings, performance, market data, watchlist, import/export |
| Reads money values | **No** — the MCP access type excludes `portfolio:read:values`; quantities, fees and totals are withheld | Yes, with the user's security token |
| Writes | No, by design | Yes unless `READ_ONLY_MODE=true` |
| Credential | An **Access** of type MCP created under *My Ghostfolio → Access*; that access id is the bearer | The user's security token in the container env, plus its own bearer for clients |

For a demo user the sidecar in read-only mode is the practical choice: an assistant can actually see the numbers it is asked about, and the account cannot be altered. [`compose/ghostfolio-mcp/`](compose/ghostfolio-mcp/) is a ready-to-run stack for it; the configuration that matters:

```dotenv
GHOSTFOLIO_URL=http://ghostfolio:3333      # must include the scheme — without it every tool call fails with
                                           # "Request URL is missing an 'http://' or 'https://' protocol"
GHOSTFOLIO_TOKEN=<demo user security token>
READ_ONLY_MODE=true
MCP_TRANSPORT=http                         # or stdio
MCP_HTTP_HOST=0.0.0.0
MCP_HTTP_PORT=8001
MCP_HTTP_BEARER_TOKEN=<random>              # what clients present
FASTMCP_HTTP_ALLOWED_HOSTS=["mcp.example.lan","127.0.0.1:8001"]   # when behind a reverse proxy
```

Publish the container's port like any other service (`ports: ["8444:8001"]` on the Ghostfolio compose network) and register it in Claude Code with `claude mcp add --transport http ghostfolio-demo http://<nas>:8444/mcp --header "Authorization: Bearer <token>"`. A reverse-proxy hostname is optional; if you use one, add it to `FASTMCP_HTTP_ALLOWED_HOSTS`. Keep the production user's MCP and the demo user's MCP as two distinct servers with distinct names; an assistant that is "pointed at Ghostfolio" will otherwise read the wrong account without any error.

---

## 3. Letting an AI assistant record activities

Reading is the easy half. Recording a trade or a dividend the assistant was told about is where an unconstrained tool list goes wrong — first symbol match taken, a fee invented to make a total reconcile, the same dividend written twice. [`agent/`](agent/) packages a bounded procedure for it: resolve from what is held, validate the arithmetic, check for duplicates, show the proposed record, **write only on explicit authorisation**, verify from the record. It ships as a Claude Code sub-agent and skill, and as a system prompt for any other MCP-capable assistant. Setup steps are in [`agent/README.md`](agent/README.md).

The input to that procedure is usually a broker's email or PDF. Run a PDF through [`sanitize/`](sanitize/) first; the procedure resolves the account by its Ghostfolio name, which you supply, so the sanitized text is all the assistant needs.

---

## Support

If this project helps you, sponsorship is appreciated but never required.

<a href="https://www.buymeacoffee.com/ANPCAI" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" width="180">
</a>

---

## Layout

```
sanitize/                              PDF → pseudonymised text, with a names file; READ ITS README FIRST
compose/ghostfolio/                    Ghostfolio + Postgres + Redis (+ backup) compose stack
compose/ghostfolio-mcp/                mhajder/ghostfolio-mcp compose stack, one per Ghostfolio user
fixtures/demo-holdings.json            the sample portfolio's positions and weights
fixtures/demo-activities.import.json   its 374 activities in Ghostfolio import format
agent/                                 activity-recording procedure: Claude Code agent + skill, generic system prompt
tools/screenshots.mjs                  Playwright tour of a Ghostfolio user
docs/screenshots/                      the tour, captured from the demo user
```

License: MIT for the code in this repository. Ghostfolio is AGPL-3.0; nothing from it is vendored here.
