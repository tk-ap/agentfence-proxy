# AgentFence — MCP Proxy Scaffold

A working, runnable first cut of the "drop-in" containment-verification
layer: a proxy that sits between an agent and its MCP tool servers,
enforces a declared policy, and produces a signed evidence trail.

No external dependencies — runs on plain Node.js (v18+) so you can try
it right now without `npm install`. That's a scaffolding choice, not a
production one; see "What's real vs. stubbed" below.

## Try it

```bash
npm run demo    # or: node test/run-demo.js  — local (stdio) end-to-end walkthrough
npm run stress  # or: node test/stress-test.js — HTTP transport: concurrency, hostile input, flood
node test/probe-ci-check.js  # adversarial probe gate — fails the build on any missed attack
```

`run-demo.js` spawns the proxy, plus two mock downstream MCP servers
(`docs`, `web`), and drives the proxy the way an agent's MCP client
would: listing tools, making an allowed call, making a blocked call
(egress outside the allowlist), attempting to reach an undeclared tool
("chained escape" — a tool that exists on the live server but isn't in
policy, the classic prompt-injection-finds-a-side-door scenario), and
pulling a drift report. It ends by re-verifying the evidence log's
hash chain from scratch.

`stress-test.js` brings the proxy up over **HTTP** (see below) and
runs three scenarios: 25 concurrent sessions each making a mixed
sequence of allowed/blocked calls (checked for correctness and timed
for latency percentiles), a battery of hostile/malformed requests
(oversized bodies, malformed JSON, missing session IDs, path-traversal-
ish tool names, mixed-validity batches), and a 300-call concurrent
flood against the evidence log — followed by re-verifying the evidence
chain to confirm nothing corrupted under real concurrency. It found
and fixed two real bugs during development; see "Bugs found by
stress-testing" below.

### Run the HTTP transport directly

```bash
AGENTFENCE_TRANSPORT=http AGENTFENCE_PORT=8787 node src/index.js
```

```bash
curl -X POST http://localhost:8787/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
# -> Mcp-Session-Id header in the response; pass it back on subsequent calls
```

## How it fits together

```
   agent's MCP client
          │  (stdio, JSON-RPC)
          ▼
  ┌─────────────────┐
  │   ProxyServer    │  src/proxy-server.js
  │  policy check ───┼──► src/policy.js       (declared vs effective)
  │  evidence log  ──┼──► src/evidence.js      (hash-chained, signed)
  └───────┬──────────┘
          │  (spawns + speaks MCP to each)
   ┌──────┴───────┐
   ▼              ▼
DownstreamClient  DownstreamClient   src/downstream-client.js
   │                  │
mock-servers/     mock-servers/
docs-server.js    web-server.js
```

- **`src/jsonrpc.js`** — line-delimited JSON-RPC framing (MCP's stdio
  transport). Both the proxy's "server-facing-the-agent" side and
  "client-facing-downstream" side reuse this.
- **`src/downstream-client.js`** — spawns and talks to one real (or
  mock) MCP tool server.
- **`src/policy.js`** — the two claims on the landing page, as code:
  - `evaluateCall()` — is this specific tool call in-policy right now?
  - `diffPermissions()` — do the live downstream servers expose
    anything the declared policy doesn't know about (or vice versa)?
- **`src/evidence.js`** — append-only, hash-chained, HMAC-signed JSONL.
  `EvidenceLog.verify()` re-derives every hash and signature and
  confirms nothing was altered or removed.
- **`src/proxy-server.js`** — transport-agnostic core: exposes
  `handleMessage(msg)` and is fed by either transport below.
  `tools/list` returns a flattened, declared-tagged tool set;
  `tools/call` is checked against policy before (maybe) being
  forwarded; every decision is logged. Also exposes a non-standard
  `agentfence/drift` method for CI/operators to pull the current drift
  report on demand.
- **`src/http-transport.js`** — Streamable HTTP transport (MCP spec
  2025-03-26): single `/mcp` endpoint, `POST` for messages, session
  management via `Mcp-Session-Id`, Origin/bearer-token checks, a
  request body size cap. This is what lets the proxy front a *hosted*
  agent instead of only a local stdio subprocess.
- **`src/prober.js`** — generates adversarial *and* control probes
  from the live policy + drift state (not a hardcoded list — it
  regenerates itself as `policy.json` changes): undeclared-tool
  access, egress-allowlist bypass tricks (userinfo tricks, typosquats,
  cloud-metadata SSRF, type confusion), path-traversal bypass
  attempts, plus legitimate "control" calls that must NOT be blocked
  (a prober that blocks everything trivially "passes" otherwise).
  `agentfence/probe` runs the battery through the *exact same*
  `_handleToolCall()` path real traffic takes, tags every probe
  `source:'probe'` in the evidence log, and returns a containment
  scorecard.
- **`test/probe-ci-check.js`** — the "gate and prove" story made
  literal: runs the probe battery standalone and fails the build
  (exit code 1) on any missed attack, any false positive, or a broken
  evidence chain. Wired into `.github/workflows/test.yml`.
- **`src/demo-api.js`** + **`src/rate-limiter.js`** — the *public*
  surface, `/demo/*`, meant to be called directly from the marketing
  site's browser JS. A different trust boundary from `/mcp`: CORS
  locked to an explicit origin allowlist, per-IP rate limited, and
  every probe run uses a fresh `InMemoryEvidenceLog` (real hash-
  chained, signed evidence returned in the response — proving the
  same claim the customer-facing evidence log proves — but discarded
  after the response, never touching the durable audit trail).
  Routes: `GET /demo/health`, `GET /demo/attacks` (lists probe IDs for
  a picker widget), `GET /demo/probe` (runs the full battery, returns
  a scorecard), `POST /demo/try-attack {attackId}` (runs one named
  attack, returns whether it was blocked plus its evidence hash).
- **`render.yaml`** — Render blueprint: Node web service running
  `npm run start:http`, with the demo-origin allowlist and rate limit
  as configurable env vars, and real random secrets generated for
  evidence signing (not the dev-only placeholders in code).
- **`config/policy.json`** — the declared policy for the demo agent.
- **`config/servers.json`** — which downstream servers to spawn.
- **`mock-servers/`** — fake MCP tool servers standing in for real
  ones (`docs`, `web`, and `sandbox` — the last one declared and
  path-constrained specifically so the path-traversal probe has a
  real rule to attack), so the whole loop is testable with zero
  external infrastructure or network access.

## A real bug the probe engine found on its first run

Worth keeping visible, same as the HTTP stress-testing bugs above —
this is the entire point of the exercise. The `path-prefix-allowlist`
constraint originally checked containment with a plain
`value.startsWith(prefix)`. That's bypassable: the string
`"/workspace/../../../etc/passwd"` starts with `"/workspace/"`
*lexically* while resolving somewhere else entirely. The very first
run of `agentfence/probe` against `sandbox.write` caught it —
containment score 91%, one critical miss. Fixed in `src/policy.js` by
resolving the path (collapsing `..`, `.`, and repeated slashes) with
`path.posix.normalize()` before comparing against the allowed prefix,
then re-running to confirm 100% containment with zero new false
positives on the legitimate-write control probe.

One advisory the probe engine surfaces but does **not** fail the
build on: the domain-allowlist's suffix match currently permits *any*
subdomain of an allowed host (`evil.docs.internal.example.com` would
pass). That's arguably intentional (wildcard trust under a domain you
control) rather than a bug — flagged for a human to confirm the
policy author meant it, not auto-blocked.

## Bugs found by stress-testing

Worth keeping visible rather than quietly fixing, since it's the point
of the exercise:

1. **False "unknown tool" blocks under concurrency.** The proxy only
   learns what tools exist as a side effect of `tools/list`. A client
   (or test) that calls `tools/call` without listing first got
   incorrectly blocked — a false positive, which is a worse failure
   mode for a containment product than the alternative. Fixed by
   making tool resolution self-healing: on a lookup miss, refresh once
   from downstream before concluding the tool is genuinely unknown
   (`src/proxy-server.js`).
2. **Oversized request bodies caused `ECONNRESET` instead of a clean
   `413`.** The body-size guard destroyed the socket the instant the
   cap was crossed, racing against the client still writing. Fixed by
   draining (and dropping) further bytes without destroying the
   connection, then responding `413` once the request actually ends
   (`src/http-transport.js`).

Both were real defects, not test artifacts — worth remembering as the
policy/probe layer gets more complex: this class of bug (transport-
level races, "haven't-learned-the-world-yet" false positives) is
exactly what a containment product itself can't afford to ship.

## What's real vs. stubbed

**Real and load-bearing:**
- The policy engine's two core checks (undeclared-tool blocking,
  argument-level constraints like egress allowlists) run against
  actual tool-call traffic, not a mockup.
- The evidence log is genuinely tamper-evident — `verify()` will
  catch an edited or truncated record, try it: hand-edit a line in
  `logs/demo-evidence.jsonl` and rerun the demo's verify step.
- The drift check compares live server state to declared policy for
  real, by actually calling `tools/list` on every downstream server.

**Stubbed / next steps:**
- **Transport**: stdio and Streamable HTTP (single `/mcp` endpoint,
  POST + session headers) are both implemented and stress-tested. The
  optional server-push half of Streamable HTTP (a standalone `GET`
  SSE stream for server-initiated notifications) is not — this proxy
  has no server-initiated messages yet, so `GET /mcp` correctly
  returns `405` per spec rather than faking a stream it'd never write
  to. Add it once `agentfence/drift`-style push notifications are
  wanted, e.g. so an operator dashboard can see drift the moment it
  happens instead of polling.
- **Auth**: `HttpTransport` has Origin-allowlist and bearer-token hooks
  wired in and off by default (`AGENTFENCE_ALLOWED_ORIGINS`,
  `AGENTFENCE_BEARER_TOKEN`) — real OAuth 2.1 (what the MCP spec
  actually wants for production remote servers) isn't built.
- **Session persistence**: sessions live in an in-memory `Map` on one
  process. Fine for one proxy instance; a horizontally-scaled
  deployment needs shared session storage (Redis, etc).
- **Protocol coverage**: only `initialize`, `tools/list`, `tools/call`
  are handled. Real MCP servers also expose resources, prompts,
  sampling, and notifications — currently dropped.
- **Signing**: HMAC with a shared secret (`AGENTFENCE_SIGNING_SECRET`
  env var) stands in for real signing (KMS/HSM-backed asymmetric
  signatures) — the record format won't need to change, just how
  `signature` is produced.
- **Policy language**: two constraint types exist
  (`domain-allowlist`, `path-prefix-allowlist`). A real product needs
  a much richer language, plus a way to author policy from something
  less brittle than hand-written JSON.
- **Probe engine next steps**: the current battery is generated from
  policy shape (declared rules + drift), not from real attack
  telemetry. Natural extensions: derive new probe variants from an
  actual incident/transcript, and run continuously (on a schedule or
  on every policy change) instead of only in CI.
- **Swap-in of the real SDK**: `DownstreamClient` and the proxy-facing
  side both talk plain JSON-RPC deliberately, so replacing them with
  `@modelcontextprotocol/sdk`'s client/server transports later is a
  contained change behind the same interfaces — useful once you have
  network access to `npm install` it.

## Environment variables

- `AGENTFENCE_CONFIG_DIR` — override the config directory (default: `./config`)
- `AGENTFENCE_EVIDENCE_LOG` — override the (durable, customer-facing) evidence log path (default: `./logs/evidence.jsonl`)
- `AGENTFENCE_SIGNING_SECRET` — HMAC secret for evidence signing (default: dev-only placeholder — set a real one outside local testing)
- `AGENTFENCE_TRANSPORT` — `stdio` (default) or `http`
- `AGENTFENCE_PORT` / `PORT` — HTTP port (Render and most PaaS set `PORT` automatically; `AGENTFENCE_PORT` takes precedence if both are set)
- `AGENTFENCE_ALLOWED_ORIGINS` — comma-separated Origin allowlist for `/mcp` (default: unrestricted — fine for non-browser agent clients)
- `AGENTFENCE_BEARER_TOKEN` — if set, `/mcp` requires `Authorization: Bearer <token>`
- `AGENTFENCE_DEMO_ALLOWED_ORIGINS` — comma-separated Origin allowlist for `/demo/*` (default: `*` — **set this to your real site origin before going live**; the server logs a warning on startup if it's unset)
- `AGENTFENCE_DEMO_RATE_MAX` / `AGENTFENCE_DEMO_RATE_WINDOW_MS` — per-IP rate limit for `/demo/*` (default: 20 requests / 60s)
- `AGENTFENCE_DEMO_SIGNING_SECRET` — HMAC secret for the ephemeral demo evidence log (separate from the real one on purpose — never share these)

## Deploying (Render)

```bash
npm install -g nothing-needed   # no build deps — this repo has zero external packages
```

1. Push this repo to GitHub.
2. On Render: New → Blueprint → point at the repo. `render.yaml` sets
   everything up (Node web service, `npm run start:http`, env vars for
   the demo origin allowlist and rate limit).
3. **Before linking this from the live site**, edit
   `AGENTFENCE_DEMO_ALLOWED_ORIGINS` in the Render dashboard to your
   real landing-page origin (e.g. `https://agentfence.madethis.app`)
   — the blueprint ships with that value, but confirm it matches
   exactly (scheme + host, no trailing slash) or the browser will
   silently refuse to read the response.
4. From the site's JS: `fetch('https://<your-render-service>.onrender.com/demo/probe')` to run the live scorecard, or `POST /demo/try-attack` with `{"attackId": "..."}` (see `GET /demo/attacks` for valid IDs) for an interactive "pick an attack, watch it get blocked" widget.
