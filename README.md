# PromptShield AI

**Interactive LLM Prompt Injection Security Testing & Defense Platform**

> Part 4 of 4 — final polish pass: a completely redesigned premium
> landing page, a real dark-themed dropdown component fixing the
> white-panel readability bug, site-wide UI/accessibility consistency,
> and full integration verification. No API key required.

This platform is an educational / defensive security tool: it helps
people understand and test detection & defense strategies against
prompt injection attacks. It never executes real attacks against a
live model — the built-in AI provider is a deterministic, offline mock.

---

## Folder structure

```
PromptShield-AI/
├── app.py                  # Flask app factory + entrypoint
├── config.py                # Centralized configuration
├── extensions.py             # db / migrate singletons
├── requirements.txt
├── .env.example
│
├── models/                   # SQLAlchemy models (fixed DB contract)
│   ├── user.py
│   ├── security_test.py
│   ├── attack_scenario.py
│   └── security_event.py
│
├── routes/
│   ├── main_routes.py         # /api/health
│   ├── api_routes.py          # /api/analyze, /simulate, /detect, /defend, ...
│   └── page_routes.py         # HTML page routes
│
├── services/
│   ├── risk_engine.py         # signals -> risk score/level
│   ├── prompt_analyzer.py     # raw prompt -> signals
│   ├── detection_engine.py    # signals -> attack_type/difficulty
│   ├── policy_engine.py       # risk_level -> decision/defense_mode
│   └── ai_provider.py         # AIProvider interface + MockLLMProvider
│
├── database/
│   └── seed.py                 # seeds AttackScenario rows
│
├── templates/                  # Jinja2 templates, all extend base.html
├── static/css, static/js       # design system + page scripts
└── tests/
    └── test_basic.py
```

## Installation

```bash
cd PromptShield-AI
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

## Run

```bash
python app.py
```

Visit **http://127.0.0.1:5000**

The SQLite database (`promptshield.db`) is created automatically on
first run and seeded with 10 baseline attack scenarios.

## Testing

```bash
pytest
```

## What's implemented in Part 1

- Full application factory, config, models, blueprints
- Complete, fully-designed landing page (hero pipeline animation,
  attack-surface diagram, attack-type cards, defense-in-depth layers,
  "how it works" flow, animated metrics, final CTA)
- Shared layout/navbar used by every page (`base.html`)
- Placeholder pages (Dashboard, Simulator, Analytics, Research,
  History, Settings, Admin) sharing the same design system, ready for
  Parts 3-4 to build on without restructuring

## What's implemented in Part 2

**Full security pipeline**, run on every `/api/analyze` and
`/api/simulate` call:

```
INPUT VALIDATION -> PROMPT NORMALIZATION -> PROMPT ANALYZER ->
INJECTION DETECTOR -> RISK ENGINE -> MOCK LLM -> OUTPUT VALIDATOR ->
POLICY ENGINE -> FINAL DECISION -> AUDIT LOG
```

- **`services/prompt_analyzer.py`** — modular pattern analyzer across 8
  categories (instruction override, system-prompt reference, role
  manipulation, protected-info requests, context manipulation,
  encoding/obfuscation, tool/action escalation, multi-step behavior),
  each with its own 0-100 sub-score.
- **`services/detection_engine.py`** — four independent detectors
  (rule-based, heuristic, context-conflict, output-safety), shown
  individually and combined into one attack_type/difficulty verdict.
- **`services/risk_engine.py`** — weighted, configurable indicator
  aggregation into a 0-100 score across 5 bands: SAFE (0-20), LOW
  (21-40), MEDIUM (41-60), HIGH (61-80), CRITICAL (81-100), plus
  confidence and per-category recommendations.
- **`services/defense_engine.py`** *(new)* — the 4 defense modes
  (Disabled / Basic / Standard / Maximum) and the concrete layers each
  one runs (input filtering, normalization, context isolation, output
  validation, policy enforcement).
- **`services/output_validator.py`** *(new)* — analyzes the Mock LLM's
  response for safety status, policy compliance, information leakage,
  instruction-following risk, tool-abuse risk, and context
  manipulation.
- **`services/ai_provider.py`** — `MockLLMProvider` now behaves
  realistically: safe replies for benign prompts, refusals when an
  attack is detected and defenses are active, and a clearly-labeled
  simulated-unsafe reply when defenses are disabled — entirely local,
  no external calls.
- **API contract fulfilled**: `/api/analyze` (full pipeline + DB
  write), `/api/detect` (prompt-side detectors only), `/api/defend`
  (policy/defense assessment), `/api/simulate` (Mock LLM run, with an
  optional `compare: true` Before/After defense-OFF-vs-ON mode) — all
  with clean JSON error handling for empty/oversized/missing/invalid
  input.
- **Security Lab UI** (`/lab`) — three-column workspace: prompt editor
  (with scenario quick-load) on the left, the animated 8-stage
  pipeline plus an animated circular risk gauge in the center, and a
  threat-intelligence panel (per-detector scores, recommendations,
  and a full response analyzer) on the right, with a Before/After
  comparison view.
- Every completed analysis is still persisted to `SecurityTest` /
  `SecurityEvent` exactly per the Part 1 schema — no fields were
  added, renamed, or removed.

## Architecture notes for Parts 3-4

- Do not rename any model field, route, or file location.
- `services/` interfaces (`RiskEngine`, `PromptAnalyzer`,
  `DetectionEngine`, `PolicyEngine`, `DefenseEngine`, `OutputValidator`,
  `AIProvider`) are stable; extend their internals, not their public
  method signatures.
- `MockLLMProvider` remains the default; a real
  `OpenAICompatibleProvider` is stubbed in `services/ai_provider.py`
  and only activates if `OPENAI_API_KEY` is set — never required.
- Risk-engine thresholds and the default defense mode are configurable
  via `.env` (`RISK_THRESHOLD_*`, `DEFAULT_DEFENSE_MODE`) so Part 3's
  Settings page can persist them without code changes.

## What's implemented in Part 3

- **Dashboard (`/dashboard`)** — SOC-style landing view: five live stat
  cards (Total Tests, Threats Detected, Threats Blocked, High-Risk
  Events, Average Risk), five Chart.js charts (threats by attack type,
  risk distribution, attacks over time, defense effectiveness,
  detection method comparison), and a Recent Security Events table
  whose rows open a full detail modal. Nothing is hard-coded — every
  number comes from `GET /api/dashboard` and `GET /api/analytics`.
- **Attack Simulator (`/simulator`)** — scenario cards (name,
  description, difficulty, risk level, expected behavior, defense
  strategy) loaded from `GET /api/scenarios`, grouped into
  Basic/Medium/Advanced tabs by difficulty, each with a **RUN
  SIMULATION** button that calls `POST /api/simulate` and shows the
  result inline.
- **Analytics (`/analytics`)** — filter bar (attack type, risk level,
  defense mode, date range) that re-queries `GET /api/analytics` with
  query-string filters, five metric cards (Average Risk, Detection
  Rate, Block Rate, High-Risk Rate, Defense Effectiveness), and the
  same chart set as the Dashboard, filtered live.
- **History (`/history`)** — full `SecurityTest` table (ID, Time,
  Attack Type, Difficulty, Risk, Confidence, Defense, Decision) with
  prompt search, per-column filters, click-to-sort headers, and
  pagination, all driven by `GET /api/history` query params
  (`q`, `attack_type`, `risk_level`, `defense_mode`, `sort_by`,
  `sort_dir`, `page`, `page_size`). Row click opens the same shared
  detail modal as the Dashboard.
- **`GET /api/dashboard` / `/api/analytics` / `/api/history` /
  `/api/events`** — all rewritten to compute everything live from
  SQLite (never hard-coded): `/api/analytics` now returns
  `by_defense_mode`, `timeseries`, `detection_methods`, and a
  `metrics` block, plus accepts filters; `/api/history` and
  `/api/events` are now paginated and return a `meta` block alongside
  the existing `data` list, so older callers reading `data` directly
  still work unchanged.
- **Demo data seed** — `database/seed.py` gained
  `seed_demo_security_tests()`, which runs ~20 safe, clearly-labeled
  demonstration prompts through the *real* pipeline (not fabricated
  numbers) and backdates them across the last two weeks, so a fresh
  install already has a populated Dashboard/Analytics/History. Wired
  into `app.py`'s bootstrap alongside the existing scenario seeding.
- Shared additions: `static/js/charts.js` (Chart.js styling helpers),
  a shared detail modal (`base.html` + `PromptShieldUI.openTestModal`
  in `main.js`), and SOC/filters/table/modal/pagination styles added
  to `dashboard.css` so every app page (Lab included) shares one
  design language.
- **Integration verified**: every nav link (Landing → Security Lab,
  Dashboard, Simulator, Analytics, History, Research, Settings, Admin)
  resolves to a real page with no 404s; `python app.py`,
  `GET /api/health`, and `POST /api/analyze` all still work exactly as
  in Part 1/2.

## Architecture notes for Part 4

- Do not rename any model field, route, or file location.
- Same `services/` and API stability guarantees as above carry
  forward unchanged.
- `/api/settings` exposes and updates runtime policy/provider controls
  without changing the endpoint URL or method. Secret API keys are never
  returned or accepted through the browser settings form.

## What's implemented in Part 4

**A — Dropdown readability, fixed properly.** The reported bug (light
option text on a white panel inside the Security Lab's Attack
Type/Difficulty/Defense Mode/LLM Mode dropdowns) is a well-known
cross-browser limitation: most browsers don't reliably honor CSS
`background-color`/`color` on `<option>` elements, no matter how the
closed `<select>` is themed. Rather than patch around that, this adds:

- `static/js/dropdown.js` — a real custom dropdown component (new
  file) that wraps every `<select>` on the page in a fully dark,
  themed, accessible listbox. The original `<select>` stays in the DOM
  as the single source of truth — `.value`, `.selectedIndex`, and any
  existing `change` listener keep working exactly as before, so
  nothing in `lab.js`, `analytics.js`, `history.js`, or `simulator.js`
  had to change. It supports Arrow Up/Down, Home/End, Enter/Space,
  Escape, click-outside-to-close, and correctly rebuilds itself when
  options are added dynamically after page load (e.g. the Lab's
  scenario picker, populated from an API call).
- A native `<select>`/`<option>` dark-theme fallback (`color-scheme:
  dark` + explicit colors) in `main.css`, so the control still looks
  right even before JavaScript runs.
- Applied automatically, site-wide, to every dropdown that exists now
  (Lab, Analytics, History, Simulator) and any added later (Settings),
  with no per-page wiring required.

**B — Landing page, redesigned.** `templates/index.html` and
`static/css/landing.css` were substantially rebuilt:

- New hero visual: an animated shield with an orbiting DETECT /
  ANALYZE / DEFEND / MONITOR / RESPOND node ring, connecting lines,
  drifting particles, a radar-style scan sweep, and a pulsing core —
  built entirely in CSS + a few DOM nodes (no canvas, no added
  libraries).
- "AI SECURITY PLATFORM" badge, scroll indicator, and an "Explore
  Platform" button that smooth-scrolls to the features.
- New Normal-vs-Adversarial prompt comparison visual in the "Why AI
  Security Matters" section.
- Attack-type cards now carry an icon, a risk-level pill, and a "Try
  in Security Lab" link straight to `/lab`.
- Defense-in-depth is now framed inside a large shield outline.
- "How It Works" is now individual step cards with icons and
  micro-copy.
- A new **Live Security Metrics** section fetches real numbers from
  `GET /api/dashboard` (Total Analyses, Threats Detected, Attacks
  Blocked, High-Risk Events, Average Risk) with a labeled fallback if
  the backend is unreachable — nothing is invented as a "real-world
  accuracy" claim.
- A new **Security Workflow** section visualizes the actual backend
  pipeline (`USER → PROMPT → INPUT FILTER → DETECTOR → LLM → OUTPUT
  VALIDATOR → POLICY ENGINE → SAFE RESPONSE`) with animated packet
  flow — this is the same pipeline concept the Part 1 hero used to
  show, now given its own dedicated, more accurate section.
- A new **Built For** section (Students & Researchers, AI Developers,
  Security Teams, AI Application Builders).
- Every section now scroll-reveals via a shared `[data-reveal]` +
  `IntersectionObserver` utility in `landing.js`, which is skipped
  entirely when `prefers-reduced-motion: reduce` is set (same for the
  shield's spin/scan/pulse/float animations, gated in CSS).
- `/` still renders this page first — `page_routes.py` was not
  changed, so `LAUNCH SECURITY LAB` continues to route to `/lab`
  exactly as before.

**C/D — Site-wide consistency & accessibility.** A shared, expanded
footer (logo, description, real nav links only, `© 2026 PromptShield
AI`) now lives in `base.html` so every page gets it. Added a
skip-to-content link, `aria-current="page"` on the active nav item,
`aria-controls` on the mobile menu toggle, and fixed a real bug where
the shared detail modal's `aria-labelledby` pointed at an id that was
never actually set — the modal now also moves focus in on open and
restores it to the trigger element on close.

**E — Security Lab.** Functionality untouched; only the dropdowns
were fixed (per A) and the modal focus-handling improvement above
applies here too since it's shared.

**Bugs caught and fixed while building this:**
1. The dropdown component's "close other open dropdowns" logic
   originally just toggled a CSS class directly, which would have
   leaked a `document`-level event listener every time a second
   dropdown was opened while another was still open. Fixed by
   tracking the actual `closeList()` closure of whichever dropdown is
   currently open and calling it properly.
2. `aria-labelledby="detailModalTitle"` in the shared modal referenced
   an id that was never set on the generated title element — fixed.

## Final output

**Files added:** `static/js/dropdown.js`

**Files modified:** `templates/index.html`, `templates/base.html`,
`static/css/landing.css` (rewritten), `static/css/main.css` (dropdown
+ footer + skip-link styles), `static/js/landing.js` (rewritten),
`static/js/main.js` (modal focus handling + id fix)

**Files NOT touched:** every backend file (`app.py`, `config.py`,
`extensions.py`, all of `models/`, `routes/`, `services/`,
`database/`), and every other template/page script (`lab.html`/`.js`,
`dashboard.html`/`.js`, `analytics.html`/`.js`, `history.html`/`.js`,
`simulator.html`/`.js`, `research.html`, `settings.html`,
`admin.html`) — Parts 1-3 functionality is unchanged.

**Run commands:**
```bash
cd PromptShield-AI
pip install -r requirements.txt
python app.py
```
**URL:** http://127.0.0.1:5000/

**Testing performed:** full Python compile check across every module;
Node.js syntax check (`node --check`) on every JS file; a static
integration sweep confirming every `url_for('page.X')` in every
template resolves to a real view function and every referenced
static asset exists on disk; a cross-check that every
`getElementById` call in each page's script matches an id present in
its template (or is created dynamically, verified by source
inspection); manual trace-through of the dropdown component's open/
close/keyboard logic. I do not have network access in this sandbox to
install Flask-SQLAlchemy, so I could not launch the live server here —
please run the steps in Part K yourself and let me know if anything
surfaces.

**Remaining/known limitations:** Settings and Admin are still Part 1
placeholder pages (no real controls to theme yet — the dropdown fix
will apply automatically the moment real `<select>` elements are
added there). `/api/settings` still doesn't persist anything, as
before.


## Part 1 security configuration

Part 1 adds authentication/roles, hashed API keys, configurable rate limiting, environment-based CORS, optional local TLS, input normalization and encoding inspection, trusted/untrusted context isolation, indirect-injection lab inputs, additive database schema preparation, and subsystem health reporting.

### Local TLS
1. Generate or provide a local certificate and private key.
2. Set `ENABLE_TLS=true`, `SSL_CERT_FILE=/path/to/cert.pem`, and `SSL_KEY_FILE=/path/to/key.pem` in `.env`.
3. Run `python app.py`. The app uses HTTPS only when both certificate paths exist.

### Authentication
- `DEMO_MODE=true` keeps the local college demonstration usable without login.
- Set `DEMO_MODE=false` and `ENABLE_API_AUTH=true` to require session/API-key authentication.
- Roles are `ADMIN`, `ANALYST`, and `VIEWER`.
- API keys are shown in raw form only on creation/rotation and are stored only as SHA-256 hashes.
- Use `X-API-Key: <key>` or `Authorization: Bearer <key>` for API-key authentication.

### CORS and rate limiting
- Configure `ALLOWED_ORIGINS` as a comma-separated list. Wildcard `*` is not used.
- Configure `RATE_LIMIT`, for example `100/minute`. The built-in limiter keys requests by API key, authenticated session, then IP.


## Part 3 Security, Cryptography, Defense and Audit

Part 3 adds HMAC-SHA256 system-prompt integrity, AES-256-GCM helpers, optional Ed25519 audit signatures, dynamic canary tokens, output leak/PII detection, policy enforcement, simulated secure/standard/vulnerable model profiles, and a tamper-evident SHA-256 audit chain.

Recommended environment variables:
- `HMAC_SECRET`
- `ENCRYPTION_KEY` (32-byte raw value or URL-safe base64)
- `AUDIT_SIGNING_KEY` (optional Ed25519 private key)
- `CANARY_ENABLED=true`
- `TARGET_SYSTEM_PROMPT`
- `SYSTEM_PROMPT_HMAC` (optional; when omitted, the expected HMAC is calculated from the configured secret for local demonstration)

Vulnerable model behavior is simulation only. It does not execute commands, access credentials/files, or perform network actions.


## Part 4: Evaluation, Analytics and Final Integration

PromptShield AI includes an offline-first Evaluation Lab at `/evaluation`, database-backed analytics, feedback labeling, forensic audit events, PDF security reports, Red Team / Blue Team scenarios, dynamic Security Posture, and runtime policy settings.

### Evaluation
`POST /api/evaluation/run` evaluates the local JSONL dataset using Rule, ML, LLM Judge, and Hybrid detectors. Metrics are calculated from actual samples: accuracy, precision, recall, F1, false-positive rate, false-negative rate, confusion matrix, and latency. An unavailable/untrained detector is reported as `INSUFFICIENT DATA`.

### Feedback
`POST /api/feedback` records analyst labels without automatic retraining. `GET /api/feedback/export` exports labeled samples as JSONL.

### Forensics and Reports
`GET /api/audit/events` lists audited requests and `GET /api/audit/events/<id>` exposes forensic details. `GET /api/reports/<request_id>` creates a PDF from the actual audit record.

### Offline-first behavior
Default configuration remains `AI_PROVIDER=mock`, `LLM_JUDGE_MODE=mock`, and `ML_BACKEND=tfidf`. The application does not claim ML accuracy until a trained model artifact exists.

### Limitations
The execution environment used for this build does not contain Flask/Flask-SQLAlchemy and cannot download packages. Python/JavaScript syntax and the standalone detector/evaluation logic were validated, but the complete Flask integration test suite and live browser run must be executed after installing `requirements.txt` in a normal Python environment.


## Gemini LLM-as-Judge integration

PromptShield AI now supports an optional real Google Gemini semantic judge. It is an additional
security signal, not a replacement for the local rule detector, ML detector, risk engine,
defense engine, output validator, or audit log.

The project uses Google's current unified `google-genai` Python SDK rather than the deprecated
`google-generativeai` package. The SDK is optional at runtime: Mock mode still works without an
API key or a Gemini installation. Google documents `google-genai` as the current Python SDK and
supports structured JSON responses through `response_mime_type` and a JSON schema.

### Environment

```text
GEMINI_API_KEY=
GEMINI_MODEL=
GEMINI_TIMEOUT_SECONDS=10

AI_PROVIDER=mock
LLM_JUDGE_ENABLED=false
LLM_JUDGE_MODE=mock
```

Recommended offline defaults keep the judge disabled. To enable the real judge:

```text
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-3.8-flash
AI_PROVIDER=gemini
LLM_JUDGE_ENABLED=true
LLM_JUDGE_MODE=gemini
```

Never put the API key in HTML or JavaScript. Keep `.env` out of version control.

### How the pipeline works

```text
INPUT
  -> NORMALIZATION
  -> RULE DETECTOR
  -> ML DETECTOR
  -> GEMINI LLM JUDGE (optional)
  -> HYBRID RISK ENGINE
  -> DEFENSE ENGINE
  -> TARGET LLM / MOCK
  -> OUTPUT VALIDATOR
  -> AUDIT
```

The hybrid defaults are Rule 35%, ML 40%, Gemini 25%. If a detector is unavailable, its weight
is redistributed across the detectors that actually returned a score. No unavailable score is
fabricated.

Gemini receives a fixed security-analysis instruction and the user prompt as explicitly marked
untrusted data. It is not allowed to execute tools, access files, access databases, access
credentials, or modify application configuration.

### Gemini failures

Missing key, disabled judge, timeout, rate limit, network error, quota error, invalid JSON, or
SDK failure results in a non-fatal judge status. PromptShield continues with local detectors and
the local risk engine. Gemini failure alone never becomes CRITICAL.

### API

`POST /api/detect/llm-judge` runs the configured judge only.

`GET /api/health` exposes a safe Gemini status object containing enabled/configured/provider/model/
status. The API key is never returned.

`POST /api/analyze` remains the main analysis endpoint and includes Gemini in the existing
hybrid pipeline when enabled.

### Model

The implementation defaults to `gemini-3.8-flash` only when `GEMINI_MODEL` is empty. The model
can always be overridden through the environment or Settings UI. Google currently lists
Gemini 3.8 Flash as a stable model and also documents structured outputs for Gemini models.

### Tests

Automated tests never call the real Gemini service. The Gemini provider is mocked/disabled for
unit tests. Real API verification is an optional integration test performed only when a valid
server-side API key is configured.


## Gemini-first prompt analysis

`/api/analyze` uses Gemini as its primary semantic detector. The rule and ML
detector endpoints remain available for compatibility, but they are not fused
into the `/api/analyze` decision. A narrow local safety fallback blocks
unambiguous dangerous-assistance requests and direct prompt-injection patterns
if Gemini is unavailable or returns a lower-risk result. This prevents a Gemini
timeout or malformed response from being treated as proof that a prompt is safe.

For local setup, copy `.env.example` to `.env`, set `GEMINI_API_KEY` in `.env`,
and keep `LLM_JUDGE_ENABLED=true`, `LLM_JUDGE_MODE=gemini`. Do not share `.env`.
