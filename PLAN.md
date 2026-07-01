# mcp-sentinel — Implementation Plan

> A security auditor / linter for **Model Context Protocol (MCP)** servers.
> Python + `typer` CLI. Rule-as-data engine. Clean exit codes. Offline-first.
> Target: `v0.1.0` shippable, MIT-licensed, recruiter-legible.

---

## 1. Context — the real unmet need

MCP went from "interesting spec" (late 2024) to the default plugin bus for AI agents across
Claude Desktop / Claude Code, Cursor, Windsurf, VS Code, Zed and a long tail of IDEs by 2026.
An MCP server is *code you invite into your agent's trust boundary*: its **tool descriptions get
injected verbatim into the model's context**, and its tools frequently wrap `exec`, filesystem, and
network. That combination created a genuinely new attack surface — **tool poisoning** (malicious
instructions hidden in a tool's `description` or parameter docs), over-broad capabilities, secrets
leaking through server env blocks, and supply-chain risk from `npx`/`uvx` one-liners that pull
unpinned, unverified packages.

**What already exists (honest survey):**

| Tool / category | What it does | Gap for MCP |
|---|---|---|
| `gitleaks`, `trufflehog` | Secret scanning in repos/history | No concept of an MCP server, tool schema, or a `mcpServers` config block. Misses env-embedded keys in `settings.json`. |
| `semgrep`, `bandit` | Generic SAST for source code | Scan *code*, not the *MCP manifest / tool descriptions* that the LLM actually consumes. No tool-poisoning heuristics. |
| `npm audit`, `pip-audit`, OSV | Known-CVE dependency scanning | Version-CVE only; blind to "this server declares a `run_shell` tool with a poisoned description". |
| MCP scanner blog posts / gists / a few nascent `mcp-scan`-style scripts | Ad-hoc, single-file, no severity model, no SARIF, no CI story | Not a rule-as-data engine, no stable JSON/SARIF contract, no test suite, not packaged. |
| Guardrails / LLM-firewall products | Runtime prompt-injection filtering | Runtime, paid, network-bound. Nothing that **statically lints a config before you install it**. |

**Differentiation:** mcp-sentinel is the *pre-install / pre-commit static linter for the MCP trust
boundary*. It reads the exact artifacts an agent trusts — the `mcpServers` block and the tool
manifest — and flags poisoning, capability creep, secrets, and supply-chain risk **offline, for
free, with SARIF output that drops straight into GitHub code-scanning**. It is to MCP configs what
`hookguard` is to Git hooks: a rule-as-data engine with clean exit codes you can wire into CI.

---

## 2. Architecture — designed for 3–4 parallel builder subagents

Modules are carved so **each builder owns a non-overlapping directory** and codes against one shared
contract (`models.py`). `models.py` is written/frozen **first** (P0), then agents A–D fan out.

```
mcp-sentinel/
├── pyproject.toml                 # packaging, deps, ruff+pytest config, console_scripts entry
├── README.md                      # recruiter-facing (Agent D / owner)
├── LICENSE                        # MIT
├── .github/workflows/ci.yml       # CI matrix py3.10–3.12 (Agent D)
├── src/mcp_sentinel/
│   ├── __init__.py                # __version__ = "0.1.0"
│   ├── models.py                  # ★ SHARED CONTRACT — frozen before fan-out (owner)
│   ├── engine.py                  # orchestrator: load target → run rules → build Report (owner)
│   ├── severity.py                # Severity enum + ordering + exit-code mapping (owner, tiny)
│   │
│   ├── parsers/                   # ── Agent A ──
│   │   ├── __init__.py            #   load_target(path) dispatch by shape/flag
│   │   ├── settings_loader.py     #   Claude/Cursor settings.json → mcpServers → ScanTarget
│   │   ├── manifest_loader.py     #   standalone MCP server manifest → ScanTarget
│   │   ├── stdio_probe.py         #   (P3) live stdio JSON-RPC tools/list → ScanTarget
│   │   └── normalize.py           #   coerce heterogeneous shapes into ServerSpec/ToolSpec
│   │
│   ├── rules/                     # ── Agent B ──
│   │   ├── __init__.py            #   ALL_RULES registry + load_rules()
│   │   ├── base.py                #   Rule protocol / helper: regex, entropy, unicode utils
│   │   ├── poisoning.py           #   MCPS001–004 tool-poisoning / prompt-injection
│   │   ├── capabilities.py        #   MCPS010–013 dangerous capability inference
│   │   ├── secrets.py             #   MCPS020–022 secrets in env/config (entropy+regex)
│   │   ├── supplychain.py         #   MCPS030–033 unpinned/untrusted sources
│   │   ├── scope.py               #   MCPS040–041 permission-scope vs declared purpose
│   │   └── data/                  #   rule metadata as data (YAML/py dict): id,title,sev,remediation
│   │       └── rules.yaml
│   │
│   ├── report/                    # ── Agent C ──
│   │   ├── __init__.py            #   render(report, fmt) dispatch
│   │   ├── markdown.py            #   severity-grouped MD, remediation blocks
│   │   ├── json_out.py            #   stable machine JSON (schema-versioned)
│   │   └── sarif.py               #   SARIF 2.1.0 (runs/results/rules, partialFingerprints)
│   │
│   ├── llm/                       # ── Agent B (optional, gated) ──
│   │   ├── __init__.py
│   │   └── deepcheck.py           #   --llm deep prompt-injection check; no-op if no key/flag
│   │
│   └── cli.py                     # ── Agent D ──  typer app, exit codes, flag wiring
└── tests/                         # split by module, each agent adds their own
    ├── conftest.py                # shared fixtures + fixtures/ tree
    └── fixtures/
        ├── clean_settings.json
        ├── poisoned_settings.json
        ├── secrets_env.json
        ├── unpinned_npx.json
        ├── overbroad_tool.json
        └── manifest_min.json
```

**Ownership map (non-overlapping):**

- **Owner (serial, P0):** `models.py`, `severity.py`, `engine.py`, `pyproject.toml` scaffold, fixtures skeleton. Freeze the contract, then unblock A–D.
- **Agent A — `parsers/`:** turn any input into a `ScanTarget`. Owns nothing in `rules/report/cli`.
- **Agent B — `rules/` + `llm/`:** pure functions `Rule.check(target) -> list[Finding]`. Never touches IO or rendering.
- **Agent C — `report/`:** `Report -> str` for md/json/sarif. Never runs rules or parses input.
- **Agent D — `cli.py` + CI + README + LICENSE:** wires A→engine→B→C, exit codes, packaging, docs.

Integration seam: everyone imports only from `models.py`. Engine is the only place A, B, C meet.

---

## 3. Shared data contract (`models.py`) — code against this

```python
# severity.py
class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    # helpers: .label -> "critical", .sarif_level -> "note|warning|error", from_str()

# models.py
@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str = ""            # the field most abused for poisoning
    parameters: dict = field(default_factory=dict)   # JSON-schema-ish
    raw: dict = field(default_factory=dict)          # untouched source for evidence

@dataclass(frozen=True)
class ServerSpec:
    name: str                       # key from mcpServers, or manifest name
    command: str | None = None      # "npx", "uvx", "node", "python", "docker"...
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None          # for http/sse transports
    declared_purpose: str = ""      # description/summary if present
    tools: list[ToolSpec] = field(default_factory=list)
    source_path: str = ""           # provenance for reporting
    raw: dict = field(default_factory=dict)

@dataclass(frozen=True)
class ScanTarget:
    kind: Literal["settings", "manifest", "stdio"]
    path: str
    servers: list[ServerSpec]

@dataclass(frozen=True)
class Location:
    server: str
    tool: str | None = None
    field: str | None = None        # "description" | "env.API_KEY" | "args[1]"
    snippet: str = ""               # redacted evidence excerpt

@dataclass(frozen=True)
class Finding:
    rule_id: str                    # "MCPS001"
    title: str
    severity: Severity
    message: str                    # what's wrong, human-readable
    location: Location
    remediation: str
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""           # stable hash(rule_id+location) for SARIF dedupe

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: Literal["poisoning","capability","secret","supplychain","scope"]
    remediation: str
    references: list[str] = field(default_factory=list)
    check: Callable[[ScanTarget], list[Finding]]   # pure fn; metadata lives here too

@dataclass
class Report:
    target: ScanTarget
    findings: list[Finding]
    schema_version: str = "1.0"
    tool_version: str = __version__
    # props: counts_by_severity, highest_severity, exit_code
```

**Exit-code contract (mirrors hookguard):**

| Code | Meaning |
|---|---|
| `0` | scan ran, no findings at/above `--fail-on` threshold |
| `1` | findings present (default threshold = MEDIUM), non-critical |
| `2` | at least one CRITICAL finding (or `--strict` and any HIGH+) |
| `3` | operational error (bad input, unreadable file, parse failure) |

`--fail-on {info,low,medium,high,critical}` shifts the 0↔1 boundary; `2` reserved for CRITICAL.

---

## 4. Detection rules (rule-as-data) — 14 rules across 5 categories

Each rule ships as a data record `{id, title, severity, category, how-detected, remediation, refs}`
in `rules/data/rules.yaml`; the matching `check()` lives in the category module. Severities are
defaults and overridable via config.

### Category 1 — Tool poisoning / prompt injection (in descriptions & param docs)

| ID | Title | Sev | How detected | Remediation |
|---|---|---|---|---|
| **MCPS001** | Instruction-override phrases in tool description | HIGH | Case-insensitive regex over `ToolSpec.description` + parameter `description`s for: `ignore (all )?previous`, `disregard (the )?instructions`, `you are now`, `system prompt`, `do not tell the user`, `<important>`, `[[.*]]` directive blocks. | Remove imperative meta-instructions from tool docs; descriptions must describe, not command. |
| **MCPS002** | Invisible / control unicode in description | HIGH | Scan for zero-width (`U+200B–200D`, `U+FEFF`), bidi overrides (`U+202A–202E`, `U+2066–2069`), tag chars (`U+E0000–E007F`). Any hit = finding. | Strip non-printable chars; re-author description in plain ASCII/UTF-8 printable. |
| **MCPS003** | Encoded payload blob in description/params | MEDIUM | Detect long base64 (`[A-Za-z0-9+/]{40,}={0,2}` with valid decode), hex blobs, or `data:` URIs embedded in doc fields. | Remove embedded blobs; tool docs should never carry encoded data. |
| **MCPS004** | Hidden-channel markers ("secret", "do not mention", exfil verbs) | MEDIUM | Phrase set: `do not mention`, `without telling`, `send .* to`, `exfiltrate`, `forward .* to http`, plus URLs pointing off declared domain inside a description. | Audit intent; remove covert-behavior language and hardcoded destination URLs. |

### Category 2 — Dangerous / over-broad capabilities (inferred from name/schema)

| ID | Title | Sev | How detected | Remediation |
|---|---|---|---|---|
| **MCPS010** | Shell/exec capability | HIGH | Tool name/desc match `\b(exec|shell|bash|sh|command|run_code|eval|subprocess|os\.system)\b`; or a param named `command`/`cmd`/`script`. | Constrain to an allowlist of commands; drop free-form shell tools or sandbox them. |
| **MCPS011** | Arbitrary file write / delete | HIGH | Match `write_file|delete|rm|unlink|put_file|save`, param `path`+`content`, or `overwrite:true` defaults. | Scope to a fixed workspace dir; deny path traversal; make write opt-in. |
| **MCPS012** | Unbounded network egress | MEDIUM | Match `fetch|http_request|curl|request|webhook|post|upload`, param `url` with no host allowlist in schema. | Add a host allowlist to the schema/config; block arbitrary outbound URLs. |
| **MCPS013** | Credential / secret access tool | HIGH | Match `get_env|read_secret|credentials|token|keychain|password|dotenv|aws_credentials`. | Remove direct secret-reading tools; broker via a scoped secrets manager. |

### Category 3 — Secrets in server config / env

| ID | Title | Sev | How detected | Remediation |
|---|---|---|---|---|
| **MCPS020** | Known-format API key in `env`/`args` | CRITICAL | Provider regexes: `sk-[A-Za-z0-9]{20,}` (OpenAI), `ghp_/gho_/ghs_[A-Za-z0-9]{36}` (GitHub), `AKIA[0-9A-Z]{16}` (AWS), `xox[baprs]-` (Slack), `AIza[0-9A-Za-z\-_]{35}` (Google), `glpat-`, `hf_`, Anthropic `sk-ant-`. | Move to env var reference / secret store; rotate the exposed key immediately. |
| **MCPS021** | High-entropy value in env (generic secret) | HIGH | For each `env`/`arg` value: Shannon entropy ≥ 4.0 over len ≥ 20 AND key name matches `(key|token|secret|passwd|password|auth|api)`. Entropy gate suppresses false hits on plain config. | Replace literal with `${ENV_VAR}` indirection; never commit raw secrets to settings.json. |
| **MCPS022** | Plaintext password / basic-auth in URL | HIGH | Match `https?://[^/\s:]+:[^/\s@]+@` in `url`/args, or `password=`/`pwd=` query params. | Use token auth via env; strip inline credentials from URLs. |

### Category 4 — Untrusted / unpinned server sources (supply chain)

| ID | Title | Sev | How detected | Remediation |
|---|---|---|---|---|
| **MCPS030** | Unpinned `npx`/`uvx` package | HIGH | `command in {npx,uvx,pnpm dlx}` and no `@x.y.z`/`==x.y.z` version in args (allow `@latest` flagged separately). | Pin an exact version and (npm) integrity hash; avoid `@latest`. |
| **MCPS031** | `@latest` / floating tag | MEDIUM | Args contain `@latest`, `@next`, `@beta`, or a semver range (`^`,`~`,`*`). | Pin to an exact released version reviewed for provenance. |
| **MCPS032** | Insecure `http://` package/source URL | HIGH | Any `http://` (not https) in `url`, args, or a `--registry` pointing at plain http. | Use `https://`; verify TLS; prefer signed registry sources. |
| **MCPS033** | Unknown / unscoped publisher | LOW | Package spec has no npm scope (`@org/`) or an unrecognized publisher not in a small bundled allowlist of well-known MCP orgs. | Verify the publisher, prefer scoped/official packages, review source before install. |

### Category 5 — Excessive permission scope vs declared purpose

| ID | Title | Sev | How detected | Remediation |
|---|---|---|---|---|
| **MCPS040** | Capability broader than declared purpose | MEDIUM | If `declared_purpose` implies a narrow read/lookup role (keywords: `read`, `search`, `lookup`, `weather`, `docs`) but tools include a HIGH-capability rule hit (MCPS010/011/013), flag the mismatch. | Split concerns; a read-only server should not expose exec/write/secret tools. |
| **MCPS041** | Excess tool count / wildcard scope | LOW | Server exposes an unusually large tool set (> configurable N, default 25) or a tool with wildcard/`*` param scope, without purpose justification. | Reduce to least-privilege tool set; document why each tool is needed. |

**Optional LLM deep-check (gated):** `MCPS001-LLM` — when `--llm` is set, sends *only the tool
description text* (never secrets/env) to a configured model with a fixed classifier prompt to catch
paraphrased injection heuristics miss. Off by default, no-op without key. Emits findings tagged
`(llm)` and is excluded from `--offline` runs.

---

## 5. CLI surface (`typer`)

```
mcp-sentinel scan <PATH> [options]     # primary command
mcp-sentinel rules [--category C]      # list/describe all rules (rule-as-data introspection)
mcp-sentinel version
```

**`scan` flags:**

| Flag | Default | Purpose |
|---|---|---|
| `PATH` (arg) | — | settings.json, manifest.json, or `-` for stdin |
| `--input {auto,settings,manifest,stdio}` | `auto` | force parser; `auto` sniffs shape |
| `--format {markdown,json,sarif}` | `markdown` | output format (repeatable → multi-emit) |
| `-o, --output FILE` | stdout | write report to file |
| `--fail-on {info,low,medium,high,critical}` | `medium` | exit-code threshold |
| `--strict` | off | any HIGH+ escalates exit code to 2 |
| `--offline` | off (implied) | hard-disable any network/LLM path |
| `--llm [model]` | off | enable optional LLM deep-check (needs key env) |
| `--select IDs` / `--ignore IDs` | — | rule allow/deny lists (comma sep) |
| `--config FILE` | `.mcp-sentinel.toml` | severity overrides, allowlists, thresholds |
| `--no-redact` | off | show full secret evidence (default: masked) |
| `-q/--quiet`, `-v/--verbose` | — | log level |

Example: `mcp-sentinel scan ~/.claude/settings.json --format sarif -o results.sarif --fail-on high`

`rules` command prints the data-driven registry (id, sev, category, one-liner) proving the
rule-as-data design — same source of truth the engine executes.

---

## 6. Quality gate (all real, no fake)

### Unit tests (16 enumerated — pytest, each maps to a rule/parser/report path)

| # | Test | Fixture | Asserts |
|---|---|---|---|
| 1 | `test_settings_loader_basic` | `clean_settings.json` | parses N servers, tools, env into `ScanTarget` |
| 2 | `test_manifest_loader_basic` | `manifest_min.json` | manifest → single `ServerSpec` with tools |
| 3 | `test_input_autodetect` | both above | `auto` picks correct parser by shape |
| 4 | `test_loader_bad_json_errors` | malformed file | raises typed error → exit 3 (no crash) |
| 5 | `test_poisoning_instruction_override` | `poisoned_settings.json` | MCPS001 fires HIGH on "ignore previous" |
| 6 | `test_poisoning_invisible_unicode` | inline zero-width str | MCPS002 fires; clean desc does not |
| 7 | `test_poisoning_base64_blob` | desc w/ 60-char b64 | MCPS003 fires; short token does not |
| 8 | `test_poisoning_hidden_channel` | "do not mention ... send to http" | MCPS004 fires |
| 9 | `test_capability_shell_exec` | `overbroad_tool.json` (run_shell) | MCPS010 HIGH |
| 10 | `test_capability_file_write` | write_file+path+content | MCPS011 fires |
| 11 | `test_secret_known_key_openai` | `secrets_env.json` (`sk-...`) | MCPS020 CRITICAL, evidence masked |
| 12 | `test_secret_entropy_generic` | high-entropy `API_TOKEN` | MCPS021; low-entropy config value clean (no FP) |
| 13 | `test_supplychain_unpinned_npx` | `unpinned_npx.json` | MCPS030 fires; `pkg@1.2.3` clean |
| 14 | `test_supplychain_http_url` | `http://` source | MCPS032 fires |
| 15 | `test_scope_capability_vs_purpose` | "read-only weather" + exec tool | MCPS040 fires |
| 16 | `test_clean_config_zero_findings` | `clean_settings.json` | empty findings, exit 0 |
| 17 | `test_sarif_schema_valid` | any findings | SARIF has `version 2.1.0`, `runs[].tool.driver.rules`, valid `level` mapping |
| 18 | `test_json_schema_stable` | any findings | JSON has `schema_version`, sorted-by-severity findings |
| 19 | `test_exit_code_mapping` | crit/med/clean | engine → 2 / 1 / 0; bad input → 3 |
| 20 | `test_severity_ordering` | — | `CRITICAL > HIGH > ... `, `sarif_level` mapping correct |

(16+ real tests; each agent contributes tests for its own module. `--no-redact` off is asserted so
secret evidence never leaks into reports by default.)

### Tooling & CI

- **ruff** (lint + format) with config in `pyproject.toml`; `ruff check` and `ruff format --check` in CI.
- **pytest** with `--cov=mcp_sentinel` (coverage reported, not gated hard at v0.1 but shown).
- **mypy** (optional, `--ignore-missing-imports`) on `models.py`/`engine.py` for the contract.
- **GitHub Actions `ci.yml`:** matrix `python-version: [3.10, 3.11, 3.12]` on ubuntu; steps =
  checkout → setup-python → `pip install -e .[dev]` → `ruff check` → `ruff format --check` →
  `pytest`. Second job: run mcp-sentinel on its own `tests/fixtures/poisoned_settings.json` and
  assert non-zero exit (dogfooding / smoke test).
- **Self-scan badge:** README shows the tool scanning a sample and the SARIF uploaded via
  `github/codeql-action/upload-sarif` in a demo workflow.

### README outline (recruiter-facing)

1. One-line pitch + shields (CI, license, py versions, PyPI).
2. "Why" — the MCP trust-boundary problem in 3 sentences + a scary before/after example.
3. Quickstart: `pipx install mcp-sentinel` → `mcp-sentinel scan settings.json`.
4. Sample output (colored terminal + a SARIF-in-GitHub screenshot).
5. Rule catalog table (auto-generated from `rules.yaml`).
6. CI integration snippet (`.github/workflows`) + exit-code semantics table.
7. Architecture diagram (the module map) + "how to add a rule" (rule-as-data, 10 lines).
8. Roadmap, security policy, contributing, MIT license.

### Licensing / release

- **LICENSE:** MIT, current year, author name.
- **v0.1.0 release steps:** (1) tag `v0.1.0`; (2) `python -m build`; (3) `twine check dist/*`;
  (4) TestPyPI upload + `pipx install` smoke test; (5) PyPI upload; (6) GitHub Release with
  changelog + attached SARIF demo; (7) enable Dependabot + branch protection requiring CI green.

---

## 7. Offline / free-tier guarantees

- **Zero paid dependencies.** Core deps: `typer`, stdlib (`json`, `re`, `math`, `unicodedata`,
  `base64`, `hashlib`, `dataclasses`). Optional: `pyyaml` for `rules.yaml` (or ship rules as a `.py`
  dict to stay stdlib-only). No cloud calls in any default path.
- **`--offline` is a hard gate:** disables `llm/` and `stdio_probe` network entirely; asserted by a
  test that monkeypatches the socket layer to fail and confirms a clean scan still passes.
- **LLM deep-check is strictly opt-in:** requires `--llm` *and* an API key env var; absent either,
  it's a silent no-op. It only ever sends *tool description strings*, never `env`/secrets. All static
  rules (the whole value prop) run with no network and no key.
- Runs on a laptop in <1s for typical configs; no daemon, no telemetry.

---

## 8. Phased roadmap

- **P0 — Scaffold (owner, serial):** `pyproject.toml`, `src/` layout, `models.py` + `severity.py`
  frozen contract, `engine.py` skeleton, empty `rules.yaml`, fixtures skeleton, ruff config, CI
  file. Deliverable: `mcp-sentinel version` runs; contract importable. **Unblocks A–D.**
- **P1 — Static rules + report (Agents A+B+C parallel):** `parsers/settings_loader` +
  `manifest_loader`; rule categories 1–5 (MCPS001–041); `report/markdown` + `report/json`; wire
  through `engine`. Deliverable: `scan settings.json` produces ranked MD/JSON findings, correct exit
  codes, tests 1–16, 18–20 green.
- **P2 — SARIF + CLI polish (Agent C + D):** `report/sarif` (2.1.0), `--format`/`--fail-on`/
  `--select`/`--ignore`/`--config`, `rules` subcommand, redaction default, README, CI dogfood job,
  test 17. Deliverable: SARIF uploads cleanly to GitHub code-scanning; ship-quality CLI.
- **P3 — Live stdio + LLM deep-check (stretch):** `parsers/stdio_probe` (spawn server, JSON-RPC
  `initialize`+`tools/list`, feed real tool schemas into the same rules); `llm/deepcheck` gated
  classifier. Deliverable: `--input stdio` and opt-in `--llm`.
- **Ship:** cut `v0.1.0` after P2 (P3 features flagged experimental), publish to PyPI, GitHub
  Release, announce.

---

## 9. Risks & differentiation

**Risks / mitigations:**

- **False positives** on heuristic poisoning/capability rules → mitigate with entropy gates,
  `--ignore`/`--select`, per-rule severity overrides, and a `--fail-on` threshold so noisy LOW/INFO
  rules don't block CI.
- **MCP config-shape drift** across clients (Claude vs Cursor vs VS Code) → isolate all shape
  handling in `parsers/normalize.py`; rules only ever see the normalized `ServerSpec`/`ToolSpec`.
- **Rule staleness** (new key formats, new attack patterns) → rule-as-data means new rules are data
  + one small pure function; contribution barrier is intentionally low.
- **Secret leakage via our own reports** → redaction on by default; test asserts masked evidence;
  `--no-redact` is explicit and documented.
- **Scope creep into runtime firewalling** → out of scope for v0.1; stay a *static pre-install
  linter*. Runtime is a different product.

**Differentiation (one line):** the only offline, free, SARIF-emitting **static linter for the MCP
trust boundary** — reading the exact `mcpServers`/manifest artifacts an agent trusts and catching
tool poisoning, capability creep, secrets, and supply-chain risk before install, with hookguard-style
rule-as-data and clean CI exit codes.
