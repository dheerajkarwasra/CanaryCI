# AGENTS.md — Mandatory Engineering Rules for Coding Models

> **READ THIS ENTIRE FILE BEFORE WRITING ANY CODE.**  
> Every coding agent or model working on `canary-ci` MUST follow these rules without exception. Do not improvise architecture, add unlisted dependencies, or deviate from task specifications.

---

## 1. Core Architectural Invariants (Non-Negotiable)

1. **ZERO LLM-as-a-Judge:** Never call an LLM to evaluate whether a test passed or failed. All grading in `canary_ci/detection/` and `canary_ci/runner/` MUST be 100% deterministic (string/byte/encoding matching, predicate evaluation, AST/SQL/path checks, state diffs).
2. **ZERO External Network Calls in Tests & Honey-Tools:**
   - All sockets opened by CanaryCI (`uvicorn`, `starlette`, MCP HTTP, A2A mock servers, Browser DOM trap servers) MUST bind exclusively to `127.0.0.1` on an OS-assigned ephemeral port (`port=0`).
   - All simulated URLs, domains, and emails in scenarios and tests MUST use RFC 2606 / RFC 6761 reserved domains (`.invalid`, `.example`, `.test`, `.corp.internal`, `localhost`, `127.0.0.1`).
   - Never make live calls to OpenAI, Anthropic, Gemini, or external URLs inside `tests/`. Use `ScriptedAgentAdapter` (`src/canary_ci/adapters/scripted.py`) or `httpx.MockTransport` for 100% offline deterministic testing.
3. **Hermetic Per-Trial Isolation:** Every trial MUST create its own ephemeral directory (`tempfile.TemporaryDirectory(prefix="canary_trial_")`) and clean it up (unless `--keep-sandbox` is explicitly set). Never mutate files inside the repository workspace or `src/canary_ci/scenarios/` during test runs.
4. **Dynamic Run-Scoped Canaries:** Never hardcode static secret values inside scenario assertions. Scenarios declare *canary IDs and templates* (e.g., `id: stripe_prod_key`, `prefix: sk_live_canary_`); the `CanarySeeder` generates deterministic tokens via `HMAC-SHA256(run_seed, f"{scenario_id}:{trial_index}:{canary_id}")`.
5. **Single Source of Truth for Models:** All YAML/JSON data structures (Config, Scenario, MockProfile, TraceEvent, TrialResult, SarifLog, AuditManifest) MUST be defined as `pydantic.BaseModel` subclasses with `model_config = ConfigDict(extra="forbid", frozen=True)` (use mutable models only for internal runtime accumulators where explicitly specified).

---

## 2. Exact Package & Directory Ownership

Do NOT create top-level modules or directories outside this canonical map:

```text
canary-ci/
├── pyproject.toml
├── AGENTS.md
├── CLAUDE.md
├── schemas/                         # Draft 2020-12 JSON Schemas (kept in sync with Pydantic models)
│   ├── config.schema.json
│   ├── scenario.schema.json
│   └── mock-profile.schema.json
├── src/canary_ci/
│   ├── __init__.py
│   ├── core/                        # Exceptions, constants, clock/ID helpers, Pydantic base models
│   │   ├── __init__.py
│   │   ├── constants.py
│   │   ├── errors.py
│   │   ├── models.py                # ScenarioSpec, CanaryConfig, MockProfileSpec, Enums
│   │   └── trace.py                 # TraceEvent, TraceWriter, TraceReader
│   ├── canary/                      # Canary token generation, normalizers, breach detection, provenance
│   │   ├── __init__.py
│   │   ├── seeder.py                # HMAC-SHA256 deterministic canary generator & template renderer
│   │   ├── normalizers.py           # 12-transform de-obfuscation pipeline (Base64 3-offset, hex, URL, etc.)
│   │   ├── detector.py              # Rolling window buffer, action tripwires, ASI09/ASI10 evaluators
│   │   └── provenance.py            # Causal breach graph builder (Origin -> Carrier -> Turn -> Sink)
│   ├── environments/                # Synthetic Honey-Tool environments & protocol servers
│   │   ├── __init__.py
│   │   ├── base.py                  # HoneyEnvironment protocol, ToolDefinition, DispatchResult
│   │   ├── workspace_fs.py          # Sandboxed virtual/tempdir filesystem + shell boundary simulator
│   │   ├── enterprise_mocks.py      # Git/PR, Email Inbox/Outbox, Ticketing, Wiki/RAG, SQLite DB
│   │   ├── http_sink.py             # Intercepted outbound HTTP/Webhook sink + local Starlette sink
│   │   ├── mcp_server.py            # Ephemeral MCP Server (stdio & streamable-http/SSE) + ASI04 rug-pull
│   │   ├── custom_profile.py        # Phase 2: User-defined custom tool mock loader & executor
│   │   ├── memory_store.py          # Phase 2: Cross-session persistent KV & RAG store (ASI06)
│   │   ├── a2a_mock.py              # Phase 3: Mock A2A JSON-RPC Peer Agent & Spoofed Agent Cards
│   │   └── browser_dom_server.py    # Phase 3: Local synthetic HTTP server for DOM/CSS/ARIA traps
│   ├── adapters/                    # Target Agent Under Test (AUT) execution adapters
│   │   ├── __init__.py
│   │   ├── base.py                  # AgentAdapter ABC, AgentTurnContext, AdapterResult
│   │   ├── scripted.py              # Offline deterministic test agent (benign & compromised modes)
│   │   ├── litellm_mcp.py           # Built-in reference LLM + MCP tool-calling loop
│   │   ├── http_adapter.py          # Black-box HTTP webhook agent adapter
│   │   ├── cli_adapter.py           # Black-box CLI subprocess agent adapter (TS/Go/Rust/Python)
│   │   ├── python_callable.py       # In-process Python import path (`module:callable`) adapter
│   │   ├── proxy_gateway.py         # Phase 2: BYOD MCP gateway / firewall wrapper transport
│   │   └── playwright_adapter.py    # Phase 3: Headless local browser agent harness adapter
│   ├── runner/                      # Scenario & suite orchestration, stats, baseline diffing, pinning
│   │   ├── __init__.py
│   │   ├── orchestrator.py          # Single-trial & multi-session lifecycle coordinator
│   │   ├── suite_runner.py          # Concurrency, tag/tier filtering, fail-fast execution
│   │   ├── statistics.py            # Phase 2: Multi-trial secure^k, breach@k, breach_rate math
│   │   ├── regression_pin.py        # Pin failed trace into permanent regression YAML scenario
│   │   └── baseline_diff.py         # Phase 3: Baseline comparison, policy gates, expiring allowlists
│   ├── reporting/                   # Terminal UI, SARIF 2.1.0, PR Markdown, Signed Audit Bundles
│   │   ├── __init__.py
│   │   ├── console.py               # Rich terminal tables, provenance trees, replay output
│   │   ├── sarif.py                 # GitHub Code Scanning SARIF 2.1.0 generator
│   │   ├── markdown_pr.py           # Concise GitHub PR summary generator
│   │   └── audit_bundle.py          # Phase 3: OWASP/NIST/EU AI Act mapping + Ed25519 signed bundle
│   ├── scenarios/                   # Built-in declarative YAML scenario suites (ASI01–ASI10)
│   │   ├── __init__.py              # Package resource loader (`importlib.resources`)
│   │   ├── phase1_core/             # 25 core MCP/tool scenarios (ASI01–ASI06, ASI09, ASI10)
│   │   ├── phase2_persistence/      # 5 multi-session memory & RAG poisoning scenarios (ASI06)
│   │   └── phase3_multimodal_a2a/   # 10 A2A delegation (ASI07/08) & Browser DOM trap scenarios
│   └── cli/                         # Typer CLI commands
│       ├── __init__.py
│       └── app.py                   # init, run, validate, list, replay, pin, diff, audit, doctor
└── tests/                           # Mirrors src/canary_ci/ 1-to-1
```

---

## 3. Coding Style & Quality Standards

1. **Python Version & Typing:**
   - Target **Python 3.12+**. Use modern union syntax (`str | None`, `list[str]`, `dict[str, Any]`, `type X = ...`) — never legacy `Optional[...]`, `List[...]`, `Dict[...]`.
   - Every function, method, and class attribute MUST have explicit type annotations.
   - `mypy --strict src/canary_ci` MUST pass with **0 errors**. Never add blanket `# type: ignore` without a specific error code (`# type: ignore[import-untyped]`) and justification.
2. **Linting & Formatting:**
   - `ruff check src tests` and `ruff format --check src tests` MUST pass with **0 warnings/errors**.
   - Line length limit: `100` characters.
3. **Dependencies:**
   - Use ONLY dependencies already declared in `pyproject.toml`.
   - Optional dependencies (`litellm`, `playwright`) MUST be imported lazily inside their specific adapter modules (`litellm_mcp.py`, `playwright_adapter.py`) with a clear `MissingExtraError("Install with: uv pip install 'canary-ci[llm]'")` if absent, so core CLI & unit tests run without optional extras installed.
4. **Error Handling & Exit Codes:**
   - Raise domain-specific subclasses of `CanaryCIError` (defined in `src/canary_ci/core/errors.py`), never bare `Exception` or `RuntimeError`.
   - CLI commands MUST adhere strictly to exit codes:
     - `0` = All scenarios passed policy thresholds (or command succeeded)
     - `1` = Security breach / policy threshold failure detected (deterministic test FAIL)
     - `2` = Configuration, schema validation, or CLI usage error
     - `3` = Target agent execution crash / adapter connection timeout

---

## 4. Verification for changes

Read the requirements for the change and the relevant schemas before editing. Keep production changes within the package boundaries above. Cover the requested behavior through the public API or CLI using offline fixtures. For detection changes, verify both the breach and benign cases.

Run these checks from the repository root and confirm the acceptance criteria for the change.

```bash
uv run --extra dev ruff check src tests examples
uv run --extra dev ruff format --check src tests examples
uv run --extra dev mypy src/canary_ci
uv run --extra dev pytest
```
