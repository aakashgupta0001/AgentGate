# AGENTGATE

**Achithon 2026 · Problem Statement 08 · Team Syntaxis**

AGENTGATE is a local educational prototype of an authorization gateway between a hospital AI assistant and three protected tools: document reading, report saving, and mock inbox delivery. The assistant may propose an action; only the gateway evaluates trusted policy and invokes the tool.

> **The AI proposes. AGENTGATE decides. The tool executes only after authorization.**

This is a hackathon/research demonstration. It is not production-ready, HIPAA-compliant, clinically validated, or a guarantee against every AI security failure. All patient records, identities, names, and inboxes are synthetic.

## Threat model and architecture

The prototype assumes a compromised or mistaken AI agent may follow malicious instructions embedded in document text. The agent output is strictly parsed and treated as an untrusted proposal. The gateway independently checks the user, agent, operation, stored resource, purpose, recipient, and trusted data label before dispatching through a fixed action-to-tool mapping. Unknown policy subjects, recipients, resources, and invalid proposals are denied. A denied operation does not call its protected tool.

Trusted policy is loaded from `policy/policy.yaml` and its exact bytes are SHA-256 hashed. Each decision records that policy hash. The digest is an integrity identifier, **not** a signature or independent protection against someone who can change both the policy and application files.

SQLite stores artifacts, labels, source links, workflow access history, inbox deliveries, classification history, and audit events. Artifact labels are stored in dedicated columns. A report inherits the strictest label of its tracked sources. Reads are scoped to a workflow session; derivation sources are collected from both explicit dependencies and that session's access history.

Audit events are canonicalized and connected by a SHA-256 hash chain. It detects tested edits and accidental corruption. Because the chain is in the same writable SQLite database, an attacker with sufficient database access can rewrite the chain; this is not an immutable external audit service.

The declassification screen is separate from the AI tool interface. Only an identity with the policy's privacy-officer role can request a configured downward classification change. The change and history are transactional and audited.

## Technology

- Python (tested in this workspace with Python 3.14.6; the target project range is 3.11/3.12)
- Pydantic v2, PyYAML, SQLite, Streamlit
- pytest, pytest-cov, Hypothesis
- Faker with the `en_IN` locale for deterministic synthetic seed names
- Optional local Ollama and optional hosted Anthropic API, both disabled unless configured

## Structure

```text
agentgate/       models, policy, gateway, labels, storage, tools, audit, agent
data/            deterministic synthetic seed data and attack scenarios
policy/          trusted YAML authorization configuration
scripts/         database initialization, seed, audit verification
tests/           gateway, information-flow, persistence, audit, property tests
storage/         local runtime SQLite database (ignored by Git)
app.py           Streamlit dashboard
```

## Installation and startup

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python scripts\init_db.py
python scripts\seed_demo.py
streamlit run app.py
```

Use `py -3.11` if that is the Python runtime available to you. In this workspace, the available interpreter was Python 3.14.6; use its interpreter explicitly if needed:

```powershell
& "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe" -m pip install -r requirements.txt
& "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe" -m streamlit run app.py
```

### macOS / Linux

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python scripts/init_db.py
python scripts/seed_demo.py
streamlit run app.py
```

The database path and policy path can be changed through `AGENTGATE_DB_PATH` and `AGENTGATE_POLICY_PATH`. Seeding is idempotent and does not reset a populated database. All runtime databases, `.env` files, generated records, and local logs are excluded by `.gitignore`.

## Demonstration

The default mode is `simulation`. The dashboard labels scripted behavior **SIMULATION — SCRIPTED COMPROMISED AGENT**; it is not live LLM output.

1. Run an authorized doctor read of `LAB-0001`.
2. Save a summary. The saved report's label is calculated from trusted source metadata.
3. Try the poisoned report's embedded instruction by attempting delivery to `external_email`. It is denied by the gateway and never appears in the mock inbox.
4. Deliver `REPORT-0001` to `doctor_inbox` to demonstrate a permitted action.
5. Inspect the decision feed, SQLite-backed mock inbox, provenance graph, and audit explorer.
6. Resume a workflow to reload stored labels and read history.
7. Select `privacy_001` to explore the separately authorized classification workflow. Try `doctor_001` to verify denial.

The synthetic data includes a public brochure, internal duty roster, confidential billing record, and patient-restricted lab report. The hostile instruction embedded in the lab text is intentionally untrusted content; the policy parser never reads document content.

## Optional model modes

The core gateway and simulation do not need a model, internet access, or API key. Model responses are strictly validated and still pass through the same gateway.

For Ollama, set `AGENTGATE_MODEL_MODE=ollama`, `OLLAMA_HOST`, and an installed `OLLAMA_MODEL`. AGENTGATE does not download models. For hosted Anthropic, set `AGENTGATE_MODEL_MODE=anthropic`, `ANTHROPIC_MODEL`, and `ANTHROPIC_API_KEY` in the ignored `.env`. Never place credentials in source code or commit `.env`. Model provider calls are optional; errors are explicit, with no silent permissive fallback.

## Policy and information-flow rules

`policy/policy.yaml` contains synthetic identities, roles, operations, resource scopes, purposes, recipient clearances, and declassification targets. The effective permissions are checked for both user and agent; the agent's capabilities cannot substitute for the user's permission. Policy changes require an explicit reload/new application start to recalculate the policy hash.

Labels are ordered `PUBLIC < INTERNAL < CONFIDENTIAL < PATIENT_RESTRICTED`. A recipient may receive data only if the stored effective label is at or below its configured clearance. Saving derived artifacts uses authoritative labels for all sources read in that session and preserves source relationships. A text summary cannot lower a label.

## Database, audit, and tests

```powershell
python scripts\init_db.py
python scripts\seed_demo.py
python scripts\verify_audit.py
python -m pytest
python -m pytest --cov=agentgate --cov-report=term-missing
```

Use forward-slash script paths on Unix-like shells. `verify_audit.py` exits nonzero when the chain is invalid. The test suite uses an isolated temporary database and tool spies. It tests that denied reads, saves, and deliveries do not execute their underlying tools, along with label propagation, persistence/resumption, authorization, and audit tampering.

## Known limitations and security boundaries

- This is a local single-host prototype, not a production authorization service. It has no authenticated identity provider, external policy signing, deployment hardening, or independently protected audit sink.
- Demo identities are selectable simulated identities, not proof of a user's real identity. The policy YAML and local database are trusted inputs only within the demo's assumed local boundary.
- SQLite transaction locking protects the authorization/read/write path from concurrent local changes during a gateway call, but does not defend against an administrator who can replace the app or database.
- The optional model adapters only generate proposals. Prompt-injection detection is not claimed; malicious text can influence a model, and the gateway's independent checks are the defense demonstrated here.
- Declassification is auditable but does not rewrite derived artifacts' stored labels. A protected ancestor can continue to keep a derived artifact's effective label high.
- No real email, clinical decision, or patient data is used. Do not connect this prototype to clinical systems or real patient records.

Potential future work includes signed policy releases, external immutable audit export, authenticated identities, stronger concurrency/version controls for multi-process deployment, and independent security review.
