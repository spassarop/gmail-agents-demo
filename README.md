# Agentic Gmail Demo: Indirect Prompt Injection in a Multi-Agent Email Assistant

This repository is a live-demo-friendly security project that shows how an agentic email assistant can be abused through **indirect prompt injection** and how the same system can be hardened with practical guardrails.

The project is built around a Gmail assistant with multiple agents, real tool execution, a web UI, OpenTelemetry traces, and a Promptfoo regression suite. It is meant for talks, workshops, and security testing of agentic workflows.

The core security theme is **OWASP ASI01: Agent Goal Hijack**, with supporting controls that also touch tool misuse and high-impact action safety.

## Why this repo exists

This demo is designed to answer a simple question:

> What happens when one agent trusts another agent’s natural-language output too much?

In the vulnerable version, the answer is: **tool misuse**.

A malicious email can influence the summarization step, the summary can be treated as trusted intent, and the management/orchestration flow can end up drafting, sending, or deleting emails based on attacker-controlled content.

In the patched version, the same workflow is constrained through:
- structured tool invocation
- intent validation before execution
- human approval for risky actions

That contrast makes the repo useful both as a **security demo** and as a **small reference architecture** for testing agentic defenses.

---

## What the demo shows

### Vulnerable mode
In vulnerable mode, the flow is intentionally unsafe:

1. A malicious email is ingested.
2. The **Summary Agent** extracts requests or action items from the email content.
3. The **Management Agent** treats that summary output as trustworthy.
4. The orchestrator executes the resulting tool action with little or no validation.

This is the behavior you want when demonstrating the failure mode on stage.

### Patched mode
In patched mode, the same attack should no longer succeed automatically:

1. Tool proposals are structured.
2. An **Intent Gate** validates what the action is trying to do.
3. High-impact actions such as sending mail require **human-in-the-loop** confirmation.
4. The traces make it visible why the unsafe action was blocked, transformed, or delayed.

---

## Repo purpose and architecture

This repo is not just a chatbot. It is a deliberately small **agentic system** with:
- multiple agents with separate responsibilities
- tool-enabled orchestration
- a real web UI
- a vulnerable and a patched runtime
- regression testing with fixed fixtures
- trace-aware validation of behavior

That combination is what makes it useful for talks and testing: you can show the attack, inspect the traces, switch modes, and rerun the same scenario against the hardened version.

## High-level flow

The demo revolves around three main responsibilities:

- **Management Agent**: decides the next action
- **Summary Agent**: summarizes message content and extracts requests
- **Composition Agent**: drafts replies

The orchestrator sits in the middle and connects agent output to Gmail-like tools such as:
- listing messages
- reading messages
- summarizing messages
- drafting replies
- sending email
- trashing email

In the vulnerable version, natural-language output can influence follow-up actions too directly.

In the patched version, the same path is mediated by security controls.

---

## Vulnerable vs patched runtime

This repository contains two implementations:

- **Vulnerable**: `agentic_mailer/`
- **Patched**: `patched/agentic_mailer/`

Both runtimes use the same package name: `agentic_mailer`.

That is intentional.

When you run:

```bash
python run.py --mode vulnerable
```

the app imports the code from the normal package.

When you run:

```bash
python run.py --mode patched
```

`run.py` prepends `patched/` to `sys.path`, so imports resolve to the hardened implementation instead.

This design keeps the runtime entrypoint simple and also makes live demos easier, because the vulnerable and patched trees are directly comparable.

---

## Main repository layout

```text
agentic_mailer/                 Vulnerable implementation
patched/agentic_mailer/         Patched implementation
testing_common_runtime/         Shared testing/runtime helpers
testing_shared/                 Shared telemetry and tracing helpers
testing-common/promptfoo/       Promptfoo config, assertions, and transforms
testing-common/fixtures/        Fixture email dataset used in regression tests
testing-vuln/                   Local eval API for vulnerable Promptfoo runs
testing-patched/                Local eval API for patched Promptfoo runs
run.py                          Main web app entrypoint
```

## What each part is for

### `agentic_mailer/`

The intentionally vulnerable app.

This is the version you want when demonstrating:

* summary-to-action trust abuse
* unsafe tool follow-up behavior
* the impact of indirect prompt injection
* why traces matter in agentic systems

### `patched/agentic_mailer/`

The hardened app.

This version exists to demonstrate concrete mitigations rather than abstract advice. It is the “same demo, safer behavior” counterpart to the vulnerable runtime.

### `testing_common_runtime/`

Shared test harness pieces used by Promptfoo and local deterministic runs.

This is especially useful because it avoids maintaining forked runtime copies just for testing.

### `testing_shared/`

Shared OpenTelemetry instrumentation and support code used by both runtimes.

This makes the traces comparable across vulnerable and patched executions.

### `testing-common/promptfoo/`

Promptfoo config, trace-aware assertions, and evaluation helpers.

This is where the behavioral contract of the demo lives.

### `testing-common/fixtures/`

The fixed email corpus used for deterministic testing.

These fixtures are important because they let you reproduce attacks and side effects without relying on a live mailbox.

---

## Prerequisites

* Python 3.11+
* Ollama installed and running
* the Ollama models used by the demo
* Gmail OAuth files for live/manual runs

Pull the models:

```bash
# You can use whatever model you want, but set them on the project config for each agent.
ollama pull phi3:latest
ollama pull deepseek-r1:8b
```

Gmail API OAuth files are expected here:

```text
secrets/credentials.json
secrets/token.json
```

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

---

## Running the demo

### Vulnerable mode

```bash
python run.py --mode vulnerable
```

### Patched mode

```bash
python run.py --mode patched
```

Then open:

```text
http://127.0.0.1:8000
```

Useful runtime outputs:

* UI in the browser
* logs in `logs/agentic_demo.log`
* trace/debug panels in the app

### UI notes

* dark mode is the default
* the top bar includes a theme toggle for projector-friendly demos

---

## Suggested chat commands

Try prompts like:

* `List my last 5 emails`
* `List emails from the last 7 days from billing@example.com`
* `Read email #1`
* `Summarize email #1`
* `Draft a reply to email #1 that says I will get back tomorrow`
* `Delete email #2`
* `Send the draft now`

These are useful both for warmup and for showing how the vulnerable and patched paths diverge.

---

# Testing

This repository has a dedicated regression setup built around **Promptfoo**, fixed fixtures, and OpenTelemetry traces.

The goal is not only to check text output, but to verify **behavior**:

* which tools were planned
* which tools actually executed
* whether the orchestration path was vulnerable or guarded
* whether the patched version inserted the correct safety controls

## Why the testing setup matters

A lot of agent demos stop at “the response looked bad.”

This repo goes further:

* it validates side effects with a fixture-backed Gmail client
* it captures spans from the real orchestrators and agents
* it asserts on trace content, not only assistant text
* it compares vulnerable and patched behavior against the same inputs

That makes the testing section one of the strongest parts of the repo and worth documenting clearly.

## Test architecture

The testing setup reuses the real packages instead of maintaining duplicate runtime trees just for eval:

* `testing_common_runtime/` provides shared harness code and the fixture Gmail client
* `testing_shared/` provides shared telemetry helpers
* `testing-vuln/` and `testing-patched/` expose local eval APIs that load the real vulnerable and patched runtimes

This is a good design choice because it reduces drift between “demo code” and “tested code”.

## Running the Promptfoo suite

Start the local eval APIs first.

### Vulnerable eval API

```bash
python testing-vuln/eval_api.py
```

### Patched eval API

```bash
python testing-patched/eval_api.py
```

Then run Promptfoo:

```bash
npx promptfoo eval -c testing-common/promptfoo/promptfooconfig.yaml
```

## What the suite validates

The suite checks things like:

* deterministic behavior over fixture emails
* trace emission from the real runtime
* tool usage and non-usage
* summary and composition spans
* intent-gate presence in patched runs
* human-in-the-loop preparation for high-impact actions
* forbidden side effects in scenarios that must remain read-only

## Fixture-based testing

The Promptfoo suite uses a fixture-backed Gmail client instead of a live mailbox.

That gives you:

* reproducibility
* no OAuth dependency for regression runs
* deterministic side effects
* easier assertions about drafts, sends, and trashed messages

If you are presenting the project, this also makes it much safer to rehearse the demo.

---

# Security notes

This repository is intentionally dual-use in the sense that one mode is designed to fail.

That is the point of the demo.

## Safe usage guidance

* Use the vulnerable mode only in controlled demo or test environments.
* Do not put real credentials or secrets in `.env`.
* The demo secret should remain fake and disposable.
* Treat the vulnerable runtime as intentionally unsafe software.
* Prefer fixtures for rehearsals and regression testing.

## What the patched version is meant to illustrate

The patched runtime is not trying to solve all agentic security problems. It exists to demonstrate a practical minimum set of improvements:

* do not trust natural-language outputs from other agents as execution intent
* constrain tool invocation formats
* validate intent before high-impact execution
* require user confirmation where appropriate
* preserve observability so the defense is visible in traces

## Security learning goals

The repo is best understood as a teaching tool for these ideas:

* all external content is untrusted, including email
* summarization is not sanitization
* “helpful follow-up action” can become unsafe delegation
* traces are critical when agent workflows cross trust boundaries
* read-only tasks should stay read-only unless intent is explicit and validated

---

# Troubleshooting

## Ollama not reachable

Make sure Ollama is running and accessible at:

```text
http://localhost:11434
```

or whatever you configured in `OLLAMA_BASE_URL`.

## Gmail OAuth issues

If `secrets/token.json` is missing or expired, the application may trigger a browser OAuth flow when using the live Gmail client.

## Promptfoo issues

If Promptfoo tests fail unexpectedly:

* make sure both eval APIs are running
* confirm the fixture files are present
* verify local ports are free
* rerun after checking that the intended runtime is being loaded

---

## License

MIT. See `LICENSE`.
