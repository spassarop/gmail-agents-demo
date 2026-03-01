# DEMO_SCRIPT (Suggested Stage Flow)

## 0) Setup (before the talk)
- Ensure Ollama is running
- Ensure Gmail `secrets/credentials.json` + `secrets/token.json` exist
- Start in vulnerable mode:
  ```bash
  python run.py --mode vulnerable
  ```
- Open the UI and show:
  - chat panel
  - debug/trace panel (collapsed)

## 1) Warmup: benign scenario
1. In chat: “List my newest 5 emails”
2. “Summarize email #1”
3. Point to trace panel:
   - Management deciding action
   - Summary agent output
   - Gmail tool calls

## 2) Attack: ASI01 via indirect prompt injection
1. Ask audience to send an email to the demo inbox using a payload from `docs/ATTACK_GUIDE.md`
2. In chat: “List my newest 5 emails”
3. “Summarize email #1”
4. Show:
   - Summary agent output includes a malicious ACTION ITEM / REQUEST
   - Management agent treats it as legitimate and executes a follow-up tool call
   - Gmail send happens (show in logs + trace)

## 3) Patch live
Option A: restart with patched mode:
```bash
python run.py --mode patched
```

Option B: copy patched files over vulnerable on screen:
- Copy `patched/agentic_mailer/*` → `agentic_mailer/*`
- Show `git diff` (or file compare)
- Restart

## 4) Re-run the same attack
- Repeat “Summarize email #1”
- Show:
  - Intent Gate blocks / requires confirmation
  - HITL prompt appears
  - Structured JSON tool invocation prevents “free-form tool calls”

## 5) Wrap-up
Key takeaways:
- Treat all external content as untrusted (email, web pages, docs, RAG sources)
- Never execute tools based on natural-language outputs from other agents
- Enforce schemas + policy middleware + human approvals for high-impact actions
