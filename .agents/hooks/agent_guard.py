"""Antigravity PreToolUse hook for invoke_subagent.

Logs subagent spawns and restricts the 'pro' model tier to authorized
design/planning roles only.

Conforms to Antigravity hook stdout schema:
  {"decision": "allow"|"deny", "reason": "..."}
"""
import datetime
import json
import os
import sys

# Roles permitted to use the expensive 'pro' tier
ALLOW_EXPENSIVE = {"architect", "planner", "rag-consultant"}

# Model strings that map to the expensive tier
EXPENSIVE_MODELS = {"pro", "gemini-2.5-pro", "gemini-1.5-pro", "opus"}

raw = sys.stdin.read()
try:
    event = json.loads(raw)
except Exception:
    # Fail open on un-parseable payload
    print(json.dumps({"decision": "allow"}))
    sys.exit(0)

tool_call = event.get("toolCall") or {}
tool_name = tool_call.get("name", "")

if tool_name != "invoke_subagent":
    print(json.dumps({"decision": "allow"}))
    sys.exit(0)

args = tool_call.get("args") or {}
agent_role = str(args.get("Role") or args.get("TypeName") or "").strip().lower()
model_choice = str(args.get("Model") or "").strip().lower()

blocked = (
    bool(model_choice)
    and any(m in model_choice for m in EXPENSIVE_MODELS)
    and not any(a in agent_role for a in ALLOW_EXPENSIVE)
)

# --- Audit log ---
root = (
    event.get("workspacePaths", [None])[0]
    or os.environ.get("AGY_PROJECT_DIR")
    or event.get("cwd")
    or "."
)
try:
    log_dir = os.path.join(root, ".agents")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "agent-calls.jsonl"), "a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                    "conversation_id": event.get("conversationId"),
                    "role": agent_role or None,
                    "model": model_choice or None,
                    "blocked": blocked,
                    "prompt_preview": str(args.get("Prompt", ""))[:120],
                }
            )
            + "\n"
        )
except Exception:
    pass  # Never let logging crash the guard

# --- Decision ---
if blocked:
    print(
        json.dumps(
            {
                "decision": "deny",
                "reason": (
                    f"Model tier '{model_choice}' is reserved for "
                    f"{', '.join(sorted(ALLOW_EXPENSIVE))}. "
                    f"Run '{agent_role or 'this task'}' using 'flash' or 'flash_lite'."
                ),
            }
        )
    )
else:
    print(json.dumps({"decision": "allow"}))

sys.exit(0)

