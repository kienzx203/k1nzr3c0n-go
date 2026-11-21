#!/usr/bin/env python3
"""
Unified LLM client. Picks a provider from env (set by the Go server from the
active model profile) so verify + report work with the Claude SUBSCRIPTION or
with an API-key provider (Anthropic API / OpenAI-compatible / Ollama).

Env:
  LLM_PROVIDER = sub | anthropic | openai | ollama   (default: sub)
  LLM_MODEL    = model id
  LLM_BASE     = base URL (optional; provider default otherwise)
  LLM_KEY      = API key (never logged, never placed on argv)

API: complete(system, user, max_tokens, timeout) -> text
     complete_json(system, user, ...) -> parsed obj (or {})
     test() -> (ok, msg)
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request

DEFAULT_BASE = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
}


def _profile():
    return {
        "provider": (os.environ.get("LLM_PROVIDER") or "sub").strip().lower(),
        "model": (os.environ.get("LLM_MODEL") or "sonnet").strip(),
        "base": (os.environ.get("LLM_BASE") or "").strip().rstrip("/"),
        "key": os.environ.get("LLM_KEY") or "",
    }


def _subenv():
    env = dict(os.environ)
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
              "LLM_PROVIDER", "LLM_MODEL", "LLM_BASE", "LLM_KEY"):
        env.pop(k, None)
    return env


def _claude_text(system, user, model, timeout):
    if shutil.which("claude") is None:
        raise RuntimeError("claude CLI not found (subscription login)")
    work = tempfile.mkdtemp(prefix="sastk1nz_cl_")
    cmd = ["claude", "-p", "Trả lời dựa trên JSON/nội dung trên stdin.",
           "--model", model or "sonnet", "--effort", "high",
           "--system-prompt", system, "--disable-slash-commands",
           "--no-session-persistence", "--strict-mcp-config",
           "--mcp-config", '{"mcpServers":{}}', "--output-format", "json"]
    try:
        p = subprocess.run(cmd, input=user, capture_output=True, text=True,
                           timeout=timeout, cwd=work, env=_subenv())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    try:
        meta = json.loads(p.stdout)
        if isinstance(meta, dict) and isinstance(meta.get("result"), str):
            return meta["result"]
    except json.JSONDecodeError:
        pass
    return p.stdout


def _http(url, headers, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={**headers, "Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 (our own call)
        return json.loads(r.read().decode())


def _anthropic(system, user, p, max_tokens, timeout):
    base = p["base"] or DEFAULT_BASE["anthropic"]
    j = _http(base + "/v1/messages",
              {"x-api-key": p["key"], "anthropic-version": "2023-06-01"},
              {"model": p["model"], "max_tokens": max_tokens, "system": system,
               "messages": [{"role": "user", "content": user}]}, timeout)
    parts = j.get("content") or []
    return "".join(b.get("text", "") for b in parts if isinstance(b, dict))


def _openai(system, user, p, max_tokens, timeout):
    base = p["base"] or DEFAULT_BASE["openai"]
    h = {"Authorization": "Bearer " + p["key"]} if p["key"] else {}
    j = _http(base + "/chat/completions", h,
              {"model": p["model"], "max_tokens": max_tokens,
               "messages": [{"role": "system", "content": system},
                            {"role": "user", "content": user}]}, timeout)
    return (((j.get("choices") or [{}])[0].get("message") or {}).get("content")) or ""


def complete(system, user, max_tokens=4096, timeout=600):
    p = _profile()
    if p["provider"] in ("", "sub", "claude", "subscription"):
        return _claude_text(system, user, p["model"], timeout)
    if p["provider"] == "anthropic":
        return _anthropic(system, user, p, max_tokens, timeout)
    if p["provider"] in ("openai", "openai-compat", "ollama", "compat"):
        return _openai(system, user, p, max_tokens, timeout)
    raise RuntimeError("unknown provider: " + p["provider"])


def complete_json(system, user, max_tokens=4096, timeout=300):
    txt = complete(system + "\nTrả về DUY NHẤT một JSON hợp lệ, không văn bản thừa.",
                   user, max_tokens, timeout)
    m = re.search(r"\{.*\}|\[.*\]", txt or "", re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}


def provider():
    return _profile()["provider"]


def test():
    p = _profile()
    try:
        t = complete("Bạn là trợ lý. Trả lời đúng 1 từ.", "ping", max_tokens=8, timeout=60)
        return True, "%s/%s OK: %s" % (p["provider"], p["model"], (t or "").strip()[:40])
    except Exception as e:  # noqa: BLE001
        return False, "%s/%s FAIL: %s" % (p["provider"], p["model"], str(e)[:160])


if __name__ == "__main__":
    ok, msg = test()
    print(json.dumps({"ok": ok, "detail": msg}))
