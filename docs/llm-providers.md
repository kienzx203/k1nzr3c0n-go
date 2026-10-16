# LLM provider templates

ScopeWeaver supports four profile formats: **Anthropic**, **OpenAI Chat Completions**, **OpenAI Responses** and native **Ollama**. Every format keeps its custom base URL, proxy, session header, retry, rate and concurrency settings, so cloud providers, gateways and self-hosted OpenAI-compatible servers keep working unchanged. Ollama is optional, and cloud providers remain the default-compatible path.

A template fills a **new profile's form** without saving credentials, activating a profile, or modifying existing profiles. Ollama templates also read installed models from the selected server; cloud templates make no requests. Format, base URL and model stay editable after any template.

## Z.ai GLM-5.3

![GLM-5.3 new-profile template](../screenshots/en/llm-templates.png)

Template preview with no API key entered; this is not a live provider connection.

Open **LLM → New → Configuration template**. Choose **General API (recommended)** for API billing, or **Coding Plan (reference)** only after obtaining Z.ai authorization for ScopeWeaver.

| Field | General API | Coding Plan reference |
| --- | --- | --- |
| Format | OpenAI Chat Completions | OpenAI Chat Completions |
| Base URL | `https://api.z.ai/api/paas/v4` | `https://api.z.ai/api/coding/paas/v4` |
| Model | `glm-5.3` | `glm-5.3` |
| Thinking | `enabled` | `enabled` |
| Reasoning effort | `max` | `max` |
| Context window (K) | `1000` | `1000` |
| Output limit | `0` (omit; provider default) | `0` (omit; provider default) |

The endpoints and billing are distinct: General API usage is separate from Coding Plan subscription quota. See [Z.ai connection configuration](https://zcode.z.ai/en/docs/configuration). Confirm your account's model access and billing before testing.

GLM-5.3 accepts text, has a 1M-token context window, and requires reasoning to remain enabled. Supported effort values are `low`, `high`, and `max`; this template uses `max`. The model field remains editable, so review reasoning and context settings when choosing another model. See the [official GLM-5.3 guide](https://docs.z.ai/guides/llm/glm-5.3).

**Coding Plan support boundary:** Z.ai limits Coding Plan to officially supported tools. ScopeWeaver is not on that list; an endpoint template does not establish permission or support. Obtain Z.ai authorization before using it here. See [tool integration](https://docs.z.ai/devpack/tool/others) and [usage policy](https://docs.z.ai/devpack/usage-policy). ScopeWeaver does not impersonate supported tools or switch billing endpoints automatically.

Enter a profile name and your own API key. Applying either template preserves any name, key, proxy, session-header setting, and other unrelated preferences already entered. Save when ready; a new profile must be activated separately. The existing **Test connection** and **Load models** controls make real provider requests only when clicked; this change does not perform a live provider test.

Verified against official documentation on **2026-10-03**. Provider availability, account entitlement, and policies may change.

## Native Ollama (local inference)

ScopeWeaver talks to Ollama through its native `/api/chat` API. Ollama's OpenAI-compatible endpoint has no way to set the context size ([Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility)), so a profile pointed at `/v1` cannot guarantee `num_ctx`. The native format sends it on every request. A base URL ending in `/v1`, `/api` or `/api/chat` is normalized to the server root.

Ollama's documented default context differs between pages: the [FAQ](https://docs.ollama.com/faq) states 4,096 tokens, and the [context length page](https://docs.ollama.com/context-length) describes a VRAM-based default (about 4K below 24 GiB, 32K for 24–48 GiB, 256K above). ScopeWeaver therefore does not rely on the server default.

### Templates

Open **LLM → New → Configuration template → Local inference (Ollama)**.

| Field | Same machine | Host from Docker | Bundled Compose service |
| --- | --- | --- | --- |
| Format | Ollama (native /api/chat) | Ollama (native /api/chat) | Ollama (native /api/chat) |
| Base URL | `http://127.0.0.1:11434` | `http://host.docker.internal:11434` | `http://ollama:11434` |
| Model | Installed model from this server | Installed model from this server | Installed model from this server |
| API key | empty | empty | empty |
| Context window (K) | `32` (`num_ctx` 32,768) | `32` | `32` |
| Max concurrent requests | `1` | `1` | `1` |
| Keep-alive | `30m` | `30m` | `30m` |
| Output limit | `4096` | `4096` | `4096` |
| Thinking / effort | omitted (model default) | omitted | omitted |

Selecting an Ollama template reads `/api/tags` and model metadata from the selected endpoint, then chooses an installed model, preferring one that declares `tools`. Choosing the Ollama format for a new profile does the same; a blank endpoint or an unchanged cloud-template endpoint uses the host default. A custom endpoint stays unchanged. The model is blank while discovery runs, and stays blank with an error if discovery fails or the list is empty. Check the endpoint, optional token and proxy, then click **Load models** or enter a model tag manually. Editing the model or connection fields cancels the pending selection; late responses cannot overwrite those edits. Opening an existing profile preserves its stored model. Selection never downloads or runs a model, saves, or activates a profile. **Test connection** runs only when clicked.

**API key behavior:** Ollama templates and switching to the Ollama format clear an unsaved key before discovery. Ollama templates keep the profile name, proxy, session header and other entered preferences, but **clear any unsaved API key** so a cloud credential is never sent to a local endpoint. The GLM templates still keep an entered key. Leave the key blank for local Ollama; enter a token only when a reverse proxy in front of Ollama requires one (it is sent as `Authorization: Bearer`). Keyless Ollama profiles can be tested, saved, activated and used in failover; the profile card shows **No key needed** instead of a missing-key warning. When you edit a saved native Ollama profile, a blank key field keeps the saved token; switching a cloud profile to Ollama with the field blank deletes the old cloud key.

**Keys for the other formats:** Anthropic and OpenAI formats require a key unless the base URL is explicitly local, meaning its host resolves only to loopback or private addresses. A keyless local OpenAI-compatible server such as vLLM or LM Studio therefore works with a blank key. ScopeWeaver then sends an internal non-secret placeholder so the SDK does not inherit `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` from the environment. A non-local endpoint with no key is refused (*llm: API key required for non-local compatible endpoint*).

### Context, output and residency controls

| Setting | Ollama behavior | Cloud formats |
| --- | --- | --- |
| Context window (K) | Binary K sent as `options.num_ctx` (32 = 32,768). `0` uses 32; values below 16 use 16. Also sets the compaction budget. | Unchanged: compaction budget only, `0` = 200K |
| Output limit | Sent as `options.num_predict`; `0` uses 4,096 | Unchanged: `0` omits the field |
| Keep-alive | Sent as `keep_alive`; blank uses `30m` (Ollama's own default is 5 minutes) | Not sent |
| Max concurrent requests | `0` uses 1. One admission gate is shared per Ollama server, even across profiles | `0` inherits **System settings → Max concurrent LLM requests** |

Raise concurrency only when the server sets `OLLAMA_NUM_PARALLEL` above 1. Ollama's memory use grows with `OLLAMA_NUM_PARALLEL × context length` ([FAQ](https://docs.ollama.com/faq)).

### Runtime safeguards

- **Pre-warm:** before the first inference through a native profile, ScopeWeaver calls `/api/show`, refuses a model that does not declare `tools`, then loads the model with an empty `/api/chat` request using the profile's `num_ctx` and `keep_alive`. Warm-up runs inside the same concurrency slot.
- **Compaction:** for native Ollama with a window of 64K or less, history compaction triggers at 75% of the window and keeps complete tool call/result pairs. If experimental noa compaction is enabled, this safeguard takes priority for those profiles: noa is skipped and a warning is emitted. At 32K or less, the part of each tool output given to the model is capped at 16,384 **bytes** (16 KiB, measured as the SDK's `len(s)`, not Unicode characters); the full output is preserved in a spill file referenced from the tool result. Cloud formats keep their existing compaction and noa behavior.
- **Approval judge:** when the judge profile (or the active profile, if no judge profile is selected) is Ollama, the default timeout becomes **60 s** and the default failure action becomes **ask**. A timeout or failure action you saved explicitly is preserved.

### Generic OpenAI-compatible servers (vLLM, LM Studio)

The existing formats remain selectable for these servers: choose **OpenAI (Chat Completions)** and point the base URL at the server's `/v1` endpoint. Do not use the native Ollama format for them.

- **Load models** in the native format reads `/api/tags`; if that returns HTTP 404 or 405 it falls back to `/v1/models`, so a generic server's model list can appear.
- Chat **never** switches silently: a native profile always calls `/api/chat`, which a generic server does not provide. The resulting "model or endpoint not found" error and its `ollama pull` hint do not apply there; pulling a model does not fix a vLLM or LM Studio server. Change the format to OpenAI instead.

### Load models and Test connection

**Load models** reads `/api/tags` and `/api/show`. Each entry shows parameter size, quantization and `tools` / `thinking` / `vision` badges. A model whose metadata omits `tools` shows: *"Warning: This model does not declare native tool-calling support. ScopeWeaver agents require tool calling to update the asset and exploration graphs."* Failed metadata is shown as unknown, not as missing.

**Test connection** checks the model with `/api/show`, runs a one-turn tool-call smoke test with the profile's `num_ctx`, `keep_alive` and `num_predict`, and reads `/api/ps`. The panel shows whether the allocated context covers the request, whether the tool call returned, cold-load time in milliseconds and generation speed in tokens/s. A missing model shows the exact command to run on the server, for example `ollama pull qwen2.5-coder:32b`. ScopeWeaver does not pull models or create Modelfiles.

### Host and container routing

| ScopeWeaver runs | Ollama runs | Base URL |
| --- | --- | --- |
| On the host | On the same host | `http://127.0.0.1:11434` |
| In Docker Compose | On the host | `http://host.docker.internal:11434` |
| In Docker Compose | Bundled `ollama` service | `http://ollama:11434` |

Inside a container, `127.0.0.1` is the container itself. Compose maps `host.docker.internal` to the host gateway (`host-gateway`). Ollama binds `127.0.0.1:11434` by default; on Linux the host Ollama must listen on an address the container can reach (for example `OLLAMA_HOST=0.0.0.0:11434`), which exposes it to the network. Restrict port 11434 with a firewall.

**Optional Compose service:** `docker compose --profile local-llm up -d` starts the `ollama` service with `OLLAMA_NO_CLOUD=1`, `OLLAMA_KEEP_ALIVE=30m`, `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_CONTEXT_LENGTH=32768` and the `ollama_data` volume. Pull a model with `docker compose exec ollama ollama pull qwen2.5-coder:14b`. Without the profile, Compose behaves as before. The bundled service requests no GPU. **On macOS, Docker containers cannot use the Apple GPU, so this service runs on CPU only**; for usable speed, run Ollama natively on the Mac and use the host template.

### Network policy (`local_llm_only`)

Off by default; cloud providers remain available. Turn it on in **System settings → Local-only LLM network** or with `SCOPEWEAVER_LOCAL_LLM_ONLY=true`. When on:

- It applies to **LLM HTTP only**: inference, model lists, connection tests, warm-up and the approval judge. Target traffic, other web search backends and the global proxy are unaffected.
- **DeepSeek web search is unavailable**, even if its endpoint is in a trusted CIDR: the SDK makes that remote LLM call with its own HTTP client, and there is no path to inject this connection guard into it. Turning the policy off restores DeepSeek search.
- Allowed destinations are loopback, private IPv4 (RFC 1918) and IPv6 unique-local addresses, plus **trusted CIDRs** (`local_llm_allowed_cidrs`). A trusted range is treated like a private LLM server, so add only networks you control.
- CIDRs from `SCOPEWEAVER_LOCAL_LLM_ALLOWED_CIDRS` apply in addition to the stored list; they are not copied into it and cannot be edited in the UI.
- Changes in System settings apply to the next LLM HTTP calls without a restart.
- The resolved IP is checked when each connection opens. DNS names that resolve to any public address are refused, and redirects to public addresses fail the same way.
- **LLM profile proxies are rejected.**
- An environment value of `true` is a floor; it cannot be switched off in the UI.

ScopeWeaver cannot see what an Ollama server does next. **Ollama can forward requests to Ollama cloud models**; the bundled Compose service sets `OLLAMA_NO_CLOUD=1`, but a host or remote Ollama must disable cloud independently (`OLLAMA_NO_CLOUD=1` or `disable_ollama_cloud` in `~/.ollama/server.json`, per the [FAQ](https://docs.ollama.com/faq)).

### Environment and configuration

`SCOPEWEAVER_LLM_*` overrides `ARTEX_LLM_*`; an explicitly empty modern variable also overrides the legacy one. Both override the `llm` block in `config.json` (path from `SCOPEWEAVER_CONFIG` or `ARTEX_CONFIG`).

| Suffix | Meaning |
| --- | --- |
| `PROVIDER` | `anthropic`, `openai`, `openai-responses` or `ollama` |
| `MODEL`, `BASE_URL`, `PROXY` | Model, endpoint and optional LLM proxy |
| `API_KEY` | Required for Anthropic/OpenAI formats unless the base URL is explicitly local; optional token for Ollama |
| `CONTEXT_WINDOW_K`, `MAX_TOKENS`, `KEEP_ALIVE`, `MAX_CONCURRENT` | Controls described above |
| `THINKING_TYPE`, `REASONING_EFFORT`, `STREAM` | Existing reasoning and streaming options |

Policy variables: `SCOPEWEAVER_LOCAL_LLM_ONLY` / `ARTEX_LOCAL_LLM_ONLY` and comma-separated `SCOPEWEAVER_LOCAL_LLM_ALLOWED_CIDRS` / `ARTEX_LOCAL_LLM_ALLOWED_CIDRS`.

At startup, Anthropic and OpenAI formats use `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` when no generic key is configured, including for authenticated local gateways. To start a deliberately keyless local profile while those provider keys are set, explicitly set `SCOPEWEAVER_LLM_API_KEY=` (or `ARTEX_LLM_API_KEY=`). This overrides file credentials and suppresses provider-key fallback. Native Ollama falls back only to `OLLAMA_API_KEY`, never to Anthropic or OpenAI keys.

Saving a new UI profile with a blank key does not import provider environment credentials. **Test connection** with a blank key can reuse an existing profile's saved key when its profile ID is supplied. Without a profile ID, a local Anthropic/OpenAI test reuses the active key only when the format, normalized base URL and proxy all match the active service, including when testing a new draft. A different local endpoint, format or proxy does not inherit the active key; native Ollama never inherits an active cloud key. Existing non-local connection tests retain their active-key fallback.

```bash
# .env for ScopeWeaver in Docker with Ollama on the host
SCOPEWEAVER_LLM_PROVIDER=ollama
SCOPEWEAVER_LLM_BASE_URL=http://host.docker.internal:11434
SCOPEWEAVER_LLM_MODEL=qwen2.5-coder:32b
SCOPEWEAVER_LLM_CONTEXT_WINDOW_K=32
SCOPEWEAVER_LLM_MAX_CONCURRENT=1
SCOPEWEAVER_LLM_KEEP_ALIVE=30m
SCOPEWEAVER_LLM_MAX_TOKENS=4096
SCOPEWEAVER_LOCAL_LLM_ONLY=false   # set true for the opt-in local-only policy
```

```json
{
  "llm": { "provider": "ollama", "base_url": "http://127.0.0.1:11434", "model": "qwen2.5-coder:32b", "context_window_k": 32, "llm_max_concurrent": 1, "keep_alive": "30m", "max_tokens": 4096 },
  "local_llm_only": false,
  "local_llm_allowed_cidrs": []
}
```

### Hardware tiers

Approximate starting points by GPU VRAM or Apple unified memory, using the tool-capable catalog models below. **These are estimates, not benchmarks.** Context listed is the profile's configured **Context window (K)**; it must fit both the model's own context limit and your memory (weights + KV cache, which grows with context and `OLLAMA_NUM_PARALLEL`). Check with **Test connection**, which reports whether the requested context was allocated.

| Memory | Example model | Context window (K) | Role |
| --- | --- | --- | --- |
| 8–12 GB | `qwen2.5-coder:7b`, `qwen3:8b` | `16`–`32` | Approval judge or auxiliary profile; weak as the main agent |
| 16–24 GB | `qwen2.5-coder:14b`, `qwen3:14b` | `32` | Main agent on a workstation  |
| 32–48 GB | `qwen2.5-coder:32b`, `qwen3:32b` | `32` | Main agent. Use `64` only with a model whose limit allows it; these list 32K and 40K |
| 64–128 GB+ | `llama3.3:70b` | `64` (model lists 128K) | Main agent on large-memory hosts; 64K needs the upper part of this range |

Templates choose from models installed on the selected server and use a 32K context. Hardware examples are not automatic model choices.

### Model candidates

Only models whose [Ollama library](https://ollama.com/library) page lists the `tools` capability are listed (checked 2026-10-15). Download sizes are the default quantization. **Memory guidance is an estimate**: weights plus a KV cache that grows with context and parallel requests. ScopeWeaver has not benchmarked these models or hardware, and tool-calling quality varies by model.

| Model | Download | Notes |
| --- | --- | --- |
| `qwen2.5-coder:7b` | 4.7 GB | Smallest practical candidate; also a judge candidate |
| `qwen2.5-coder:14b` | 9.0 GB | Workstation candidate |
| `qwen2.5-coder:32b` | 20 GB | Larger-host candidate |
| `qwen3:8b`, `qwen3:14b`, `qwen3:32b` | 5.2 / 9.3 / 20 GB | Also declare `thinking` |
| `llama3.3:70b` | 43 GB | Large-memory hosts |

`qwen3:72b` and `llama3.2:8b` do not appear in the Ollama library; `llama3.2` ships as 1B and 3B. Confirm `tools` with **Load models** on your own server before use.

**Observed limitation (2026-10-15):** a declared `tools` capability does not guarantee wire tool calls. In branch testing, `qwen2.5-coder:7b` wrote tool-shaped JSON as plain text, so no tool ran, and `qwen3:4b` passed the tool-call diagnostic but did not complete long autonomous tasks. Treat small models as unvalidated for the main agent; see [Verification](VERIFICATION.md#autonomous-task-reliability-is-not-validated).

The usage restrictions in the [README](../README.md) still apply: run ScopeWeaver only in a locally isolated environment, whichever provider you choose.

[한국어 안내](ko/llm-providers.md)
