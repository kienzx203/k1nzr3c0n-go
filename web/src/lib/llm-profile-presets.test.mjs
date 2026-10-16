import assert from "node:assert/strict";
import test from "node:test";
import { applyLLMProfilePreset, getLLMProfilePreset, isOllamaPreset, selectInstalledOllamaModel, LLM_PROFILE_PRESET_IDS } from "./llm-profile-presets.ts";

test("GLM templates distinguish billing endpoints and use documented model settings", () => {
  const general = getLLMProfilePreset("zai-general");
  const coding = getLLMProfilePreset("zai-coding-reference");
  assert.equal(general.base_url, "https://api.z.ai/api/paas/v4");
  assert.equal(coding.base_url, "https://api.z.ai/api/coding/paas/v4");
  for (const preset of [general, coding]) {
    assert.equal(preset.format, "openai");
    assert.equal(preset.model, "glm-5.3");
    assert.equal(preset.thinking_type, "enabled");
    assert.equal(preset.reasoning_effort, "max");
    assert.equal(preset.context_window_k, 1000);
    assert.equal(preset.max_tokens, 0);
    assert.equal(preset.max_tokens_field, "");
    assert.equal("api_key" in preset, false, "GLM templates never touch credentials");
    assert.equal("keep_alive" in preset, false);
    assert.equal("llm_max_concurrent" in preset, false);
  }
});

test("applying a template preserves entered secrets and unrelated draft preferences", () => {
  const draft = Object.freeze({ name: "My profile", api_key: "user-entered-key", proxy: "http://user:pass@proxy:8080", username: "operator", session_header_key: "x-session", streaming: false, rate_per_minute: 7, model: "custom-model", base_url: "https://previous.example" });
  const next = applyLLMProfilePreset(draft, "zai-general");
  for (const key of ["name", "api_key", "proxy", "username", "session_header_key", "streaming", "rate_per_minute"]) assert.equal(next[key], draft[key]);
  assert.equal(draft.model, "custom-model");
  assert.notEqual(next, draft);
  next.model = "user-selected-model";
  assert.equal(next.model, "user-selected-model", "the preset does not lock model editing");
});

test("three Ollama templates select native host, Docker host bridge and Compose service routes", () => {
  const expected = {
    "ollama-host": ["http://127.0.0.1:11434", ""],
    "ollama-docker-host": ["http://host.docker.internal:11434", ""],
    "ollama-compose": ["http://ollama:11434", ""],
  };
  assert.deepEqual(LLM_PROFILE_PRESET_IDS.filter(isOllamaPreset), Object.keys(expected));
  for (const [id, [baseURL, model]] of Object.entries(expected)) {
    assert.deepEqual(getLLMProfilePreset(id), {
      format: "ollama",
      base_url: baseURL,
      model,
      api_key: "",
      thinking_type: "",
      reasoning_effort: "",
      context_window_k: 32,
      max_tokens: 4096,
      max_tokens_field: "",
      keep_alive: "30m",
      llm_max_concurrent: 1,
    });
  }
});

test("Ollama templates clear an unsaved cloud key but keep name, proxy, session header and other preferences", () => {
  const draft = Object.freeze({ name: "Lab GPU", api_key: "sk-cloud-unsaved", proxy: "http://127.0.0.1:8080", session_header_key: "x-session", streaming: false, rate_per_minute: 7, priority: 3, pool_exclude: true });
  for (const id of ["ollama-host", "ollama-docker-host", "ollama-compose"]) {
    const next = applyLLMProfilePreset(draft, id);
    assert.equal(next.api_key, "", `${id} must not carry the cloud key to a local endpoint`);
    for (const key of ["name", "proxy", "session_header_key", "streaming", "rate_per_minute", "priority", "pool_exclude"]) assert.equal(next[key], draft[key]);
    assert.equal(draft.api_key, "sk-cloud-unsaved", "the original draft is not mutated");
  }
});

test("switching from an Ollama template back to GLM restores the cloud format without inventing a key", () => {
  const local = applyLLMProfilePreset({ name: "n", api_key: "sk-cloud" }, "ollama-host");
  const cloud = applyLLMProfilePreset(local, "zai-general");
  assert.equal(cloud.format, "openai");
  assert.equal(cloud.base_url, "https://api.z.ai/api/paas/v4");
  assert.equal(cloud.api_key, "", "a cleared key stays cleared; the user re-enters it explicitly");
});

test("unsupported template IDs fail explicitly without changing the draft", () => {
  const draft = { api_key: "keep", model: "keep-model" };
  for (const id of ["", "glm-unknown", "__proto__", "zai-general-extra", "ollama", "ollama-host-extra", "constructor", "toString"]) {
    assert.throws(() => applyLLMProfilePreset(draft, id), RangeError);
    assert.deepEqual(draft, { api_key: "keep", model: "keep-model" });
  }
});

test("installed Ollama default prefers confirmed tools while preserving the returned order", () => {
  const models = ["embeddinggemma:latest", "qwen3:4b", "qwen2.5-coder:7b"];
  assert.equal(selectInstalledOllamaModel(models, [
    { name: "embeddinggemma:latest", capabilities: ["embedding"] },
    { model: "not-installed:32b", capabilities: ["tools"] },
    { model: "qwen2.5-coder:7b", capabilities: ["tools"] },
    { name: "qwen3:4b", capabilities: ["tools", "thinking"] },
  ]), "qwen3:4b");
});

test("installed Ollama default falls back to the first installed model and never invents a tag", () => {
  assert.equal(selectInstalledOllamaModel(["custom:latest", "other:7b"]), "custom:latest");
  assert.equal(selectInstalledOllamaModel(["custom:latest", "other:7b"], [
    { model: "other:7b", capabilities: ["tools"], error: "metadata failed" },
  ]), "custom:latest");
  assert.equal(selectInstalledOllamaModel([], [{ name: "not-installed:32b", capabilities: ["tools"] }]), "");
});
