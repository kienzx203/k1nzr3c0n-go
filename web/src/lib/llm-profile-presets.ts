// Z.ai documentation verified 2026-10-03. This helper changes form fields only.
// https://docs.z.ai/guides/llm/glm-5.3
// https://zcode.z.ai/en/docs/configuration
// Ollama templates target the native /api/chat path (https://docs.ollama.com/api), verified 2026-10-15.
export const LLM_PROFILE_PRESET_IDS = [
  "zai-general",
  "zai-coding-reference",
  "ollama-host",
  "ollama-docker-host",
  "ollama-compose",
] as const;
export type LLMProfilePresetId = (typeof LLM_PROFILE_PRESET_IDS)[number];

export interface ZaiPresetFields {
  format: "openai";
  model: string;
  base_url: string;
  thinking_type: "enabled";
  reasoning_effort: "max";
  context_window_k: number;
  max_tokens: number;
  max_tokens_field: "";
}

export interface OllamaPresetFields {
  format: "ollama";
  model: string;
  base_url: string;
  // Native templates clear any unsaved key so a cloud credential is never sent to a local endpoint.
  api_key: "";
  // Empty values omit the fields: Ollama decides thinking per model.
  thinking_type: "";
  reasoning_effort: "";
  // Binary K for Ollama: 32 sends options.num_ctx = 32768.
  context_window_k: number;
  max_tokens: number;
  max_tokens_field: "";
  keep_alive: string;
  llm_max_concurrent: number;
}

export type LLMProfilePresetFields = ZaiPresetFields | OllamaPresetFields;

const OLLAMA_TARGETS: Record<string, { base_url: string }> = {
  "ollama-host": { base_url: "http://127.0.0.1:11434" },
  "ollama-docker-host": { base_url: "http://host.docker.internal:11434" },
  "ollama-compose": { base_url: "http://ollama:11434" },
};

export function isOllamaPreset(id: string): boolean {
  return Object.hasOwn(OLLAMA_TARGETS, id);
}

export function getLLMProfilePreset(id: string): Readonly<LLMProfilePresetFields> {
  if (!(LLM_PROFILE_PRESET_IDS as readonly string[]).includes(id)) {
    throw new RangeError(`Unknown LLM profile preset: ${id}`);
  }
  if (isOllamaPreset(id)) {
    return {
      format: "ollama",
      ...OLLAMA_TARGETS[id],
      // The form discovers an installed model from this server; never assume a tag is installed.
      model: "",
      api_key: "",
      thinking_type: "",
      reasoning_effort: "",
      context_window_k: 32,
      max_tokens: 4096,
      max_tokens_field: "",
      keep_alive: "30m",
      llm_max_concurrent: 1,
    };
  }
  return {
    format: "openai",
    model: "glm-5.3",
    base_url: id === "zai-general" ? "https://api.z.ai/api/paas/v4" : "https://api.z.ai/api/coding/paas/v4",
    thinking_type: "enabled",
    reasoning_effort: "max",
    context_window_k: 1000,
    // Preserve the existing default: omit the output limit and use provider defaults.
    max_tokens: 0,
    max_tokens_field: "",
  };
}

// Unknown fields, including profile names, proxies and session headers, survive unchanged.
// GLM templates also keep entered credentials; Ollama templates clear them (see api_key above).
// The original draft is not mutated, and no request or persistence occurs here.
export function applyLLMProfilePreset<T extends object>(draft: T, id: string): T & LLMProfilePresetFields {
  return { ...draft, ...getLLMProfilePreset(id) };
}

// Choose only from the installed list, preferring confirmed native tool support.
export function selectInstalledOllamaModel(
  models: readonly string[],
  details: readonly { name?: string; model?: string; capabilities?: string[]; error?: string }[] = [],
): string {
  return models.find((model) => details.some((d) =>
    (d.name === model || d.model === model) && !d.error && d.capabilities?.includes("tools"),
  )) ?? models[0] ?? "";
}
