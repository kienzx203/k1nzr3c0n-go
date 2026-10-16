// Native Ollama profile browser checks, called from smoke.mjs after login.
// A local fixture stands in for Ollama, so no real model or provider is contacted.
// The ScopeWeaver backend must reach the fixture; set E2E_OLLAMA_FIXTURE_HOST when
// the backend runs elsewhere (default 127.0.0.1, i.e. the binary runs on this host).
import http from "node:http";
import { en as iEn, ko as iKo } from "../web/src/i18n/messages/interface.ts";
import { en as pEn, ko as pKo } from "../web/src/i18n/messages/providers.ts";
import { en as sEn, ko as sKo } from "../web/src/i18n/messages/settings.ts";

const T = { en: { i: iEn, p: pEn, s: sEn }, ko: { i: iKo, p: pKo, s: sKo } };
const TOOL_MODEL = "fixture-installed-tools:7b";
const NO_TOOLS_MODEL = "aaa-fixture-notools:8b";
const MODELS = {
  [NO_TOOLS_MODEL]: { details: { parameter_size: "8.0B", quantization_level: "Q4_0" }, capabilities: ["completion"] },
  [TOOL_MODEL]: { details: { parameter_size: "7.0B", quantization_level: "Q4_K_M" }, capabilities: ["completion", "tools"] },
};

function startFixture() {
  const hits = [];
  const chats = [];
  const requests = [];
  const control = { mode: "ok", holdTags: false, held: [] };
  const releaseTags = () => {
    control.holdTags = false;
    for (const send of control.held.splice(0)) send();
  };
  const waitForHeld = async () => {
    for (let attempt = 0; attempt < 250; attempt++) {
      if (control.held.length) return;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error("fixture did not receive the held discovery request");
  };
  let lastModel = "";
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : {};
      // An explicit fixture proxy keeps all three template targets local without
      // intercepting browser/API responses or contacting the real host daemon.
      const path = req.url.startsWith("http") ? new URL(req.url).pathname : req.url;
      hits.push(`${req.method} ${path}`);
      requests.push({ method: req.method, target: req.url, path, authorization: req.headers.authorization, body });
      const send = (code, value) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(value)); };
      if (req.method === "GET" && path === "/api/tags") {
        const reply = () => control.mode === "error" ? send(503, { error: "fixture discovery unavailable" }) : send(200, { models: control.mode === "empty" ? [] : Object.entries(MODELS).map(([name, m]) => ({ name, model: name, details: m.details })) });
        if (control.holdTags) control.held.push(reply);
        else reply();
        return;
      }
      if (req.method === "POST" && path === "/api/show") {
        const m = MODELS[body.model];
        return m ? send(200, { capabilities: m.capabilities, details: m.details }) : send(404, { error: `model '${body.model}' not found` });
      }
      if (req.method === "POST" && path === "/api/chat") {
        chats.push(body);
        lastModel = body.model;
        if (!MODELS[body.model]) return send(404, { error: `model '${body.model}' not found` });
        const toolCalls = MODELS[body.model].capabilities.includes("tools") && body.tools?.length ? [{ function: { name: body.tools[0].function.name, arguments: { value: "OK" } } }] : [];
        return send(200, { model: body.model, message: { role: "assistant", content: toolCalls.length ? "" : "OK", tool_calls: toolCalls }, done: true, load_duration: 1_234_000_000, eval_count: 40, eval_duration: 1_000_000_000 });
      }
      if (req.method === "GET" && path === "/api/ps") return send(200, { models: lastModel ? [{ name: lastModel, model: lastModel, context_length: 32768 }] : [] });
      send(404, { error: "not found" });
    });
  });
  const host = process.env.E2E_OLLAMA_FIXTURE_HOST || "127.0.0.1";
  return new Promise((resolve) => server.listen(0, host === "127.0.0.1" ? host : "0.0.0.0", () => resolve({ server, hits, chats, requests, control, releaseTags, waitForHeld, url: `http://${host}:${server.address().port}` })));
}

export async function runOllamaProfileChecks({ base, token, step, check, openPage, out }) {
  const fixture = await startFixture();
  const auth = { Authorization: `Bearer ${token}` };
  try {
    for (const locale of ["en", "ko"]) {
      const t = T[locale];
      const name = `e2e ollama ${locale}`;
      const initialHits = fixture.hits.length;
      const p = await openPage(locale, token);
      const llmCalls = [];
      p.on("request", (r) => {
        const path = new URL(r.url()).pathname;
        if (/^\/api\/llm\/(test|models|profiles)/.test(path) && r.method() === "POST") llmCalls.push(path);
      });
      try {
        await step(`[${locale}] Ollama templates select an installed tool model using metadata only`, async () => {
          await p.goto(`${base}/system/llm`);
          await p.getByRole("button", { name: t.i.m0728, exact: true }).click();
          const sheet = p.getByRole("dialog");
          await sheet.getByRole("heading", { name: t.i.m1382, exact: true }).waitFor();
          await p.fill("#p-name", name);
          await p.fill("#p-proxy", fixture.url);
          await p.fill("#p-session-header", "x-e2e-session");
          await p.fill("#p-api-key", "sk-cloud-unsaved");
          const routes = [
            ["ollamaHost", "http://127.0.0.1:11434"],
            ["ollamaDockerHost", "http://host.docker.internal:11434"],
            ["ollamaCompose", "http://ollama:11434"],
          ];
          for (const [key, url] of routes) {
            await p.fill("#p-api-key", "sk-cloud-unsaved");
            const before = fixture.requests.length;
            const discovery = p.waitForResponse((r) => new URL(r.url()).pathname === "/api/llm/models" && r.request().postDataJSON()?.base_url === url);
            await p.locator("#p-preset").click();
            await p.getByRole("option", { name: t.p[key], exact: true }).click();
            check((await (await discovery).json()).ok, `${key} discovery failed`);
            await p.waitForFunction((m) => document.getElementById("p-model")?.value === m, TOOL_MODEL);
            const values = await p.evaluate(() => Object.fromEntries(["p-name", "p-proxy", "p-session-header", "p-api-key", "p-base-url", "p-model", "p-cw", "p-max-concurrent", "p-keep-alive", "p-max-tokens"].map((id) => [id, document.getElementById(id)?.value])));
            check(values["p-base-url"] === url && values["p-model"] === TOOL_MODEL, `${key} route ${values["p-base-url"]} ${values["p-model"]}`);
            check(values["p-cw"] === "32" && values["p-max-concurrent"] === "1" && values["p-keep-alive"] === "30m" && values["p-max-tokens"] === "4096", `${key} defaults ${JSON.stringify(values)}`);
            check(values["p-api-key"] === "", `${key} kept the unsaved cloud key`);
            check(values["p-name"] === name && values["p-proxy"] === fixture.url && values["p-session-header"] === "x-e2e-session", `${key} lost preferences`);
            const metadata = fixture.requests.slice(before);
            check(metadata.some((r) => r.target === `${url}/api/tags`), `${key} queried the wrong server`);
            check(metadata.every((r) => ["/api/tags", "/api/show"].includes(r.path) && !r.authorization), `${key} sent credentials or inference`);
            await sheet.getByRole("combobox", { name: t.i.m1388, exact: true }).getByText(t.p.ollamaFormat, { exact: true }).waitFor();
          }
          await sheet.getByText(t.p.ollamaCloudWarning, { exact: true }).waitFor();
          await p.screenshot({ path: `${out}/ollama-template-${locale}.png` });
          check(llmCalls.length === 3 && llmCalls.every((path) => path === "/api/llm/models"), `template selection sent ${llmCalls.join(",")}`);
          check(fixture.hits.slice(initialHits).every((hit) => /^(GET \/api\/tags|POST \/api\/show)$/.test(hit)), "template selection did more than metadata discovery");
        });

        await step(`[${locale}] cloud formats and GLM templates stay selectable and manually editable`, async () => {
          const beforeCalls = llmCalls.length;
          const beforeHits = fixture.hits.length;
          const sheet = p.getByRole("dialog");
          await p.locator("#p-preset").click();
          await p.getByRole("option", { name: t.p.general, exact: true }).click();
          check(await p.inputValue("#p-base-url") === "https://api.z.ai/api/paas/v4" && await p.inputValue("#p-model") === "glm-5.3", "GLM template changed");
          await sheet.getByRole("combobox", { name: t.i.m1388, exact: true }).click();
          for (const label of ["Anthropic", "OpenAI (Chat Completions)", "OpenAI (Responses API)", t.p.ollamaFormat]) {
            await p.getByRole("option", { name: label, exact: true }).waitFor();
          }
          await p.getByRole("option", { name: "OpenAI (Responses API)", exact: true }).click();
          await p.fill("#p-base-url", "https://gateway.example.invalid/v1");
          await p.fill("#p-model", "custom-model");
          check(await p.inputValue("#p-base-url") === "https://gateway.example.invalid/v1" && await p.inputValue("#p-model") === "custom-model", "manual fields not editable");
          check(llmCalls.length === beforeCalls && fixture.hits.length === beforeHits, "cloud templates or manual edits sent requests");
        });

        await step(`[${locale}] keyless Ollama profile loads metadata, diagnoses, saves and activates against the fixture`, async () => {
          const sheet = p.getByRole("dialog");
          await p.locator("#p-preset").click();
          const autoDiscovery = p.waitForResponse((r) => new URL(r.url()).pathname === "/api/llm/models");
          await p.getByRole("option", { name: t.p.ollamaHost, exact: true }).click();
          await autoDiscovery;
          await p.waitForFunction((m) => document.getElementById("p-model")?.value === m, TOOL_MODEL);
          await p.fill("#p-proxy", "");
          await p.fill("#p-base-url", fixture.url);
          await sheet.getByRole("button", { name: t.i.m1390, exact: true }).click();
          const list = p.locator('[data-slot="popover-content"]');
          // Assert metadata per model row so one row's badges cannot satisfy another row's checks.
          const row = (model) => list.getByRole("button").filter({ has: p.getByText(model, { exact: true }) });
          for (const text of ["7.0B", "Q4_K_M", "tools"]) await row(TOOL_MODEL).getByText(text, { exact: true }).waitFor();
          for (const text of ["8.0B", "Q4_0", t.p.noToolsBadge]) await row(NO_TOOLS_MODEL).getByText(text, { exact: true }).waitFor();
          check(await row(TOOL_MODEL).getByText(t.p.noToolsBadge, { exact: true }).count() === 0, "tool-capable row shows the no-tools badge");
          check(await row(NO_TOOLS_MODEL).getByText("tools", { exact: true }).count() === 0, "no-tools row shows the tools badge");
          await list.getByText(NO_TOOLS_MODEL, { exact: true }).click();
          await sheet.getByText(t.p.noTools, { exact: true }).waitFor();
          await p.fill("#p-model", "absent-model:1b");
          await sheet.getByRole("button", { name: t.i.m1418, exact: true }).click();
          await sheet.getByText("ollama pull absent-model:1b", { exact: true }).waitFor();
          await p.fill("#p-model", TOOL_MODEL);
          check(!(await sheet.getByText(t.p.noTools, { exact: true }).isVisible()), "tools warning shown for a tool-capable model");
          await sheet.getByRole("button", { name: t.i.m1418, exact: true }).click();
          await sheet.getByText(t.p.diagToolsOk, { exact: true }).waitFor();
          for (const text of [t.p.diagContextOk.replace("{actual}", "32768").replace("{requested}", "32768"), t.p.diagLoadValue.replace("{ms}", "1234"), t.p.diagSpeedValue.replace("{tps}", "40.0")]) {
            await sheet.getByText(text, { exact: true }).waitFor();
          }
          const chat = fixture.chats.at(-1);
          check(chat.options?.num_ctx === 32768 && chat.options?.num_predict === 4096 && chat.keep_alive === "30m", `native request ${JSON.stringify({ options: chat.options, keep_alive: chat.keep_alive })}`);
          await p.screenshot({ path: `${out}/ollama-diagnostics-${locale}.png` });
          await sheet.getByRole("button", { name: t.i.m0728, exact: true }).click();
          await sheet.waitFor({ state: "hidden" });
          const profiles = (await (await p.request.get(`${base}/api/llm/profiles`, { headers: auth })).json()).profiles;
          const saved = profiles.find((x) => x.name === name);
          check(saved && saved.format === "ollama" && saved.context_window_k === 32 && saved.llm_max_concurrent === 1 && saved.keep_alive === "30m" && saved.max_tokens === 4096 && !saved.api_key_hint && !saved.proxy && saved.session_header_key === "x-e2e-session", `saved ${JSON.stringify(saved)}`);
          const card = p.locator('[data-slot="card"]').filter({ has: p.getByText(name, { exact: true }) });
          await card.getByText(t.p.keyless, { exact: true }).waitFor();
          await card.getByText(t.i.m1339, { exact: true }).waitFor();
          await card.getByRole("button", { name: t.i.m1431, exact: true }).click();
          await p.getByText(t.i.m1419.replace("{p0}", name), { exact: true }).waitFor();
          const active = (await (await p.request.get(`${base}/api/llm/profiles`, { headers: auth })).json()).profiles.find((x) => x.name === name);
          check(active?.is_default === true, "keyless Ollama profile did not activate");
        });

        const newProfile = async () => {
          await p.goto(`${base}/system/llm`);
          await p.getByRole("button", { name: t.i.m0728, exact: true }).click();
          const sheet = p.getByRole("dialog");
          await sheet.getByRole("heading", { name: t.i.m1382, exact: true }).waitFor();
          await p.fill("#p-proxy", fixture.url);
          return sheet;
        };
        const selectHost = async () => {
          await p.locator("#p-preset").click();
          await p.getByRole("option", { name: t.p.ollamaHost, exact: true }).click();
        };
        const settledDiscovery = async (response) => {
          await (await response).finished();
          await p.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
        };

        await step(`[${locale}] direct Ollama format selects installed models and saved profiles do not rediscover on open`, async () => {
          const chatsBefore = fixture.chats.length;
          for (const endpoint of ["", fixture.url]) {
            const sheet = await newProfile();
            await p.fill("#p-base-url", endpoint);
            await p.fill("#p-api-key", "sk-unsaved-cloud-key");
            const response = p.waitForResponse((r) => new URL(r.url()).pathname === "/api/llm/models");
            await sheet.getByRole("combobox", { name: t.i.m1388, exact: true }).click();
            await p.getByRole("option", { name: t.p.ollamaFormat, exact: true }).click();
            await settledDiscovery(response);
            check(await p.inputValue("#p-model") === TOOL_MODEL, "format selection did not choose an installed tool model");
            check(await p.inputValue("#p-base-url") === (endpoint || "http://127.0.0.1:11434"), "format selection lost the selected server");
            check(await p.inputValue("#p-api-key") === "", "format selection retained a cloud key");
          }
          await p.keyboard.press("Escape");
          await p.getByRole("dialog").waitFor({ state: "hidden" });
          const before = llmCalls.length;
          await p.getByText(name, { exact: true }).click();
          const sheet = p.getByRole("dialog");
          await sheet.waitFor();
          await p.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
          check(await p.inputValue("#p-model") === TOOL_MODEL, "opening a saved profile changed its model");
          check(llmCalls.length === before && fixture.chats.length === chatsBefore, "opening a saved profile made a discovery or inference request");
        });

        await step(`[${locale}] empty and failed discovery leave a blank editable model and allow reload`, async () => {
          const before = llmCalls.length;
          const chatsBefore = fixture.chats.length;
          try {
            for (const mode of ["empty", "error"]) {
              fixture.control.mode = mode;
              const sheet = await newProfile();
              const response = p.waitForResponse((r) => new URL(r.url()).pathname === "/api/llm/models");
              await selectHost();
              await settledDiscovery(response);
              await sheet.getByRole("alert").waitFor();
              check(await p.inputValue("#p-model") === "", `${mode} discovery invented a model`);
              check(await sheet.getByRole("button", { name: t.i.m1390, exact: true }).isEnabled(), "reload stayed disabled");
              await p.fill("#p-model", "manual-installed:custom");
              check(await p.inputValue("#p-model") === "manual-installed:custom", "manual model entry is blocked");
            }
          } finally { fixture.control.mode = "ok"; }
          check(llmCalls.slice(before).every((path) => path === "/api/llm/models") && fixture.chats.length === chatsBefore, "failed discovery saved, tested or inferred");
        });

        await step(`[${locale}] late discovery cannot overwrite manual edits, another format or a reopened draft`, async () => {
          const before = llmCalls.length;
          const chatsBefore = fixture.chats.length;
          for (const field of ["model", "base-url", "proxy", "api-key", "format", "preset", "reopen", "stale-error"]) {
            const sheet = await newProfile();
            fixture.control.holdTags = true;
            const response = p.waitForResponse((r) => new URL(r.url()).pathname === "/api/llm/models");
            try {
              await selectHost();
              await fixture.waitForHeld();
              check(await p.inputValue("#p-model") === "", "pending discovery filled an uninstalled model");
              if (field === "reopen") {
                await p.keyboard.press("Escape");
                await sheet.waitFor({ state: "hidden" });
                await p.getByRole("button", { name: t.i.m0728, exact: true }).click();
                await p.getByRole("dialog").waitFor();
              } else if (field === "format") {
                await sheet.getByRole("combobox", { name: t.i.m1388, exact: true }).click();
                await p.getByRole("option", { name: "OpenAI (Responses API)", exact: true }).click();
              } else if (field === "preset") {
                await p.locator("#p-preset").click();
                await p.getByRole("option", { name: t.p.general, exact: true }).click();
              } else {
                const id = field === "stale-error" ? "model" : field;
                await p.fill(`#p-${id}`, id === "model" ? "manual-installed:custom" : `manual-${id}`);
                if (field === "stale-error") fixture.control.mode = "error";
              }
              fixture.releaseTags();
              await settledDiscovery(response);
              const expectedModel = field === "model" || field === "stale-error" ? "manual-installed:custom" : field === "preset" ? "glm-5.3" : "";
              check(await p.inputValue("#p-model") === expectedModel, `${field} edit was overwritten by late discovery`);
              check(await p.getByRole("dialog").getByRole("alert").count() === 0, `${field} edit received a stale discovery error`);
              check(await p.getByRole("dialog").getByRole("button", { name: t.i.m1390, exact: true }).isEnabled(), `${field} edit left loading stuck`);
              if (["base-url", "proxy", "api-key"].includes(field)) check(await p.inputValue(`#p-${field}`) === `manual-${field}`, `${field} edit was lost`);
              if (field === "format") await sheet.getByRole("combobox", { name: t.i.m1388, exact: true }).getByText("OpenAI (Responses API)", { exact: true }).waitFor();
            } finally { fixture.control.mode = "ok"; fixture.releaseTags(); }
          }
          check(llmCalls.slice(before).every((path) => path === "/api/llm/models") && fixture.chats.length === chatsBefore, "late discovery saved, tested or inferred");
        });

        await step(`[${locale}] local-only LLM policy is visible, explained and off by default`, async () => {
          const settings = await (await p.request.get(`${base}/api/settings`, { headers: auth })).json();
          check(settings.local_llm_only === false, `local_llm_only defaulted to ${settings.local_llm_only}`);
          await p.goto(`${base}/system/settings`);
          const toggle = p.locator("#local-llm-only:not([disabled])");
          await toggle.waitFor();
          check(await toggle.getAttribute("aria-checked") === "false", "local-only switch is on by default");
          await p.getByText(t.s.localOnlyTitle, { exact: true }).waitFor();
          await p.getByText(t.s.localOnlyEnv, { exact: true }).waitFor();
        });

        await step(`[${locale}] compatible local keyless health differs from a public cloud profile missing its key`, async () => {
          const localName = `e2e local compatible ${locale}`;
          const publicName = `e2e public missing key ${locale}`;
          for (const [profileName, baseURL] of [[localName, fixture.url], [publicName, "http://203.0.113.7:11434/v1"]]) {
            const response = await p.request.post(`${base}/api/llm/profiles`, { headers: auth, data: {
              name: profileName, format: "openai", model: TOOL_MODEL, base_url: baseURL, api_key: "",
            } });
            check(response.ok(), `profile creation failed: ${response.status()}`);
          }
          const profiles = (await (await p.request.get(`${base}/api/llm/profiles`, { headers: auth })).json()).profiles;
          check(profiles.find((x) => x.name === localName)?.api_key_optional === true, "local compatible key is not optional");
          check(profiles.find((x) => x.name === publicName)?.api_key_optional === false, "public cloud key became optional");
          await p.goto(`${base}/system/llm`);
          const card = (profileName) => p.locator('[data-slot="card"]').filter({ has: p.getByText(profileName, { exact: true }) });
          await card(localName).getByText(t.p.keyless, { exact: true }).waitFor();
          check(await card(localName).getByText(t.i.m1334, { exact: true }).count() === 0, "local compatible profile is mislabeled as missing a key");
          await card(publicName).getByText(t.i.m1334, { exact: true }).waitFor();
        });
      } finally {
        await p.context().close();
      }
    }
  } finally {
    fixture.releaseTags();
    fixture.server.close();
  }
}
