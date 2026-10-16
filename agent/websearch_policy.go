package agent

import (
	"context"
	"encoding/json"
	"strings"

	runtimeconfig "github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/norma/agentcore"
	actool "github.com/Autumn-27/norma/tool"
)

// DeepSeekLocalOnlyMessage is shared with the search connectivity probe.
const DeepSeekLocalOnlyMessage = "DeepSeek web search uses a remote LLM and is unavailable while local_llm_only is enabled"

// secureWebSearch replaces only the SDK's DeepSeek search tool: its private HTTP
// client cannot receive the application's guarded LLM transport. Keep the SDK
// schema and permissions, but check the live policy before every invocation.
func secureWebSearch(opts *agentcore.Options, policy func() (bool, []string)) {
	if !opts.EnableWebSearch || strings.ToLower(strings.TrimSpace(opts.WebSearchBackend)) != "deepseek" {
		return
	}
	opts.EnableWebSearch = false
	search, err := actool.NewWebSearch(actool.WebSearchConfig{
		Backend: opts.WebSearchBackend, BraveAPIKey: opts.BraveSearchAPIKey, TavilyAPIKey: opts.TavilySearchAPIKey,
		DeepSeekBaseURL: opts.DeepSeekSearchBaseURL, DeepSeekAPIKey: opts.DeepSeekSearchAPIKey, DeepSeekModel: opts.DeepSeekSearchModel,
		Proxy: opts.WebSearchProxy, CACert: opts.WebSearchCACert, InsecureTLS: opts.WebSearchInsecureTLS,
	})
	// Match agentcore's existing behavior: a misconfigured search backend omits
	// the tool and leaves the rest of the session available.
	if err != nil {
		return
	}
	if policy == nil {
		policy = runtimeconfig.LocalLLMPolicy
	}
	opts.Tools = append(opts.Tools, &localOnlyDeepSeekSearch{CoreTool: search, policy: policy})
}

type localOnlyDeepSeekSearch struct {
	actool.CoreTool
	policy func() (bool, []string)
}

func (t *localOnlyDeepSeekSearch) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if strict, _ := t.policy(); strict {
		return actool.Errorf(locale.Text(locale.FromContext(ctx), DeepSeekLocalOnlyMessage)), nil
	}
	return t.CoreTool.Call(ctx, input, tc)
}
