package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestChatUnavailableFixtureCleansProfiles(t *testing.T) {
	m := backportTestManager(t)
	t.Run("completed profile fixture", TestChatUnavailableReasonDistinguishesStates)
	var count int
	if err := m.pg.QueryRow(`SELECT count(*) FROM llm_profiles WHERE name='p1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("completed profile fixture left %d profiles for later tests", count)
	}
}

// TestChatUnavailableReasonDistinguishesStates pins the operator-facing message
// to the actual configuration state: nothing configured vs. configured-but-not-
// activated must read differently so the user knows what to do.
func TestChatUnavailableReasonDistinguishesStates(t *testing.T) {
	m := backportTestManager(t)
	td := t.TempDir()
	s := New(t.Context(), m, td, td, td)

	// Start from a clean profile table; other tests in the shared DB may have left rows.
	existing, _ := m.pg.ListProfiles()
	for _, p := range existing {
		if p.IsDefault {
			// The active profile cannot be deleted directly; clear the flag first.
			_, _ = m.pg.Exec(`UPDATE llm_profiles SET is_default=false WHERE id=$1`, p.ID)
		}
		_ = m.pg.DeleteProfile(p.ID)
	}

	if reason := s.chatUnavailableReason(); !strings.Contains(reason, "No LLM is configured") {
		t.Fatalf("no-profile reason=%q, want No LLM is configured", reason)
	}

	id, err := m.pg.SaveProfile(&db.LLMProfile{Name: "p1", Format: "anthropic", Model: "claude-x", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := m.pg.Exec(`UPDATE llm_profiles SET is_default=false WHERE id=$1`, id); err != nil {
			t.Errorf("clear active test profile: %v", err)
		}
		if err := m.pg.DeleteProfile(id); err != nil {
			t.Errorf("delete test profile: %v", err)
		}
	})

	// Profile exists but is not activated.
	if reason := s.chatUnavailableReason(); !strings.Contains(reason, "No active LLM profile") {
		t.Fatalf("inactive reason=%q, want No active LLM profile", reason)
	}

	// Once activated, the reason no longer claims a missing/inactive config.
	if err := m.pg.SetActiveProfile(id); err != nil {
		t.Fatal(err)
	}
	if reason := s.chatUnavailableReason(); strings.Contains(reason, "No LLM is configured") || strings.Contains(reason, "No active LLM profile") {
		t.Fatalf("active reason=%q should not report missing/inactive", reason)
	}
}

// TestResolveChatAgentHonoursConversationProfile is the regression guard for the
// reported bug: a conversation that picked a valid profile must resolve a chat
// agent even when NO global profile is active, so the send precheck stops
// rejecting it with an unconfigured-LLM error.
func TestResolveChatAgentHonoursConversationProfile(t *testing.T) {
	m := backportTestManager(t)
	td := t.TempDir()
	s := New(t.Context(), m, td, td, td)

	// Force the global fallback to nil so a non-nil result can ONLY come from the
	// conversation's own profile — this is exactly the situation the user hit
	// (no usable global config) and isolates the fix from the test host's env.
	s.cfgMu.Lock()
	s.chatAgent = nil
	s.cfgMu.Unlock()

	id, err := m.pg.SaveProfile(&db.LLMProfile{Name: "conv-pick", Format: "anthropic", Model: "claude-x", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.pg.DeleteProfile(id); err != nil {
			t.Errorf("delete conversation test profile: %v", err)
		}
	})

	// A conversation that pinned this profile resolves a chat agent despite the
	// nil global fallback; without the fix the send precheck rejected it outright.
	conv := &db.Conversation{AgentKey: "mainagent", LLMProfileID: &id}
	if s.resolveChatAgent(conv) == nil {
		t.Fatalf("resolveChatAgent(conversation with valid profile) = nil; global fallback wrongly gates the pick")
	}

	// With neither a pick nor a global fallback there is genuinely nothing to run.
	if s.resolveChatAgent(&db.Conversation{AgentKey: "mainagent"}) != nil {
		t.Fatalf("resolveChatAgent with neither pick nor global config should be nil")
	}
}
