package report

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFenceFor(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "```"},
		{"plain evidence text", "```"},
		{"single ` inline", "```"},
		{"double `` inline", "```"},
		{"```\n<script>alert(1)</script>\n```", "````"},
		{"four ```` run", "`````"},
		{"run at end: `", "```"},
		{"runs split by newline\n``\n``", "```"},
		{"``````````", "```````````"},
	}
	for _, tc := range cases {
		if got := fenceFor(tc.in); got != tc.want {
			t.Errorf("fenceFor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The triple-backtick line in tricky would, before the fix, close a fixed fence early and leak <script> as top-level Markdown.
const tricky = "Vulnerable parameter reflected:\n```\n<script>alert(1)</script>\n```"

func TestFindingsMarkdownEvidenceFence(t *testing.T) {
	f := &db.DBFinding{
		ID: 1, VulnClass: "XSS", Severity: "high", Status: "confirmed",
		Summary: "reflected xss", Evidence: tricky, CreatedAt: time.Now(),
	}
	rendered := map[string]string{
		"summary": FindingsMarkdown([]*db.DBFinding{f}, time.Now()),
		"single":  SingleFindingMarkdown(f, time.Now()),
	}
	for name, out := range rendered {
		if !strings.Contains(out, "````\n"+tricky+"\n````") {
			t.Errorf("%s: evidence is not wrapped verbatim in a 4-backtick fence, risking escape", name)
		}
	}
}

func TestMarkdownPoCFence(t *testing.T) {
	// poc contains 4 consecutive backticks, so the fence must grow to 5 to keep the content from closing it early.
	poc := "poc" + strings.Repeat("`", 4) + " inside"
	payload := fmt.Sprintf(`{"severity":"critical","name":"cmd injection","summary":"exec","evidence":{"poc":%s}}`,
		strconv.Quote(poc))
	node := &db.Node{Kind: "finding", Payload: []byte(payload)}
	out := Markdown(Input{Title: "t", Goal: "g", GeneratedAt: time.Now(), Findings: []*db.Node{node}})
	if !strings.Contains(out, "`````\n"+poc+"\n`````") {
		t.Errorf("PoC is not wrapped verbatim in a lengthened fence, risking escape:\n%s", out)
	}
}
