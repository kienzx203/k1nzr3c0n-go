package graph

import "testing"

func TestSecretType(t *testing.T) {
	cases := map[string]string{
		"AKIAIOSFODNN7EXAMPLE":                 "aws",
		"ASIA1234567890ABCDEF":                 "aws",
		"AIzaSyA-1234567890abcdefNOTREAL":      "google",
		"ghp_abcdefghijklmnopqrstuvwxyz0123":   "github",
		"github_pat_11ABCNOTREAL":              "github",
		"xoxb-123-456-abcNOTREAL":              "slack",
		"sk_live_1234567890NOTREAL":            "stripe",
		"SG.abcNOTREAL.defNOTREAL":             "sendgrid",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9": "jwt",
		"-----BEGIN RSA PRIVATE KEY-----":      "privatekey",
		"DB_PASSWORD=hunter2":                  "credential",
		"just some random text":                "", // unknown → unclassified
	}
	for in, want := range cases {
		if got := secretType(in); got != want {
			t.Errorf("secretType(%q) = %q, want %q", in, got, want)
		}
	}
}
