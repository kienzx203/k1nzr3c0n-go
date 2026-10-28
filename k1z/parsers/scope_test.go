package parsers

import "testing"

func TestHostOfURL(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"example.com":                 "example.com",     // bare target apex
		"sub.example.com":             "sub.example.com", // bare subdomain
		"1.2.3.4":                     "1.2.3.4",         // IP literal target
		"example.com:443":             "example.com",     // host:port
		"https://example.com":         "example.com",     // full URL
		"http://WWW.Example.COM/x?y":  "www.example.com", // lowercase + strip path/query
		"https://www.w3.org/2000/svg": "www.w3.org",      // third-party URL
	}
	for in, want := range cases {
		if got := hostOfURL(in); got != want {
			t.Errorf("hostOfURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInTargetScope(t *testing.T) {
	const target = "example.com" // stored bare, as runner does
	in := []string{
		"https://example.com/a",
		"https://api.example.com/v1",
		"https://API.Example.com/v1", // case-insensitive
	}
	out := []string{
		"https://www.w3.org/2000/svg",
		"https://github.com/x",
		"https://notexample.com.evil.com/", // suffix trap: not a subdomain of example.com
		"https://evilexample.com/",         // must not match on bare substring
	}
	for _, u := range in {
		if !inTargetScope(target, hostOfURL(u)) {
			t.Errorf("inTargetScope(%q, %q) = false, want true", target, u)
		}
	}
	for _, u := range out {
		if inTargetScope(target, hostOfURL(u)) {
			t.Errorf("inTargetScope(%q, %q) = true, want false", target, u)
		}
	}
	// IP-literal target: only that IP is in scope.
	if !inTargetScope("1.2.3.4", hostOfURL("http://1.2.3.4/x")) {
		t.Error("IP target: own IP should be in scope")
	}
	if inTargetScope("1.2.3.4", hostOfURL("https://www.w3.org/")) {
		t.Error("IP target: third-party host should be out of scope")
	}
}
