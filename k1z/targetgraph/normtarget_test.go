package targetgraph

import "testing"

func TestNormTarget(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"viettelcdn.com.vn":             "viettelcdn.com.vn",
		"https://viettelcdn.com.vn":     "viettelcdn.com.vn", // scheme stripped → same group
		"http://Example.COM:8080/a?q=1": "example.com",       // scheme+port+path+case
		"https://x.com/examp/aaa":       "x.com",             // path stripped
		"example.com:443":               "example.com",
		"1.2.3.4":                       "1.2.3.4",
		"  HTTPS://Foo.Bar/path  ":      "foo.bar",
		"sub.example.com.":              "sub.example.com", // trailing dot
	}
	for in, want := range cases {
		if got := NormTarget(in); got != want {
			t.Errorf("NormTarget(%q) = %q, want %q", in, got, want)
		}
	}
	if NormTarget("https://viettelcdn.com.vn") != NormTarget("viettelcdn.com.vn") {
		t.Error("scheme and bare forms must aggregate into one target")
	}
}
