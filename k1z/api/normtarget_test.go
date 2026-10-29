package api

import "testing"

func TestNormTarget(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"viettelcdn.com.vn":             "viettelcdn.com.vn",
		"https://viettelcdn.com.vn":     "viettelcdn.com.vn", // scheme stripped → same group
		"http://Example.COM:8080/a?q=1": "example.com",       // scheme+port+path+case
		"example.com:443":               "example.com",
		"1.2.3.4":                       "1.2.3.4",
		"  HTTPS://Foo.Bar/path  ":      "foo.bar",
		"sub.example.com.":              "sub.example.com", // trailing dot
	}
	for in, want := range cases {
		if got := normTarget(in); got != want {
			t.Errorf("normTarget(%q) = %q, want %q", in, got, want)
		}
	}
	// the two forms from the user's run list must collapse to one key
	if normTarget("https://viettelcdn.com.vn") != normTarget("viettelcdn.com.vn") {
		t.Error("scheme and bare forms must aggregate into one target")
	}
}
