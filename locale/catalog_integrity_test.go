package locale

import (
	"strings"
	"testing"
)

func TestProductionCatalogCompleteAndFormatCompatible(t *testing.T) {
	if len(catalog) < 1888 {
		t.Fatalf("production catalog unexpectedly small: %d", len(catalog))
	}
	keys := make([]string, 0, len(catalog))
	for key := range catalog {
		if key != "test.hello" {
			keys = append(keys, key)
		}
	}
	t.Logf("checking %d registered keys in %v", len(keys), Languages())
	if err := ValidateTranslations(keys); err != nil {
		t.Fatal(err)
	}
}

func TestFormatArgumentsRecognizesReorderingAndWidth(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"%s %d %%", "1:s,2:d"},
		{"%[2]d %[1]s", "1:s,2:d"},
		{"%[3]*.[2]*[1]f", "1:f,2:width,3:width"},
	} {
		if got := strings.Join(formatArguments(tc.input), ","); got != tc.want {
			t.Errorf("%q: got %s, want %s", tc.input, got, tc.want)
		}
	}
}
