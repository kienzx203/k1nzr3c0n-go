package locale

import (
	"embed"
	"encoding/json"
)

// definitionsJSON is also imported by the frontend; the checked-in declaration
// is the single source of supported identifiers, native names and Intl tags.
//
//go:embed definitions.json
var definitionsJSON []byte

//go:embed matching-vectors.json
var matchingVectors embed.FS

// Definition describes a shipped interface/output language.
type Definition struct {
	ID         Lang     `json:"id"`
	NativeName string   `json:"nativeName"`
	IntlLocale string   `json:"intlLocale"`
	Aliases    []string `json:"aliases"`
}

var definitions = func() []Definition {
	var declaration struct {
		Default Lang         `json:"default"`
		Locales []Definition `json:"locales"`
	}
	if err := json.Unmarshal(definitionsJSON, &declaration); err != nil {
		panic(err)
	}
	if declaration.Default != Default {
		panic("locale declaration default disagrees with Go default")
	}
	seen := map[Lang]bool{}
	for _, d := range declaration.Locales {
		if d.ID == "" || seen[d.ID] || d.NativeName == "" || d.IntlLocale == "" || len(d.Aliases) == 0 {
			panic("invalid locale definition")
		}
		seen[d.ID] = true
	}
	if !seen[Default] {
		panic("default locale missing from declaration")
	}
	return declaration.Locales
}()

// Definitions returns independent copies of the shipped language declaration.
func Definitions() []Definition {
	out := append([]Definition(nil), definitions...)
	for i := range out {
		out[i].Aliases = append([]string(nil), out[i].Aliases...)
	}
	return out
}

// Languages returns shipped canonical identifiers in declaration order.
func Languages() []Lang {
	out := make([]Lang, len(definitions))
	for i, d := range definitions {
		out[i] = d.ID
	}
	return out
}
