package locale

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var formatVerb = regexp.MustCompile(`%((?:\[[0-9]+\]|[-+# 0-9.*])*)([vTtbcdoOqxXUeEfFgGspw%])`)
var formatIndex = regexp.MustCompile(`\[([0-9]+)\]`)

// Record the argument index and verb, allowing explicit indexed reordering.
func formatArguments(value string) []string {
	next := 1
	var signature []string
	for _, match := range formatVerb.FindAllStringSubmatch(value, -1) {
		if match[2] == "%" {
			continue
		}
		spec := match[1]
		indexes := formatIndex.FindAllStringSubmatchIndex(spec, -1)
		pos := 0
		for _, index := range indexes {
			for strings.Contains(spec[pos:index[0]], "*") {
				star := strings.Index(spec[pos:index[0]], "*")
				signature = append(signature, fmt.Sprintf("%d:width", next))
				next++
				pos += star + 1
			}
			next, _ = strconv.Atoi(spec[index[2]:index[3]])
			pos = index[1]
		}
		for range strings.Count(spec[pos:], "*") {
			signature = append(signature, fmt.Sprintf("%d:width", next))
			next++
		}
		signature = append(signature, fmt.Sprintf("%d:%s", next, match[2]))
		next++
	}
	sort.Strings(signature)
	return signature
}

// ValidateTranslations checks registered values without runtime fallback. The
// authoritative English printf argument indices/types must match every shipped
// language. Packages with external registrations call this in their tests too.
func ValidateTranslations(keys []string) error { return validateTranslations(keys, true) }

// ValidateTextTranslations checks raw template completeness without treating
// literal percentages in prose ("100% with ...") as fmt format directives.
// Stock agent/judge prompts use text/template, not fmt.Sprintf.
func ValidateTextTranslations(keys []string) error { return validateTranslations(keys, false) }

func validateTranslations(keys []string, printf bool) error {
	var problems []error
	for _, key := range keys {
		english, ok := Raw(En, key)
		if !ok || strings.TrimSpace(english) == "" {
			problems = append(problems, fmt.Errorf("missing English translation for %q", key))
			continue
		}
		signature := strings.Join(formatArguments(english), ",")
		for _, lang := range Languages() {
			value, ok := Raw(lang, key)
			if !ok || strings.TrimSpace(value) == "" {
				problems = append(problems, fmt.Errorf("missing %s translation for %q", lang, key))
				continue
			}
			actual := strings.Join(formatArguments(value), ",")
			if printf && signature != actual {
				problems = append(problems, fmt.Errorf("format arguments differ for %q: English %s; %s %s", key, signature, lang, actual))
			}
		}
	}
	return errors.Join(problems...)
}
