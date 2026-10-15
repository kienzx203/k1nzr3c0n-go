package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Skill is one SKILL.md package (agentskills.io format: YAML frontmatter
// name/description + markdown instructions).
type Skill struct {
	Name         string
	Description  string
	Instructions string
	Dir          string
}

var frontmatterRe = regexp.MustCompile(`(?s)^---\n(.*?)\n---\n?(.*)$`)

// LoadSkillsDir reads <base>/skills/*/SKILL.md.
func LoadSkillsDir() []Skill {
	base := filepath.Join(baseDir(), "skills")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []Skill
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(base, e.Name(), "SKILL.md")
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := Skill{Dir: filepath.Join(base, e.Name())}
		body := string(data)
		if m := frontmatterRe.FindStringSubmatch(body); m != nil {
			for _, line := range strings.Split(m[1], "\n") {
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				switch strings.TrimSpace(k) {
				case "name":
					s.Name = v
				case "description":
					s.Description = v
				}
			}
			body = m[2]
		}
		if s.Name == "" {
			s.Name = e.Name()
		}
		s.Instructions = strings.TrimSpace(body)
		out = append(out, s)
	}
	return out
}
