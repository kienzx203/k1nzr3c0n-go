package api

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"k1nzr3c0n/internal/agent"
	"k1nzr3c0n/internal/config"
)

func skillsDir() string { return filepath.Join(config.BaseDir(), "skills") }

// handleSkillOverview powers the Skill library overview (stats + ranking + recent).
func (s *Server) handleSkillOverview(w http.ResponseWriter, r *http.Request) {
	skills := agent.LoadSkillsDir()
	stats, _ := s.St.SkillStats()
	missing, _ := s.St.MissingSkillStats()
	recent, _ := s.St.RecentSkillCalls("", 20)

	calledNames := map[string]bool{}
	ranking := []map[string]any{}
	for _, st := range stats {
		calledNames[st.Skill] = true
		ranking = append(ranking, map[string]any{
			"skill": st.Skill, "calls": st.Calls, "agents": st.Agents, "last_used": iso(st.LastUsed),
		})
	}
	unused := []string{}
	for _, sk := range skills {
		if !calledNames[sk.Name] {
			unused = append(unused, sk.Name)
		}
	}
	unmatched := 0
	missList := []map[string]any{}
	for _, m := range missing {
		unmatched += m.Calls
		missList = append(missList, map[string]any{"skill": m.Skill, "calls": m.Calls})
	}
	recentOut := []map[string]any{}
	for _, c := range recent {
		recentOut = append(recentOut, map[string]any{
			"id": c.ID, "skill": c.Skill, "agent_key": c.AgentKey, "found": c.Found, "created_at": iso(c.CreatedAt),
		})
	}
	writeJSON(w, 200, map[string]any{
		"total_skills":     len(skills),
		"total_calls":      s.St.TotalSkillCalls(),
		"called_skills":    len(calledNames),
		"unused_count":     len(unused),
		"unused_skills":    unused,
		"unmatched_calls":  unmatched,
		"unmatched_detail": missList,
		"call_ranking":     ranking,
		"recent_calls":     recentOut,
	})
}

// handleSkillFiles lists the files inside one skill folder (tree).
func (s *Server) handleSkillFiles(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	dir := filepath.Join(skillsDir(), name)
	if _, err := os.Stat(dir); err != nil {
		writeDetail(w, 404, "skill not found")
		return
	}
	out := []map[string]any{}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, map[string]any{"path": filepath.ToSlash(rel), "size": info.Size()})
		return nil
	})
	writeJSON(w, 200, map[string]any{"name": name, "files": out})
}

// handleSkillFileGet returns one skill file's content.
func (s *Server) handleSkillFileGet(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	file := filepath.Clean("/" + r.PathValue("file"))[1:] // strip traversal
	full := filepath.Join(skillsDir(), name, file)
	data, err := os.ReadFile(full)
	if err != nil {
		writeDetail(w, 404, "file not found")
		return
	}
	writeJSON(w, 200, map[string]any{"path": file, "content": string(data)})
}

// handleSkillUsage returns recent calls for one skill.
func (s *Server) handleSkillUsage(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	calls, _ := s.St.RecentSkillCalls(name, 50)
	out := []map[string]any{}
	for _, c := range calls {
		out = append(out, map[string]any{"id": c.ID, "agent_key": c.AgentKey, "found": c.Found, "created_at": iso(c.CreatedAt)})
	}
	writeJSON(w, 200, map[string]any{"skill": name, "calls": out})
}

// handleSkillCreate writes a new SKILL.md (agentskills.io frontmatter).
func (s *Server) handleSkillCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Content     string `json:"content"`
	}
	if err := readJSON(r, &body); err != nil || body.Name == "" {
		writeDetail(w, 422, "name is required")
		return
	}
	name := sanitizeSkillName(body.Name)
	dir := filepath.Join(skillsDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	md := body.Content
	if !strings.HasPrefix(md, "---") {
		md = "---\nname: " + name + "\ndescription: " + body.Description + "\n---\n\n" + md
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"name": name, "created": true})
}

// handleSkillDelete removes a skill folder.
func (s *Server) handleSkillDelete(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	if name == "" || name == "." || strings.Contains(name, "..") {
		writeDetail(w, 422, "bad name")
		return
	}
	if err := os.RemoveAll(filepath.Join(skillsDir(), name)); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": name})
}

// handleSkillUpload accepts a .zip or .tar.gz archive and extracts it into skills/.
func (s *Server) handleSkillUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeDetail(w, 422, "invalid multipart form")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeDetail(w, 422, "file field required")
		return
	}
	defer file.Close()
	lower := strings.ToLower(hdr.Filename)
	n := 0
	switch {
	case strings.HasSuffix(lower, ".zip"):
		n, err = extractZip(file, hdr.Size, skillsDir())
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		n, err = extractTarGz(file, skillsDir())
	default:
		writeDetail(w, 422, "upload a .zip or .tar.gz archive")
		return
	}
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"extracted_files": n})
}

func sanitizeSkillName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		out = "skill"
	}
	return out
}

func safeJoin(base, name string) (string, bool) {
	clean := filepath.Clean("/" + name)[1:]
	full := filepath.Join(base, clean)
	if !strings.HasPrefix(full, filepath.Clean(base)+string(os.PathSeparator)) && full != filepath.Clean(base) {
		return "", false
	}
	return full, true
}

func extractZip(r io.ReaderAt, size int64, dest string) (int, error) {
	// io.ReaderAt from multipart File (it implements ReaderAt)
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range zr.File {
		full, ok := safeJoin(dest, f.Name)
		if !ok {
			continue
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(full, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(full)
		if err != nil {
			rc.Close()
			continue
		}
		io.Copy(out, rc)
		out.Close()
		rc.Close()
		n++
	}
	return n, nil
}

func extractTarGz(r io.Reader, dest string) (int, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		full, ok := safeJoin(dest, h.Name)
		if !ok {
			continue
		}
		if h.FileInfo().IsDir() {
			os.MkdirAll(full, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		out, err := os.Create(full)
		if err != nil {
			continue
		}
		io.Copy(out, tr)
		out.Close()
		n++
	}
	return n, nil
}
