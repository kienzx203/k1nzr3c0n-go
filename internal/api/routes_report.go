package api

import (
	"net/http"
	"strconv"

	"k1nzr3c0n/internal/report"
	"k1nzr3c0n/internal/store"
)

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	switch run.Status {
	case "completed", "failed", "paused":
	default:
		writeDetail(w, 400, "Report not available for status: "+run.Status)
		return
	}
	items, _, _ := s.St.ListRunFindings(run.ID, store.FindingFilter{Limit: 1000})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"report-"+run.ID+".html\"")
	w.Write([]byte(report.HTML(run, items)))
}

func (s *Server) handleReportDraft(w http.ResponseWriter, r *http.Request) {
	run := s.getRunOr404(w, r.PathValue("run_id"))
	if run == nil {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "hackerone"
	}
	switch format {
	case "hackerone", "bugcrowd", "markdown":
	default:
		writeDetail(w, 422, "format must match ^(hackerone|bugcrowd|markdown)$")
		return
	}
	items, _, _ := s.St.ListRunFindings(run.ID, store.FindingFilter{
		Kind: "vuln", Status: "open", Limit: 1000,
	})
	report.SortBySeverity(items)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"draft-"+run.ID+"-"+format+".md\"")
	w.Write([]byte(report.Draft(run, items, format)))
}

var _ = strconv.Itoa
