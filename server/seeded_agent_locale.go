package server

import (
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
)

// Normalize the stock reporter/retester metadata to English on a response copy;
// user-edited values remain verbatim. These two stock agents are English-only (the
// product is English), so a legacy Chinese/Korean seed value \u2014 detected as stock in
// ANY language, or by the known legacy Chinese literal \u2014 is forced to English
// regardless of the request language (lang is intentionally not used to pick a
// translation here; it stays in the signature for the call sites).
func localizeSeededAgentMetadata(a *db.Agent, _ locale.Lang) {
	if a.Key == "reporter" {
		if isStockMetadataText(a.Name, "Report writer") || a.Name == "\u62a5\u544a\u64b0\u5199" || containsHan(a.Name) {
			a.Name = "Report writer"
		}
		if isStockMetadataText(a.Description, "Writes detailed vulnerability reports: triggered by findings, reads evidence and execution traces, then saves a Markdown report.") || a.Description == "\u6f0f\u6d1e\u8be6\u7ec6\u62a5\u544a\u64b0\u5199\uff1a\u53d1\u73b0\u6f0f\u6d1e\u65f6\u81ea\u52a8\u89e6\u53d1\uff0c\u67e5\u53d6\u8bc1\u636e\u4e0e\u6267\u884c\u8fc7\u7a0b\u540e\u5199 Markdown \u62a5\u544a\u5e76\u56de\u5199\u3002" || containsHan(a.Description) {
			a.Description = "Writes detailed vulnerability reports: triggered by findings, reads evidence and execution traces, then saves a Markdown report."
		}
	}
	if a.Key == db.FindingRetestAgentKey {
		if isStockMetadataText(a.Name, "Finding retest") || a.Name == "\u6f0f\u6d1e\u590d\u6d4b" || containsHan(a.Name) {
			a.Name = "Finding retest"
		}
		if isStockMetadataText(a.Description, "Started manually from finding details; reads original evidence and saves an independent retest conclusion.") || a.Description == "\u4ece\u6f0f\u6d1e\u8be6\u60c5\u624b\u52a8\u542f\u52a8\uff0c\u8bfb\u53d6\u539f\u8bc1\u636e\u5e76\u4fdd\u5b58\u72ec\u7acb\u590d\u6d4b\u7ed3\u8bba\u3002" || containsHan(a.Description) {
			a.Description = "Started manually from finding details; reads original evidence and saves an independent retest conclusion."
		}
	}
}

func isStockMetadataText(text, english string) bool {
	for _, lang := range locale.Languages() {
		if text == locale.Text(lang, english) {
			return true
		}
	}
	return false
}

// containsHan reports whether s has any CJK ideograph — used to force the stock
// reporter/retester metadata to English even when a legacy seed value doesn't
// exactly match a known stock string.
func containsHan(s string) bool {
	for _, r := range s {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}
