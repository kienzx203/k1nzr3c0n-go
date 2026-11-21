# -*- coding: utf-8 -*-
"""Template-engine unescaped-output scanner (XSS the per-language extractor can't see).

Template files (.blade.php, .jinja/.j2, .twig, .erb, .ejs, .hbs, .vue, …) are not parsed
by the tree-sitter source extractor, so an XSS through a template's RAW/unescaped output
construct is otherwise invisible. Most engines auto-escape `{{ x }}` by default; the bug
is the explicit escape-hatch. We flag those hatches as XSS candidates (the agent confirms
the interpolated value is attacker-controlled).
"""

import os
import re

_EXT = {".blade.php", ".jinja", ".jinja2", ".j2", ".twig", ".erb", ".ejs", ".hbs",
        ".handlebars", ".mustache", ".vue", ".html", ".htm", ".tpl", ".liquid",
        ".cshtml", ".razor", ".svelte", ".jsp", ".jspx"}
_SKIP = {".git", "node_modules", "vendor", ".svn", "dist", "build", ".next", "venv", ".venv"}

# (regex, engine) — each marks output that bypasses the framework's default auto-escaping.
_PATTERNS = [
    (re.compile(r"\{!!.*?!!\}"), "Blade {!! !!} (unescaped)"),
    (re.compile(r"\|\s*safe\b"), "Jinja/Django |safe (unescaped)"),
    (re.compile(r"\|\s*raw\b"), "Twig |raw (unescaped)"),
    (re.compile(r"autoescape\s+false|\{%\s*autoescape\s+off"), "autoescape disabled"),
    (re.compile(r"<%==[^%]"), "ERB <%== (unescaped)"),
    (re.compile(r"\.html_safe\b|\braw\s*\("), "Rails html_safe/raw (unescaped)"),
    (re.compile(r"<%-[^%]"), "EJS <%- (unescaped)"),
    (re.compile(r"\{\{\{[^}]"), "Mustache/Handlebars {{{ }}} (unescaped)"),
    (re.compile(r"v-html\s*="), "Vue v-html (unescaped)"),
    (re.compile(r"\[innerHTML\]\s*=|bypassSecurityTrust"), "Angular innerHTML/bypassSecurityTrust"),
    (re.compile(r"\|\s*striptags\b\s*\|\s*safe"), "Jinja striptags|safe"),
]
# server-side template injection: a template compiled from a variable expression.
_SSTI = re.compile(r"(render_template_string|Template|createTemplate|from_string)\s*\(\s*[\$\w]")


def _is_template(name):
    low = name.lower()
    if low.endswith(".blade.php"):
        return True
    return os.path.splitext(low)[1] in _EXT


def scan(root):
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP]
        for fn in fns:
            if not _is_template(fn):
                continue
            path = os.path.join(dp, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            for i, ln in enumerate(lines, 1):
                for rx, note in _PATTERNS:
                    if rx.search(ln):
                        out.append({
                            "category": "XSS", "func": rel, "pos": "%s:%d" % (path, i),
                            "line": i, "file": rel,
                            "sink": "template unescaped output — %s" % note,
                            "sink_note": "value interpolated here bypasses the template engine's auto-escaping; XSS if it is attacker-controlled",
                            "source": "template variable (confirm it carries request data)",
                            "severity": "medium", "confidence": 0.4,
                            "weak_sanitizer": False, "interproc": False,
                        })
                        break
                if _SSTI.search(ln):
                    out.append({
                        "category": "TEMPLATE_INJECTION", "func": rel, "pos": "%s:%d" % (path, i),
                        "line": i, "file": rel,
                        "sink": "template compiled from a variable (SSTI)",
                        "sink_note": "a template rendered from a non-literal string allows server-side template injection if attacker-controlled",
                        "source": "template source expression",
                        "severity": "high", "confidence": 0.45,
                        "weak_sanitizer": False, "interproc": False,
                    })
    return out
