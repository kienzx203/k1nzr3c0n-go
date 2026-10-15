import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'

// ─── Phase palette ─────────────────────────────────────────────────────────────
const PHASES = {
  discovery: { label: 'Discovery',   color: '#58a6ff', icon: '◉' },
  resolve:   { label: 'Resolve',     color: '#79c0ff', icon: '⊕' },
  process:   { label: 'Process',     color: '#a371f7', icon: '◈' },
  scan:      { label: 'Scan',        color: '#f0b429', icon: '◎' },
  crawl:     { label: 'Crawl',       color: '#3fb950', icon: '⊛' },
  brute:     { label: 'Brute',       color: '#ff9966', icon: '◎' },
  vuln:      { label: 'Vuln',        color: '#f85149', icon: '⚑' },
  report:    { label: 'Report',      color: '#56d364', icon: '▤' },
}

// ─── Step definitions (tool id → default config) ───────────────────────────────
function mk(id, name, phase, run, opts = {}) {
  const s = { id, name, _phase: phase, shell: true, optional: true, run, ...opts }
  if (!s.depends_on) delete s.depends_on
  return s
}
const SD = {
  subfinder:        mk('subfinder',        'Subfinder',         'discovery', 'subfinder -d {target} -all -silent -o {workspace}/subdomains_subfinder.txt 2>/dev/null; true'),
  amass:            mk('amass',            'Amass',             'discovery', 'amass enum -passive -d {target} -o {workspace}/subdomains_amass.txt 2>/dev/null; true'),
  assetfinder:      mk('assetfinder',      'Assetfinder',       'discovery', 'assetfinder --subs-only {target} 2>/dev/null > {workspace}/subdomains_assetfinder.txt; true'),
  findomain:        mk('findomain',        'Findomain',         'discovery', 'findomain -t {target} -u {workspace}/subdomains_findomain.txt 2>/dev/null; true'),
  gobuster_dns:     mk('gobuster_dns',     'Gobuster DNS',      'discovery', 'gobuster dns -d {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 --no-error -o {workspace}/subdomains_gobuster_dns.txt 2>/dev/null; true'),
  merge_subdomains: mk('merge_subdomains', 'Merge Subdomains',  'process',   '( echo {target}; echo www.{target}; cat {workspace}/subdomains_*.txt 2>/dev/null ) | sort -u > {workspace}/subdomains.txt; true'),
  dnsx_resolve:     mk('dnsx_resolve',     'DNSX Resolve',      'resolve',   'cat {workspace}/subdomains.txt | dnsx -silent -r {vars.dns_resolvers} -t 200 -o {workspace}/subdomains_resolved.txt 2>/dev/null; true'),
  httpx:            mk('httpx',            'HTTPX Probe',       'process',   'cat {workspace}/subdomains_resolved.txt | httpx -silent -threads 200 -json -o {workspace}/httpx.jsonl -follow-redirects -title -tech-detect -status-code 2>/dev/null; true'),
  subzy:            mk('subzy',            'Subzy',             'process',   'subzy run --targets {workspace}/subdomains_resolved.txt --hide-fails --output {workspace}/subzy.txt 2>/dev/null; true'),
  naabu:            mk('naabu',            'Naabu',             'scan',      'naabu -list {workspace}/subdomains_resolved.txt -p top-100 -rate 2000 -exclude-cdn -silent -json -o {workspace}/naabu.jsonl 2>/dev/null; true'),
  katana:           mk('katana',           'Katana',            'crawl',     'katana -list {workspace}/httpx.jsonl -depth 3 -silent -jsonl -jc -aff -o {workspace}/katana.jsonl 2>/dev/null; true'),
  gau:              mk('gau',             'GAU',               'crawl',     'cat {workspace}/subdomains_resolved.txt | gau --blacklist png,jpg,gif,svg,css,woff --threads 5 --json 2>/dev/null > {workspace}/gau.jsonl; true'),
  waybackurls:      mk('waybackurls',      'Wayback URLs',      'crawl',     'cat {workspace}/subdomains_resolved.txt | waybackurls 2>/dev/null > {workspace}/waybackurls.txt; true'),
  merge_urls:       mk('merge_urls',       'Merge URLs',        'crawl',     '( jq -r \'.request.endpoint // .endpoint // empty\' {workspace}/katana.jsonl 2>/dev/null; cat {workspace}/gau.jsonl 2>/dev/null | jq -r \'.url // empty\'; cat {workspace}/waybackurls.txt 2>/dev/null ) | grep -E \'^https?://\' | sort -u > {workspace}/urls_all.txt; true'),
  feroxbuster:      mk('feroxbuster',      'Feroxbuster',       'brute',     'jq -r \'.url\' {workspace}/httpx.jsonl | feroxbuster --stdin -w {vars.dir_wordlist} -t 50 --silent --json -o {workspace}/feroxbuster.json 2>/dev/null; true'),
  dirsearch:        mk('dirsearch',        'Dirsearch',         'brute',     'jq -r \'.url\' {workspace}/httpx.jsonl > {workspace}/httpx_urls.txt; dirsearch -l {workspace}/httpx_urls.txt -w {vars.dir_wordlist} -o {workspace}/dirsearch.txt --format=plain -q 2>/dev/null; true'),
  ffuf:             mk('ffuf',             'FFUF',              'brute',     'ffuf -w {vars.dir_wordlist} -u https://{target}/FUZZ -mc 200,301,302,403 -o {workspace}/ffuf.json -of json -s 2>/dev/null; true'),
  kiterunner:       mk('kiterunner',       'Kiterunner',        'brute',     'kr scan {workspace}/httpx.jsonl -w {vars.kr_wordlist} -j 2>/dev/null > {workspace}/kiterunner.txt; true'),
  nuclei:           mk('nuclei',           'Nuclei',            'vuln',      'nuclei -l {workspace}/httpx.jsonl -nmhe -jsonl -silent -rl 150 -c 25 -timeout 8 -etags dns -o {workspace}/nuclei.jsonl 2>/dev/null; touch {workspace}/nuclei.jsonl'),
  nuclei_urls:      mk('nuclei_urls',      'Nuclei on URLs',    'vuln',      'test -s {workspace}/urls_all.txt && timeout 3600 nuclei -l {workspace}/urls_all.txt -nmhe -jsonl -silent -rl 100 -c 20 -timeout 8 -etags dns -o {workspace}/nuclei_urls.jsonl 2>/dev/null || true; touch {workspace}/nuclei_urls.jsonl'),
  afrog:            mk('afrog',            'Afrog',             'vuln',      'afrog -T {workspace}/httpx.jsonl -o {workspace}/afrog.jsonl -json 2>/dev/null; true'),
  param_discover:   mk('param_discover',   'Param Discovery',   'vuln',      'test -s {workspace}/urls_all.txt && arjun -i {workspace}/urls_all.txt --rate-limit 10 -oJ {workspace}/arjun.json 2>/dev/null; true'),
  nuclei_report:    mk('nuclei_report',    'Nuclei Report',     'report',    '( test -s {workspace}/nuclei.jsonl || test -s {workspace}/nuclei_urls.jsonl ) && python {vars.scripts_dir}/scripts/nuclei_report.py --input {workspace}/nuclei.jsonl {workspace}/nuclei_urls.jsonl --out {workspace}/nuclei_report || mkdir -p {workspace}/nuclei_report; true'),
}

const DEFAULT_VARS = {
  dns_resolvers:    '1.1.1.1,8.8.8.8,9.9.9.9',
  dnsx_threads:     '200',
  dnsx_retry:       '3',
  naabu_rate:       '2000',
  naabu_top_ports:  'top-100',
  httpx_threads:    '200',
  katana_depth:     '3',
  dir_wordlist:     '/usr/share/seclists/Discovery/Web-Content/common.txt',
  kr_wordlist:      '/app/wordlists/routes-large.kite',
  arjun_rate:       '10',
  scripts_dir:      '/app',
}

// Build steps from chain definition [{id, deps?}, ...]
function buildSteps(chain) {
  return chain.map(item => {
    const { id, deps } = typeof item === 'string' ? { id: item, deps: [] } : item
    const base = SD[id] || { id, name: id, _phase: 'scan', shell: true, optional: true, run: '' }
    const step = { ...base }
    if (deps && deps.length > 0) {
      step.depends_on = deps
    } else {
      delete step.depends_on
    }
    return step
  })
}

// ─── Workflow Templates ─────────────────────────────────────────────────────────
const WF_TEMPLATES = [
  {
    id: 'blank',
    name: 'Blank Canvas',
    icon: '◻',
    accent: 'var(--text-3)',
    glow: 'var(--border)',
    desc: 'Empty canvas — drag tools from the Library panel and wire them however you want. Full control from step one.',
    time: null,
    phases: [],
    chain: [],
    extraVars: {},
  },
  {
    id: 'quick_recon',
    name: 'Quick Recon',
    icon: '⚡',
    accent: '#f0b429',
    glow: '#f0b42920',
    desc: 'One subdomain source → DNS resolve → live HTTP probe → Nuclei template scan → report. Fastest path from domain to findings.',
    time: '~20 min',
    phases: ['discovery', 'resolve', 'process', 'vuln', 'report'],
    chain: [
      { id: 'subfinder',        deps: [] },
      { id: 'merge_subdomains', deps: ['subfinder'] },
      { id: 'dnsx_resolve',     deps: ['merge_subdomains'] },
      { id: 'httpx',            deps: ['dnsx_resolve'] },
      { id: 'nuclei',           deps: ['httpx'] },
      { id: 'nuclei_report',    deps: ['nuclei'] },
    ],
    extraVars: {},
  },
  {
    id: 'bug_bounty',
    name: 'Bug Bounty',
    icon: '🎯',
    accent: '#f85149',
    glow: '#f8514920',
    desc: 'Multi-source subdomain enum → takeover check → parallel crawl (Katana + GAU) → Nuclei on hosts & URL surface → report. Built for program submissions.',
    time: '1–2 hr',
    phases: ['discovery', 'resolve', 'process', 'crawl', 'vuln', 'report'],
    chain: [
      { id: 'subfinder',        deps: [] },
      { id: 'amass',            deps: [] },
      { id: 'assetfinder',      deps: [] },
      { id: 'merge_subdomains', deps: ['subfinder', 'amass', 'assetfinder'] },
      { id: 'dnsx_resolve',     deps: ['merge_subdomains'] },
      { id: 'httpx',            deps: ['dnsx_resolve'] },
      { id: 'subzy',            deps: ['dnsx_resolve'] },
      { id: 'katana',           deps: ['httpx'] },
      { id: 'gau',              deps: ['dnsx_resolve'] },
      { id: 'merge_urls',       deps: ['katana', 'gau'] },
      { id: 'nuclei',           deps: ['httpx'] },
      { id: 'nuclei_urls',      deps: ['merge_urls'] },
      { id: 'nuclei_report',    deps: ['nuclei', 'nuclei_urls'] },
    ],
    extraVars: {},
  },
  {
    id: 'full_audit',
    name: 'Full Audit',
    icon: '◈',
    accent: '#a371f7',
    glow: '#a371f720',
    desc: '5-source discovery → port scan → deep crawl → directory brute-force → API route discovery → Nuclei + Afrog + param fuzzing → report. Leave no stone unturned.',
    time: '4+ hr',
    phases: ['discovery', 'resolve', 'process', 'scan', 'crawl', 'brute', 'vuln', 'report'],
    chain: [
      { id: 'subfinder',        deps: [] },
      { id: 'amass',            deps: [] },
      { id: 'assetfinder',      deps: [] },
      { id: 'findomain',        deps: [] },
      { id: 'gobuster_dns',     deps: [] },
      { id: 'merge_subdomains', deps: ['subfinder', 'amass', 'assetfinder', 'findomain', 'gobuster_dns'] },
      { id: 'dnsx_resolve',     deps: ['merge_subdomains'] },
      { id: 'naabu',            deps: ['dnsx_resolve'] },
      { id: 'httpx',            deps: ['dnsx_resolve'] },
      { id: 'subzy',            deps: ['dnsx_resolve'] },
      { id: 'katana',           deps: ['httpx'] },
      { id: 'gau',              deps: ['dnsx_resolve'] },
      { id: 'waybackurls',      deps: ['dnsx_resolve'] },
      { id: 'merge_urls',       deps: ['katana', 'gau', 'waybackurls'] },
      { id: 'feroxbuster',      deps: ['httpx'] },
      { id: 'dirsearch',        deps: ['httpx'] },
      { id: 'kiterunner',       deps: ['httpx'] },
      { id: 'nuclei',           deps: ['httpx'] },
      { id: 'nuclei_urls',      deps: ['merge_urls'] },
      { id: 'afrog',            deps: ['httpx'] },
      { id: 'param_discover',   deps: ['merge_urls'] },
      { id: 'nuclei_report',    deps: ['nuclei', 'nuclei_urls'] },
    ],
    extraVars: {},
  },
  {
    id: 'passive_only',
    name: 'Passive Only',
    icon: '🥷',
    accent: '#3fb950',
    glow: '#3fb95020',
    desc: 'Zero active traffic. Passive subdomain enum via cert transparency, APIs and DNS archives only. Safe for OSINT and initial reconnaissance.',
    time: '5–10 min',
    phases: ['discovery', 'resolve'],
    chain: [
      { id: 'subfinder',        deps: [] },
      { id: 'amass',            deps: [] },
      { id: 'assetfinder',      deps: [] },
      { id: 'findomain',        deps: [] },
      { id: 'merge_subdomains', deps: ['subfinder', 'amass', 'assetfinder', 'findomain'] },
      { id: 'dnsx_resolve',     deps: ['merge_subdomains'] },
    ],
    extraVars: {},
  },
  {
    id: 'api_attack',
    name: 'API Attack',
    icon: '⬡',
    accent: '#79c0ff',
    glow: '#79c0ff20',
    desc: 'Subdomain → HTTP → crawl (Katana + GAU) → Kiterunner API route brute → FFUF directory fuzz → param discovery → Nuclei on URL surface → report. Targets REST, GraphQL and microservice APIs.',
    time: '30–60 min',
    phases: ['discovery', 'resolve', 'process', 'crawl', 'brute', 'vuln', 'report'],
    chain: [
      { id: 'subfinder',        deps: [] },
      { id: 'merge_subdomains', deps: ['subfinder'] },
      { id: 'dnsx_resolve',     deps: ['merge_subdomains'] },
      { id: 'httpx',            deps: ['dnsx_resolve'] },
      { id: 'katana',           deps: ['httpx'] },
      { id: 'gau',              deps: ['dnsx_resolve'] },
      { id: 'merge_urls',       deps: ['katana', 'gau'] },
      { id: 'kiterunner',       deps: ['httpx'] },
      { id: 'ffuf',             deps: ['httpx'] },
      { id: 'param_discover',   deps: ['merge_urls'] },
      { id: 'nuclei_urls',      deps: ['merge_urls'] },
      { id: 'nuclei_report',    deps: ['nuclei_urls'] },
    ],
    extraVars: {
      dir_wordlist: '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
    },
  },
]

// ─── New Workflow Wizard ────────────────────────────────────────────────────────
function NewWorkflowModal({ onClose, onCreated }) {
  const [selected, setSelected] = useState('quick_recon')
  const [name, setName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const tpl = WF_TEMPLATES.find(t => t.id === selected)
  const normalized = name.trim().replace(/\.yaml$/, '')

  async function handleCreate() {
    if (!normalized) { setError('Enter a workflow name'); return }
    if (!/^[\w\-]+$/.test(normalized)) {
      setError('Only letters, numbers, hyphens and underscores')
      return
    }
    setLoading(true)
    setError('')
    try {
      const steps = buildSteps(tpl.chain)
      const vars = { ...DEFAULT_VARS, ...tpl.extraVars }
      await api.saveWorkflow(`${normalized}.yaml`, { vars, steps })
      onCreated(`${normalized}.yaml`)
    } catch (e) {
      setError(e.message || 'Failed to create workflow')
      setLoading(false)
    }
  }

  // Phase pills display
  function PhasePill({ pk }) {
    const p = PHASES[pk]
    if (!p) return null
    return (
      <span style={{
        fontSize: 9.5, fontWeight: 700, letterSpacing: '.04em',
        color: p.color, border: `1px solid ${p.color}44`,
        background: `${p.color}0e`, borderRadius: 4,
        padding: '2px 7px', whiteSpace: 'nowrap',
        display: 'inline-flex', alignItems: 'center', gap: 3,
      }}>
        {p.icon} {p.label}
      </span>
    )
  }

  // Step chain visualization (horizontal scrollable)
  function StepChain({ chain }) {
    if (!chain.length) {
      return (
        <div style={{ textAlign: 'center', color: 'var(--text-3)', fontSize: 11, padding: '12px 0' }}>
          Empty canvas — build from scratch using the Library panel
        </div>
      )
    }
    // Group by phase for display
    const items = chain.map(({ id }) => SD[id] || { id, name: id, _phase: 'scan' })
    // Build level map for showing parallel groups
    const levelMap = {}
    const depMap = {}
    chain.forEach(({ id, deps }) => { depMap[id] = deps || [] })
    // topological levels
    function getLevel(id, seen = new Set()) {
      if (levelMap[id] != null) return levelMap[id]
      if (seen.has(id)) return 0
      seen.add(id)
      const deps = depMap[id] || []
      if (!deps.length) { levelMap[id] = 0; return 0 }
      levelMap[id] = Math.max(...deps.map(d => getLevel(d, seen))) + 1
      return levelMap[id]
    }
    chain.forEach(({ id }) => getLevel(id))
    const byLevel = {}
    chain.forEach(({ id }) => {
      const l = levelMap[id] || 0
      ;(byLevel[l] = byLevel[l] || []).push(id)
    })
    const levels = Object.keys(byLevel).map(Number).sort((a, b) => a - b)

    return (
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 0, overflowX: 'auto',
        paddingBottom: 4, minHeight: 50 }}>
        {levels.map((lv, li) => (
          <div key={lv} style={{ display: 'flex', alignItems: 'center', gap: 0, flexShrink: 0 }}>
            {li > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', padding: '0 2px' }}>
                <div style={{ width: 18, height: 1, background: 'var(--border)' }} />
                <div style={{ width: 0, height: 0, borderTop: '3px solid transparent',
                  borderBottom: '3px solid transparent', borderLeft: '5px solid #30363d' }} />
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {byLevel[lv].map(id => {
                const step = SD[id] || { id, name: id, _phase: 'scan' }
                const ph = PHASES[step._phase] || PHASES.scan
                return (
                  <div key={id} style={{
                    fontSize: 9, fontFamily: 'monospace', fontWeight: 600,
                    color: ph.color, background: `${ph.color}12`,
                    border: `1px solid ${ph.color}33`,
                    borderRadius: 4, padding: '2px 7px',
                    whiteSpace: 'nowrap',
                  }}>
                    {id}
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    )
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,.82)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: 'var(--bg-soft)', border: '1px solid #30363d', borderRadius: 12,
        width: 780, maxHeight: '90vh', display: 'flex', flexDirection: 'column',
        boxShadow: `0 32px 96px rgba(0,0,0,.8), 0 0 0 1px #161b22`,
        overflow: 'hidden',
      }}>

        {/* ── Header ── */}
        <div style={{
          padding: '18px 22px 14px', borderBottom: '1px solid #21262d',
          display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
          flexShrink: 0,
        }}>
          <div>
            <div style={{ fontSize: 10, color: '#58a6ff', fontWeight: 700,
              letterSpacing: '.08em', textTransform: 'uppercase', marginBottom: 4 }}>
              ◈ New Workflow
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text)', lineHeight: 1 }}>
              Choose a starting template
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 5 }}>
              Each template comes pre-wired with the right tools and dependencies.
              You can add, remove or modify steps in the editor.
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: 'var(--text-2)',
            cursor: 'pointer', fontSize: 22, lineHeight: 1, padding: '0 2px', marginTop: -2,
          }}>×</button>
        </div>

        {/* ── Template Grid ── */}
        <div style={{ padding: '16px 22px 0', flexShrink: 0 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {WF_TEMPLATES.map(t => {
              const isSel = selected === t.id
              return (
                <button key={t.id} onClick={() => setSelected(t.id)} style={{
                  background: isSel ? `${t.glow || 'var(--surface-2)'}` : 'var(--surface)',
                  border: `1.5px solid ${isSel ? t.accent : 'var(--border)'}`,
                  borderRadius: 8, padding: '11px 14px', cursor: 'pointer',
                  textAlign: 'left', transition: 'all .15s',
                  boxShadow: isSel ? `0 0 0 3px ${t.accent}22` : 'none',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ fontSize: 17 }}>{t.icon}</span>
                    <span style={{ fontSize: 12, fontWeight: 700,
                      color: isSel ? t.accent : 'var(--text)', letterSpacing: '.01em' }}>
                      {t.name}
                    </span>
                    {t.time && (
                      <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--text-3)',
                        background: 'var(--surface)', border: '1px solid #21262d',
                        borderRadius: 3, padding: '1px 5px', whiteSpace: 'nowrap' }}>
                        {t.time}
                      </span>
                    )}
                  </div>
                  {/* Phase pills — minimal */}
                  <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                    {t.phases.length === 0
                      ? <span style={{ fontSize: 9.5, color: 'var(--text-3)' }}>Custom</span>
                      : t.phases.map(pk => {
                        const p = PHASES[pk]
                        return p ? (
                          <span key={pk} style={{
                            fontSize: 8, color: p.color, border: `1px solid ${p.color}33`,
                            background: `${p.color}0c`, borderRadius: 3, padding: '1px 5px',
                          }}>{p.icon}</span>
                        ) : null
                      })}
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* ── Template Detail ── */}
        {tpl && (
          <div style={{
            margin: '14px 22px 0',
            background: 'var(--surface)', border: `1px solid ${tpl.accent}33`,
            borderRadius: 8, padding: '14px 16px',
            flexShrink: 0,
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 10 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 700, color: tpl.accent }}>
                    {tpl.icon} {tpl.name}
                  </span>
                  {tpl.chain.length > 0 && (
                    <span style={{ fontSize: 9.5, color: 'var(--text-2)', background: 'var(--bg-soft)',
                      border: '1px solid #21262d', borderRadius: 4, padding: '1px 7px' }}>
                      {tpl.chain.length} steps
                    </span>
                  )}
                  {tpl.time && (
                    <span style={{ fontSize: 9.5, color: '#f0b429', background: '#1f1800',
                      border: '1px solid #f0b42933', borderRadius: 4, padding: '1px 7px' }}>
                      ⏱ {tpl.time}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-2)', lineHeight: 1.65, marginBottom: 10 }}>
                  {tpl.desc}
                </div>
                {/* Phase flow */}
                {tpl.phases.length > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', marginBottom: 8 }}>
                    {tpl.phases.map((pk, i) => (
                      <React.Fragment key={pk}>
                        {i > 0 && <span style={{ color: 'var(--text-3)', fontSize: 9 }}>→</span>}
                        <span style={{
                          fontSize: 9.5, fontWeight: 700, color: PHASES[pk]?.color,
                          border: `1px solid ${PHASES[pk]?.color}44`,
                          background: `${PHASES[pk]?.color}0d`,
                          borderRadius: 4, padding: '2px 8px',
                          display: 'inline-flex', alignItems: 'center', gap: 3,
                        }}>
                          {PHASES[pk]?.icon} {PHASES[pk]?.label}
                        </span>
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>
            </div>
            {/* Step chain */}
            <div style={{ background: 'var(--bg-soft)', borderRadius: 6, padding: '8px 12px',
              border: '1px solid #21262d' }}>
              <div style={{ fontSize: 9, color: 'var(--text-3)', fontWeight: 700,
                letterSpacing: '.07em', textTransform: 'uppercase', marginBottom: 6 }}>
                Execution Flow
              </div>
              <StepChain chain={tpl.chain} />
            </div>
          </div>
        )}

        {/* ── Name Input + Create ── */}
        <div style={{
          padding: '16px 22px 20px', borderTop: '1px solid #21262d', marginTop: 14,
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
            <div style={{ flex: 1 }}>
              <label style={{ fontSize: 9.5, color: 'var(--text-2)', fontWeight: 700,
                letterSpacing: '.06em', textTransform: 'uppercase', display: 'block', marginBottom: 5 }}>
                Workflow name
              </label>
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <input
                  className="input"
                  placeholder={`${selected}_recon`}
                  value={name}
                  onChange={e => { setName(e.target.value); setError('') }}
                  onKeyDown={e => e.key === 'Enter' && handleCreate()}
                  autoFocus
                  style={{ borderRadius: '6px 0 0 6px', borderRight: 'none', fontFamily: 'monospace' }}
                />
                <span style={{
                  padding: '6px 10px', background: 'var(--surface)', border: '1px solid #30363d',
                  borderRadius: '0 6px 6px 0', fontSize: 11, color: 'var(--text-3)',
                  lineHeight: '1.6', whiteSpace: 'nowrap',
                }}>.yaml</span>
              </div>
              {error && (
                <div style={{ fontSize: 10, color: '#f85149', marginTop: 4 }}>✕ {error}</div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              <button className="btn btn-ghost" onClick={onClose}
                style={{ fontSize: 12, padding: '7px 16px' }}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleCreate}
                disabled={loading || !normalized}
                style={{ fontSize: 12, padding: '7px 18px', minWidth: 130 }}>
                {loading ? '⌛ Creating…' : `◈ Create & Open →`}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Workflow meta for known files ─────────────────────────────────────────────
const WORKFLOW_META = {
  'k1nzr3con.yaml': {
    desc: 'Full unified recon — 31 steps, 9 phases: discovery → scan → crawl → vuln → report',
    steps: 31, tags: ['passive', 'active', 'vuln', 'full'],
  },
  '01-full-recon-pipeline.yaml': {
    desc: 'Enterprise recon — 47 steps, 14 phases: passive+active subdomain → ASN/IP → TLS SAN mining → puredns+dnsx resolve → port scan → HTTP → CDN check → crawl → JS analysis → takeover → cloud storage → nuclei/afrog vuln scan',
    steps: 47, tags: ['passive', 'active', 'tlsx', 'crawl', 'js', 'vuln', 'full'],
  },
  '02-js-secrets-recon.yaml': {
    desc: 'JS & secrets recon — 19 steps: probe → katana/hakrawler/gau/waymore/waybackurls crawl → collect JS → LinkFinder/jsapiscan/SecretFinder/TruffleHog/Gitleaks/jsubfinder → nuclei file/keys + http/exposures → gf patterns → dirsearch/ffuf/feroxbuster/gobuster brute-force → report',
    steps: 19, tags: ['js', 'secrets', 'crawl', 'nuclei', 'gf', 'trufflehog', 'gitleaks', 'ffuf'],
  },
  '03-param-discovery.yaml': {
    desc: 'Authenticated parameter discovery — 8 steps: probe với auth headers → fallparams/gau/katana crawl → extract existing params → arjun/x8/ffuf brute-force → merge → report. Hỗ trợ Cookie, Authorization, custom headers',
    steps: 8, tags: ['params', 'auth', 'arjun', 'x8', 'ffuf', 'session'],
  },
}

// ─── Workflows list page ────────────────────────────────────────────────────────
export default function Workflows() {
  const [workflows, setWorkflows] = useState([])
  const [showNew, setShowNew] = useState(false)
  const [deleting, setDeleting] = useState(null)
  const [importing, setImporting] = useState(false)
  const fileRef = React.useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    api.getWorkflows().then(setWorkflows).catch(() => {})
  }, [])

  async function handleImport(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setImporting(true)
    try {
      const text = await file.text()
      const name = file.name.endsWith('.yaml') ? file.name : file.name + '.yaml'
      await api.importWorkflow(name, text)   // server validates with the full engine
      const list = await api.getWorkflows()
      setWorkflows(list)
      alert(`Imported ${name}`)
    } catch (err) {
      alert(err.message || 'Import failed')
    } finally {
      setImporting(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  async function handleDelete(name, e) {
    e.preventDefault()
    e.stopPropagation()
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return
    setDeleting(name)
    try {
      await api.deleteWorkflow(name)
      setWorkflows(prev => prev.filter(w => w !== name))
    } catch (err) {
      alert(err.message || 'Delete failed')
    }
    setDeleting(null)
  }

  function handleCreated(filename) {
    setShowNew(false)
    navigate(`/workflows/${encodeURIComponent(filename)}`)
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-[var(--text)]">Workflows</h1>
          <p className="text-xs text-[var(--text-2)] mt-0.5">
            Visual drag-drop editor — click a workflow to open the canvas
          </p>
        </div>
        <div className="flex gap-2">
          <input ref={fileRef} type="file" accept=".yaml,.yml" className="hidden" onChange={handleImport} />
          <button
            className="btn btn-accent"
            style={{ fontSize: 12 }}
            disabled={importing}
            onClick={() => fileRef.current?.click()}>
            {importing ? 'Importing…' : '⬆ Import YAML'}
          </button>
          <button
            className="btn btn-primary"
            style={{ fontSize: 12 }}
            onClick={() => setShowNew(true)}>
            + New Workflow
          </button>
        </div>
      </div>

      <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))' }}>
        {workflows.map(name => {
          const meta = WORKFLOW_META[name] || {}
          return (
            <Link key={name} to={`/workflows/${encodeURIComponent(name)}`}
              className="card p-4 hover:border-[#58a6ff44] transition-colors block group relative"
              style={{ textDecoration: 'none' }}>
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-[var(--accent)] text-lg">◈</span>
                  <span className="font-mono font-bold text-sm text-[var(--text)] group-hover:text-[var(--accent)] transition-colors">
                    {name}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {meta.steps && (
                    <span className="text-[10px] text-[var(--text-3)] border border-[var(--border)] rounded px-1.5 py-0.5 shrink-0">
                      {meta.steps} steps
                    </span>
                  )}
                  <a
                    href={api.workflowDownloadUrl(name)}
                    onClick={e => e.stopPropagation()}
                    title="Download YAML (share/export)"
                    style={{
                      background: 'none', border: '1px solid var(--border)', borderRadius: 4,
                      color: 'var(--text-2)', fontSize: 11, padding: '2px 7px', textDecoration: 'none',
                    }}>
                    ⬇
                  </a>
                  <button
                    onClick={e => handleDelete(name, e)}
                    disabled={deleting === name}
                    title="Delete workflow"
                    style={{
                      background: 'none', border: '1px solid #f8514933', borderRadius: 4,
                      color: '#f85149', cursor: 'pointer', fontSize: 11, padding: '2px 7px',
                      transition: 'background .15s, border-color .15s', opacity: deleting === name ? 0.4 : 1,
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background='#f8514922'; e.currentTarget.style.borderColor='#f85149aa' }}
                    onMouseLeave={e => { e.currentTarget.style.background='none'; e.currentTarget.style.borderColor='#f8514933' }}>
                    {deleting === name ? '…' : '✕'}
                  </button>
                </div>
              </div>
              {meta.desc
                ? <p className="text-xs text-[var(--text-2)] leading-relaxed mb-3">{meta.desc}</p>
                : <p className="text-xs text-[var(--text-3)] leading-relaxed mb-3 italic">Custom workflow</p>
              }
              {meta.tags && (
                <div className="flex gap-1.5 flex-wrap">
                  {meta.tags.map(t => (
                    <span key={t} className="text-[9px] font-bold uppercase tracking-wider
                      text-[var(--accent)] bg-[#58a6ff11] border border-[#58a6ff33]
                      rounded px-1.5 py-0.5">{t}</span>
                  ))}
                </div>
              )}
              <div className="mt-3 flex items-center gap-1.5 text-[10px] text-[var(--accent)] opacity-0 group-hover:opacity-100 transition-opacity">
                <span>◈ Open in editor</span>
                <span>→</span>
              </div>
            </Link>
          )
        })}

        {/* New workflow card */}
        <button
          onClick={() => setShowNew(true)}
          style={{
            background: 'none', border: '1px dashed #30363d', borderRadius: 8,
            padding: 24, cursor: 'pointer', textAlign: 'center',
            transition: 'border-color .15s, background .15s', minHeight: 120,
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', gap: 8,
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor='#58a6ff55'; e.currentTarget.style.background='#0a1929' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.background='none' }}>
          <span style={{ fontSize: 24, color: 'var(--border)' }}>+</span>
          <span style={{ fontSize: 11, color: 'var(--text-3)' }}>New Workflow</span>
        </button>

        {workflows.length === 0 && (
          <div className="card p-8 text-center">
            <p className="text-[var(--text-2)] text-sm">No workflow files found in /workflows/</p>
          </div>
        )}
      </div>

      {showNew && (
        <NewWorkflowModal onClose={() => setShowNew(false)} onCreated={handleCreated} />
      )}
    </div>
  )
}
