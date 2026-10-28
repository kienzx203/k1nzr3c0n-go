#!/usr/bin/env python3
# recon-graph.py — stitch a recon run's output into one attack-surface graph.
#
# Reads a workspace (full k1nzr3c0n pipeline) OR a dns-recon output dir and links
# every layer into nodes + edges:
#
#   subdomain --A--> ip --in_asn--> ASN
#           |            --in_subnet--> BGP-prefix / inferred /24
#           --CNAME--> provider (CDN / pivot domain)
#   ip --port--> service        host --vuln--> finding (by severity)
#   host enriched from httpx (alive/status/title/tech/cdn); origin IPs flagged;
#   internal (RFC1918) hosts/IPs flagged; interesting hosts flagged.
#
# Output: <out>.json (nodes/edges for the agent) + <out>.html (interactive,
#         self-contained vis-network graph with type/severity filters + detail panel).
#
# Usage:  recon-graph.py <workspace_dir> [-o out_prefix] [--target domain]
import sys, os, re, json, argparse, ipaddress

RE_IP4 = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
RE_HOST = re.compile(r'^[a-z0-9_.-]+\.[a-z]{2,}$')

def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip); return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False

def find(d, *names):
    for n in names:
        p = os.path.join(d, n)
        if os.path.isfile(p) and os.path.getsize(p) > 0: return p
    return None

def lines(path):
    if not path: return []
    with open(path, encoding='utf-8', errors='ignore') as f:
        return [ln.rstrip('\n') for ln in f if ln.strip()]

def tcols(path):   # TAB-only (fields may contain spaces)
    return [ln.split('\t') for ln in lines(path)]

def records(path):
    """Yield dicts from a JSONL file, or from a JSON array file."""
    if not path: return
    txt = open(path, encoding='utf-8', errors='ignore').read().strip()
    if not txt: return
    if txt[0] == '[':
        try:
            for o in json.loads(txt):
                if isinstance(o, dict): yield o
            return
        except Exception: pass
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln: continue
        try:
            o = json.loads(ln)
            if isinstance(o, dict): yield o
        except Exception: continue

def host_of(u):
    m = re.sub(r'^[a-z]+://', '', u or ''); return m.split('/')[0].split(':')[0].lower()

SEV = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('workspace'); ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--target', default=None)
    a = ap.parse_args()
    d = a.workspace
    if not os.path.isdir(d): sys.exit(f"not a directory: {d}")
    out = a.out or os.path.join(d, 'recon-graph')

    hosts = set(); host_ip = {}; host_cname = {}; host_ports = {}
    host_http = {}          # host -> {status,title,tech,server,url,cdn}
    ip_asn = {}; ip_org = {}; ip_prefix = {}; ip_rev = {}; ip_ptr = {}
    ip_ports = {}; origin_ips = set(); cdn_hosts = set()
    findings = []           # (host, name, sev, url)
    internal_hosts = set(); interesting = set(); subnets = []

    def add_ip(h, ip):
        if RE_IP4.fullmatch(ip): host_ip.setdefault(h, set()).add(ip); hosts.add(h)

    # ── host lists ──────────────────────────────────────────────────────────────
    for p in (find(d,'subdomains.txt'), find(d,'subdomains_resolved.txt'),
              find(d,'passive_merged.txt'), find(d,'p_dns_zone.txt'), find(d,'dns_zone_nsec.txt')):
        for h in lines(p):
            h = h.lower().strip('.')
            if RE_HOST.match(h): hosts.add(h)

    # ── resolved (dnsx -resp: "host [cname] [ip] [ip]") ──────────────────────────
    for c in (lines(find(d,'subdomains_resolved_resp.txt'))):
        parts = c.split()
        if not parts: continue
        h = parts[0].lower().strip('.')
        if not RE_HOST.match(h): continue
        hosts.add(h)
        brack = re.findall(r'\[([^\]]+)\]', c)
        for b in brack:
            if RE_IP4.fullmatch(b.strip()): add_ip(h, b.strip())
            elif RE_HOST.match(b.strip().lower().strip('.')):
                host_cname[h] = b.strip().lower().strip('.')
    for p in (find(d,'resolved.txt'), find(d,'dns_resolved.txt')):
        for col in (ln.split('\t') for ln in lines(p)):
            if len(col) >= 2: add_ip(col[0].lower(), col[1])
    for p in (find(d,'censys_ip.txt'), find(d,'fofa_ip_port.txt')):
        for col in (ln.split('\t') for ln in lines(p)):
            if len(col) >= 2:
                h = col[0].lower(); add_ip(h, col[1])
                if len(col) >= 3 and col[2].strip().isdigit():
                    host_ports.setdefault(h, set()).add(col[2].strip())
    for p in (find(d,'internal_hosts.txt'), find(d,'dns_internal_hosts.txt')):
        for col in (ln.split('\t') for ln in lines(p)):
            if col: internal_hosts.add(col[0].lower()); hosts.add(col[0].lower())
            if len(col) >= 2: add_ip(col[0].lower(), col[1])

    # ── httpx.json: alive hosts + IP + tech + CDN ────────────────────────────────
    for m in records(find(d,'httpx.json','httpx.jsonl')):
        h = (m.get('host') or host_of(m.get('url',''))).lower()
        if not h: continue
        hosts.add(h)
        arr = m.get('a') or []
        for ip in arr: add_ip(h, ip)
        tech = m.get('technologies') or m.get('tech') or []
        cdnn = m.get('cdn_name') or ('CDN' if m.get('cdn') else '')
        host_http[h] = {'status': m.get('status_code') or m.get('status-code'),
                        'title': (m.get('title') or '')[:80],
                        'tech': ', '.join(tech) if isinstance(tech, list) else str(tech),
                        'server': m.get('webserver') or '', 'url': m.get('url') or '', 'cdn': cdnn}
        if cdnn: cdn_hosts.add(h)

    # ── naabu.json: ip/host -> ports ─────────────────────────────────────────────
    for m in records(find(d,'naabu.json','naabu.jsonl','naabu_asn.json')):
        ip = m.get('ip') or ''; port = m.get('port')
        if RE_IP4.fullmatch(str(ip)) and port: ip_ports.setdefault(ip, set()).add(str(port))
        h = (m.get('host') or '').lower()
        if h and port and RE_HOST.match(h): host_ports.setdefault(h, set()).add(str(port))

    # ── nuclei*.json: vulns ──────────────────────────────────────────────────────
    for fn in ('nuclei.json','nuclei_results.json','nuclei_hosts.json','nuclei_misconfig.json','nuclei_ports.json','afrog.json'):
        for m in records(find(d, fn)):
            info = m.get('info') if isinstance(m.get('info'), dict) else {}
            name = (info.get('name') if info else '') or m.get('template-id') or m.get('template') or 'finding'
            sev = ((info.get('severity') if info else '') or m.get('severity') or 'info').lower()
            matched = m.get('matched-at') or m.get('matched_at') or m.get('host') or ''
            h = (m.get('host') or host_of(matched) or m.get('ip') or '').lower()
            if h: hosts.add(h) if RE_HOST.match(h) else None; findings.append((h, name, sev if sev in SEV else 'unknown', matched))

    # takeover findings (text)
    for ln in lines(find(d,'takeover_findings.txt')):
        h = host_of(ln) or (ln.split()[0].lower() if ln.split() else '')
        if h: findings.append((h, 'subdomain takeover', 'high', ln))

    # ── enrichment maps ──────────────────────────────────────────────────────────
    for c in tcols(find(d,'censys_hosts.txt')):
        if len(c) >= 4 and RE_IP4.fullmatch(c[0]):
            ip_asn[c[0]] = c[1].strip(); ip_org[c[0]] = c[2].strip(); ip_prefix[c[0]] = c[3].strip()
            if len(c) >= 6 and c[5].strip() not in ('', '-'): ip_rev[c[0]] = c[5].strip()
    for col in (ln.split('\t') for ln in lines(find(d,'ptr.txt') or find(d,'dns_ptr.txt'))):
        if len(col) >= 2 and RE_IP4.fullmatch(col[0]): ip_ptr[col[0]] = col[1]
    origin_ips = set(x for x in lines(find(d,'origin_ips.txt')) if RE_IP4.fullmatch(x))
    subnets = [c[0] for c in (ln.split() for ln in lines(find(d,'internal_subnets.txt') or find(d,'dns_internal_subnets.txt'))) if c and '/' in c[0]]
    interesting = set(h.lower().strip('.') for h in lines(find(d,'interesting.txt')))
    # cdncheck.json
    for m in records(find(d,'cdncheck.json')):
        h = (m.get('host') or m.get('input') or '').lower()
        if h and (m.get('cdn') or m.get('cdn_name')): cdn_hosts.add(h)

    target = a.target or (min((h for h in hosts if '.' in h), key=len) if hosts else None)

    # ── build graph ──────────────────────────────────────────────────────────────
    nodes = {}; edges = []; seen = set()
    def node(nid, label, group, title='', extra=None):
        if nid not in nodes:
            nd = {'id': nid, 'label': label, 'group': group, 'title': title or label}
            if extra: nd.update(extra)
            nodes[nid] = nd
    def edge(x, y, lb):
        k = (x, y, lb)
        if k not in seen and x in nodes and y in nodes: seen.add(k); edges.append({'from': x, 'to': y, 'label': lb})

    short = lambda h: (h[:-len('.'+target)] if target and h.endswith('.'+target) else h)
    if target: node('dom:'+target, target, 'domain')

    def subnet24(ip):
        try: return str(ipaddress.ip_network(ip+'/24', strict=False))
        except ValueError: return None

    for h in sorted(hosts):
        if not RE_HOST.match(h): continue
        internal = h in internal_hosts or any(is_internal(ip) for ip in host_ip.get(h, ()))
        hh = host_http.get(h, {})
        alive = bool(hh)
        grp = 'sub_int' if internal else ('vhost' if h in interesting else ('sub' if alive else 'sub_dead'))
        tip = h
        if hh:
            tip += f"\\n{hh.get('status','')} {hh.get('title','')}".rstrip()
            if hh.get('tech'):   tip += f"\\ntech: {hh['tech']}"
            if hh.get('server'): tip += f"\\nserver: {hh['server']}"
            if hh.get('cdn'):    tip += f"\\nCDN: {hh['cdn']}"
        if h in host_ports: tip += "\\nports: " + ','.join(sorted(host_ports[h], key=int))
        node('h:'+h, short(h), grp, tip, {'status': hh.get('status')})

    for h, ips in host_ip.items():
        for ip in ips:
            node('ip:'+ip, ip, 'ip_int' if is_internal(ip) else ('ip_origin' if ip in origin_ips else 'ip_pub'),
                 ip + (f"\\nPTR: {ip_ptr[ip]}" if ip in ip_ptr else '')
                    + (f"\\nrevDNS: {ip_rev[ip]}" if ip in ip_rev else '')
                    + (f"\\n{ip_asn[ip]} {ip_org.get(ip,'')}" if ip in ip_asn else '')
                    + (f"\\nports: {','.join(sorted(ip_ports[ip],key=int))}" if ip in ip_ports else ''))
            if 'h:'+h in nodes: edge('h:'+h, 'ip:'+ip, 'A')

    for h, c in host_cname.items():
        prov = c
        if target and (c.endswith('.'+target) or c == target):
            node('h:'+c, short(c), 'sub', c)  # internal CNAME to another in-scope host
            if 'h:'+h in nodes: edge('h:'+h, 'h:'+c, 'CNAME')
        else:
            node('prov:'+prov, prov, 'provider', 'CNAME target / provider: '+prov)
            if 'h:'+h in nodes: edge('h:'+h, 'prov:'+prov, 'CNAME')

    allips = {ip for ips in host_ip.values() for ip in ips} | set(ip_asn) | set(ip_ports)
    for ip in allips:
        if ip not in nodes.get('ip:'+ip, {}) and 'ip:'+ip not in nodes:
            node('ip:'+ip, ip, 'ip_int' if is_internal(ip) else 'ip_pub', ip)
        if ip in ip_asn:
            node('as:'+ip_asn[ip], ip_asn[ip]+' '+ip_org.get(ip,''), 'asn'); edge('ip:'+ip, 'as:'+ip_asn[ip], 'ASN')
        pfx = ip_prefix.get(ip)
        if not pfx or pfx == '?': pfx = subnet24(ip) if is_internal(ip) else None
        if pfx: node('net:'+pfx, pfx, 'subnet'); edge('ip:'+ip, 'net:'+pfx, 'in')
    for s in subnets: node('net:'+s, s, 'subnet')

    sev_count = {s: 0 for s in SEV}
    for (h, name, sev, url) in findings:
        sev_count[sev] = sev_count.get(sev, 0) + 1
        fid = 'v:'+sev+':'+name+':'+(h or url)
        node(fid, name, 'vuln_'+sev, f"[{sev.upper()}] {name}\\n{url}")
        if h and 'h:'+h in nodes: edge('h:'+h, fid, sev)
        elif ('ip:'+h) in nodes: edge('ip:'+h, fid, sev)

    stats = {'subdomains': len([n for n in nodes.values() if n['group'].startswith('sub') or n['group']=='vhost']),
             'alive': len(host_http), 'ips': len([n for n in nodes if n.startswith('ip:')]),
             'internal_hosts': len(internal_hosts),
             'asn': len({n for n in nodes if n.startswith('as:')}),
             'subnets': len({n for n in nodes if n.startswith('net:')}),
             'providers': len({n for n in nodes if n.startswith('prov:')}),
             'findings': len(findings), 'sev': sev_count,
             'nodes': len(nodes), 'edges': len(edges)}
    graph = {'target': target, 'stats': stats, 'nodes': list(nodes.values()), 'edges': edges}
    json.dump(graph, open(out+'.json','w',encoding='utf-8'), ensure_ascii=False)
    open(out+'.html','w',encoding='utf-8').write(html(graph))
    print(f"recon-graph: {stats['nodes']} nodes / {stats['edges']} edges — "
          f"{stats['subdomains']} subs ({stats['alive']} alive), {stats['ips']} IPs, "
          f"{stats['internal_hosts']} internal, {stats['asn']} ASN, {stats['subnets']} nets, "
          f"{stats['providers']} providers, {stats['findings']} findings")
    print(f"  -> {out}.html   {out}.json")

# node palette: group -> (fill, border)
PALETTE = {
 'domain':('#f0f6fc','#1f6feb'), 'sub':('#58a6ff','#1f6feb'),
 'sub_dead':('#3d4650','#30363d'), 'vhost':('#f0883e','#9e4a06'),
 'sub_int':('#f85149','#8e1519'), 'ip_pub':('#3fb950','#1a7f37'),
 'ip_int':('#da3633','#6e0b0b'), 'ip_origin':('#2ea043','#116329'),
 'asn':('#a371f7','#6639ba'), 'subnet':('#d29922','#9e6a03'),
 'provider':('#39c5cf','#1b7f86'),
 'vuln_critical':('#ff4d4f','#a61d24'), 'vuln_high':('#ff7a45','#ad4e00'),
 'vuln_medium':('#ffc53d','#ad8b00'), 'vuln_low':('#73d13d','#3f6600'),
 'vuln_info':('#8b949e','#484f58'), 'vuln_unknown':('#8b949e','#484f58'),
}
SEVW = {'critical': 8, 'high': 5, 'medium': 3, 'low': 1}

def cy_elements(g):
    # IP -> parent subnet: compound containment (replaces the 'in' edge → clusters)
    parent = {}
    for e in g['edges']:
        if e['label'] == 'in' and e['from'].startswith('ip:') and e['to'].startswith('net:'):
            parent[e['from']] = e['to']
    deg, risk = {}, {}
    for e in g['edges']:
        deg[e['from']] = deg.get(e['from'], 0) + 1
        deg[e['to']] = deg.get(e['to'], 0) + 1
        if e['label'] in SEVW:
            risk[e['from']] = risk.get(e['from'], 0) + SEVW[e['label']]
    els = []
    for n in g['nodes']:
        grp = n['group']; pal = PALETTE.get(grp, ('#8b949e', '#484f58'))
        bump = (2 if grp.startswith('vuln') else 0) + (3 if grp in ('ip_int', 'sub_int') else 0) \
             + (2 if grp in ('ip_origin', 'vhost') else 0)
        sz = min(64, 13 + bump * 2 + min(deg.get(n['id'], 1), 20) + risk.get(n['id'], 0))
        d = {'id': n['id'], 'label': n['label'], 'group': grp, 'title': n.get('title', ''),
             'col': pal[0], 'bd': pal[1], 'sz': sz, 'risk': risk.get(n['id'], 0),
             'internal': 1 if grp in ('ip_int', 'sub_int') else 0,
             'dead': 1 if grp == 'sub_dead' else 0,
             'cdn': 1 if grp == 'provider' else 0,
             'kind': ('vuln' if grp.startswith('vuln') else grp.split('_')[0])}
        if n['id'] in parent and parent[n['id']] != n['id']:
            d['parent'] = parent[n['id']]
        els.append({'data': d})
    for e in g['edges']:
        if e['label'] == 'in':
            continue
        sev = e['label'] if e['label'] in SEVW else ''
        els.append({'data': {'id': e['from'] + '>' + e['to'] + '>' + e['label'],
                             'source': e['from'], 'target': e['to'], 'label': e['label'], 'sev': sev}})
    return els

def html(g):
    data = json.dumps(cy_elements(g))
    pal = json.dumps(PALETTE)
    st = g['stats']; sv = st.get('sev', {}); tgt = g.get('target') or 'recon'
    stat = (f"{st['subdomains']} subs · {st['alive']} alive · {st['ips']} IPs · "
            f"{st['internal_hosts']} internal · {st['asn']} ASN · {st['subnets']} nets · "
            f"{st['providers']} cdn · {st['findings']} vulns")
    return (_TPL.replace('/*DATA*/0', data).replace('/*PAL*/0', pal)
            .replace('__TARGET__', tgt).replace('__STAT__', stat).replace('__N__', str(len(g['nodes']))))

_TPL = r"""<!doctype html><html><head><meta charset="utf-8"><title>Attack surface — __TARGET__</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
<style>
 :root{--bg:#0d1117;--fg:#c9d1d9;--mut:#8b949e;--bd:#30363d;--card:#161b22;--acc:#58a6ff}
 *{box-sizing:border-box} html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
   font:13px/1.45 system-ui,Segoe UI,Roboto,sans-serif;overflow:hidden}
 #bar{position:fixed;inset:0 0 auto 0;z-index:6;display:flex;gap:10px;align-items:center;flex-wrap:wrap;
   padding:7px 12px;background:var(--card);border-bottom:1px solid var(--bd)}
 #bar b{color:#f0f6fc} .stat{color:var(--mut);font-size:12px}
 input,button,select{background:#0d1117;border:1px solid var(--bd);color:var(--fg);border-radius:6px;
   padding:4px 8px;font-size:12px} button{cursor:pointer} button:hover{border-color:var(--acc)}
 button.on{background:#1f6feb33;border-color:var(--acc);color:#fff}
 #chips{display:flex;gap:5px;flex-wrap:wrap} .chip{display:inline-flex;align-items:center;gap:4px;
   font-size:11px;color:var(--mut);cursor:pointer;user-select:none;padding:2px 7px;border:1px solid var(--bd);
   border-radius:20px} .chip.off{opacity:.35;text-decoration:line-through} .chip i{width:9px;height:9px;border-radius:50%}
 #cy{position:fixed;inset:46px 0 0 0}
 #panel{position:fixed;top:54px;right:10px;width:310px;max-height:84vh;overflow:auto;background:var(--card);
   border:1px solid var(--bd);border-radius:10px;padding:13px 15px;display:none;z-index:7;white-space:pre-wrap;
   font-family:ui-monospace,monospace;font-size:11px;box-shadow:0 8px 30px #0008}
 #panel h3{margin:0 0 6px;color:#f0f6fc;font:600 13px system-ui} #panel .x{float:right;cursor:pointer;color:var(--mut)}
 #hint{position:fixed;bottom:10px;left:12px;color:#484f58;font-size:11px;z-index:5}
</style></head><body>
<div id="bar">
 <b>🎯 __TARGET__</b>
 <span class="stat">__STAT__</span>
 <input id="q" placeholder="search host / ip / asn…" style="width:180px">
 <select id="layout" title="layout">
   <option value="concentric">◎ tiers</option><option value="cose">✸ force</option>
   <option value="breadthfirst">⊟ layered</option><option value="grid">▦ grid</option>
 </select>
 <button id="signal" class="on" title="hide no-http + CDN noise">signal only</button>
 <button id="cluster" title="collapse subnets into one node">⊡ clusters</button>
 <button id="fit">⤢ fit</button>
 <span id="chips"></span>
</div>
<div id="cy"></div><div id="panel"></div>
<div id="hint">click = focus + attack-path · dbl-click bg = reset · drag = pan · scroll = zoom</div>
<script>
const ELES=/*DATA*/0, PAL=/*PAL*/0, N=__N__;
const LBL={domain:'domain',sub:'subdomain',sub_dead:'no-http',vhost:'interesting',sub_int:'internal host',
  ip_pub:'IP',ip_int:'internal IP',ip_origin:'origin IP',asn:'ASN',subnet:'subnet',provider:'CDN/CNAME',
  vuln_critical:'critical',vuln_high:'high',vuln_medium:'medium',vuln_low:'low',vuln_info:'info'};
const SEVCOL={critical:'#ff4d4f',high:'#ff7a45',medium:'#ffc53d',low:'#73d13d'};
const cy=cytoscape({
 container:document.getElementById('cy'), elements:ELES, wheelSensitivity:0.25,
 textureOnViewport:true, hideEdgesOnViewport:true, pixelRatio:1, motionBlur:false, maxZoom:4, minZoom:0.04,
 style:[
  {selector:'node',style:{'background-color':'data(col)','border-color':'data(bd)','border-width':2,
    'width':'data(sz)','height':'data(sz)','label':'data(label)','color':'#c9d1d9','font-size':9,
    'text-valign':'bottom','text-margin-y':2,'text-wrap':'ellipsis','text-max-width':90,
    'min-zoomed-font-size':12,'overlay-opacity':0}},
  {selector:'node[kind="vuln"]',style:{'shape':'triangle','color':'#fff','font-size':8}},
  {selector:'node[group="domain"]',style:{'shape':'round-diamond','font-size':13,'color':'#f0f6fc','text-valign':'center'}},
  {selector:'node[group="asn"]',style:{'shape':'hexagon'}},
  {selector:':parent',style:{'background-opacity':0.08,'background-color':'#d29922','border-color':'#9e6a03',
    'border-style':'dashed','border-width':1.5,'shape':'round-rectangle','label':'data(label)','color':'#d29922',
    'font-size':10,'text-valign':'top','text-margin-y':-2,'padding':'12px'}},
  {selector:'edge',style:{'width':0.7,'line-color':'#283039','target-arrow-color':'#283039',
    'target-arrow-shape':'triangle','arrow-scale':0.5,'curve-style':'bezier','opacity':0.7}},
  {selector:'edge[sev]',style:{'line-color':'#6e40c9','target-arrow-color':'#6e40c9'}},
  {selector:'edge[label="CNAME"]',style:{'line-style':'dashed','line-color':'#39c5cf'}},
  {selector:'.dim',style:{'opacity':0.07}},
  {selector:'.hl',style:{'opacity':1,'border-width':4}},
  {selector:'.path',style:{'line-color':'#58a6ff','target-arrow-color':'#58a6ff','width':3,'opacity':1,'z-index':99}},
  {selector:'.pathnode',style:{'border-color':'#58a6ff','border-width':4,'opacity':1}},
  {selector:'.hidden',style:{'display':'none'}}
 ],
 layout:layoutCfg('concentric')
});
function layoutCfg(name){
 if(name==='concentric') return {name:'concentric',concentric:n=>({domain:9,asn:7,subnet:6,ip_origin:5,ip_pub:5,
   ip_int:5,vhost:4,sub:3,sub_int:3,sub_dead:2})[n.data('group')]||1,
   levelWidth:()=>2,minNodeSpacing:28,animate:false,spacingFactor:1.1};
 if(name==='cose') return {name:'cose',animate:false,nodeRepulsion:9000,idealEdgeLength:70,nestingFactor:0.9,gravity:0.3,numIter:800};
 if(name==='breadthfirst') return {name:'breadthfirst',directed:true,spacingFactor:1.1,animate:false,
   roots:cy?cy.nodes('[group="domain"]'):undefined};
 return {name:'grid',animate:false};
}
// ── chips (per group present) ──
const present=[...new Set(ELES.filter(e=>e.data.group).map(e=>e.data.group))];
const order=Object.keys(LBL).filter(g=>present.includes(g));
const off=new Set();
document.getElementById('chips').innerHTML=order.map(g=>
 `<span class="chip" data-g="${g}"><i style="background:${(PAL[g]||['#888'])[0]}"></i>${LBL[g]||g}</span>`).join('');
document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{
 const g=c.dataset.g; c.classList.toggle('off');
 off.has(g)?off.delete(g):off.add(g); applyVis();
});
// ── signal filter (hide no-http + cdn by default) ──
let signal=true;
document.getElementById('signal').onclick=e=>{signal=!signal;e.target.classList.toggle('on',signal);applyVis();};
function applyVis(){
 cy.batch(()=>{
  cy.nodes().forEach(n=>{
   const g=n.data('group');
   const hide = off.has(g) || (signal && (g==='sub_dead'||g==='provider'));
   n.toggleClass('hidden',hide);
  });
 });
}
applyVis();
// ── clusters collapse/expand ──
let collapsed=false;
document.getElementById('cluster').onclick=e=>{
 collapsed=!collapsed; e.target.classList.toggle('on',collapsed);
 cy.batch(()=>{
  cy.nodes(':parent').forEach(p=>{
   const kids=p.children();
   kids.toggleClass('hidden',collapsed);
   p.data('label', collapsed? (p.data('label').split('  ')[0]+'  ('+kids.length+')') : p.data('label').split('  (')[0]);
   p.style('background-opacity', collapsed?0.25:0.08);
  });
 });
};
// ── search ──
let qT; const qEl=document.getElementById('q');
qEl.addEventListener('input',()=>{
 clearTimeout(qT);
 qT=setTimeout(()=>{                       // debounce so typing stays smooth on big graphs
  const q=qEl.value.toLowerCase().trim();
  if(!q){cy.batch(()=>cy.elements().removeClass('dim hl'));qEl.removeAttribute('title');return;}
  const hit=cy.nodes().filter(n=>(n.data('label')||'').toLowerCase().includes(q)||n.id().toLowerCase().includes(q));
  cy.batch(()=>{                            // dim all, keep matches + their context lit
   cy.elements().addClass('dim');
   hit.closedNeighborhood().removeClass('dim'); hit.addClass('hl');
  });
  qEl.title=hit.length+' match';
  if(hit.length&&hit.length<=8) cy.animate({fit:{eles:hit,padding:90}},{duration:250});
 },150);
});
// ── focus + attack-path on tap ──
const P=document.getElementById('panel');
function root(){return cy.nodes('[group="domain"]')[0]||cy.nodes('[group="ip_origin"]')[0]||cy.nodes('[group="ip_pub"]')[0];}
cy.on('tap','node',ev=>{
 const n=ev.target; const r=root();
 cy.batch(()=>{                             // one style pass → no interaction lag on big graphs
  cy.elements().removeClass('dim hl path pathnode').addClass('dim');
  n.closedNeighborhood().removeClass('dim'); n.addClass('hl');
  if(r&&r.id()!==n.id()){                   // attack-path: shortest path from exposed root → node
   const p=cy.elements().dijkstra({root:r,directed:false}).pathTo(n);
   if(p&&p.length){p.removeClass('dim').addClass('path'); p.nodes().addClass('pathnode');}
  }
 });
 // detail panel
 const links=n.connectedEdges().map(e=>{const o=e.source().id()===n.id()?e.target():e.source();return (e.data('label')||'')+' → '+o.data('label');});
 P.innerHTML='<span class="x" onclick="this.parentElement.style.display=\'none\'">✕</span>'+
   '<h3>'+n.data('label')+'</h3>'+(LBL[n.data('group')]||n.data('group'))+
   (n.data('risk')?'  · risk '+n.data('risk'):'')+'\n\n'+(n.data('title')||'').replace(/\\n/g,'\n')+
   '\n\n'+links.length+' links:\n'+links.slice(0,50).map(x=>'• '+x).join('\n');
 P.style.display='block';
});
cy.on('tap',ev=>{if(ev.target===cy){cy.elements().removeClass('dim hl path pathnode');P.style.display='none';}});
cy.on('dbltap',ev=>{if(ev.target===cy)cy.animate({fit:{padding:40}},{duration:300});});
// ── controls ──
document.getElementById('layout').onchange=e=>cy.layout(layoutCfg(e.target.value)).run();
document.getElementById('fit').onclick=()=>cy.animate({fit:{padding:40}},{duration:300});
cy.ready(()=>cy.fit(40));
</script></body></html>"""

if __name__ == '__main__':
    main()
