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
# light-theme palette (fill, border) — saturated for contrast on a white canvas
PALETTE = {
 'domain':('#0969da','#0a3069'), 'sub':('#54aeff','#0969da'),
 'sub_dead':('#afb8c1','#8c959f'), 'vhost':('#fb8500','#bc4c00'),
 'sub_int':('#cf222e','#a40e26'), 'ip_pub':('#1f883d','#116329'),
 'ip_int':('#e5484d','#a40e26'), 'ip_origin':('#2da44e','#116329'),
 'asn':('#8250df','#6639ba'), 'subnet':('#bf8700','#9a6700'),
 'provider':('#1b7c83','#0e5a5f'),
 'vuln_critical':('#cf222e','#82071e'), 'vuln_high':('#bc4c00','#8a3800'),
 'vuln_medium':('#bf8700','#9a6700'), 'vuln_low':('#1f883d','#116329'),
 'vuln_info':('#6e7781','#57606a'), 'vuln_unknown':('#6e7781','#57606a'),
}
SEVW = {'critical': 8, 'high': 5, 'medium': 3, 'low': 1}

HOST_GROUPS = ('sub', 'sub_dead', 'vhost', 'sub_int')

def cy_elements(g, budget=800):
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
    vuln_hosts = set(e['from'] for e in g['edges'] if e['label'] in SEVW)

    # NODE BUDGET: a flat graph of 10k+ hosts is unreadable (and un-renderable).
    # Keep all infra (ip/subnet/asn/vuln/domain/provider) + only the most
    # important hosts (vuln > internal > interesting > alive > high-degree);
    # roll the dropped no-http leaf hosts onto their IP as a "+N" badge.
    def score(n):
        gg = n['group']
        return ((100 if n['id'] in vuln_hosts else 0) + (60 if gg == 'sub_int' else 0)
                + (40 if gg == 'vhost' else 0) + (25 if gg == 'sub' else 0)
                + risk.get(n['id'], 0) * 50 + min(deg.get(n['id'], 0), 30))
    allhosts = [n for n in g['nodes'] if n['group'] in HOST_GROUPS]
    pruned = len(allhosts) > budget
    keep = set(n['id'] for n in g['nodes'] if n['group'] not in HOST_GROUPS)   # infra always
    if not pruned:
        keep |= set(n['id'] for n in allhosts)
        shown = len(allhosts)
    else:
        # drop the no-http noise entirely; keep only notable hosts (capped)
        notable = sorted((n for n in allhosts
                          if n['group'] in ('sub_int', 'vhost', 'sub') or n['id'] in vuln_hosts),
                         key=score, reverse=True)[:budget]
        keep |= set(n['id'] for n in notable)
        shown = len(notable)
    node_by_id = {n['id']: n for n in g['nodes']}
    extra, hidden = {}, {}
    for e in g['edges']:
        if e['label'] == 'A' and e['from'] not in keep and e['to'] in keep and e['to'].startswith('ip:'):
            extra[e['to']] = extra.get(e['to'], 0) + 1
            lst = hidden.setdefault(e['to'], [])          # for lazy reveal on click
            if len(lst) < 400:
                hn = node_by_id.get(e['from'])
                if hn:
                    hp = PALETTE.get(hn['group'], ('#afb8c1', '#8c959f'))
                    lst.append({'id': hn['id'], 'label': hn['label'], 'group': hn['group'],
                                'col': hp[0], 'bd': hp[1], 'sz': 11, 'title': hn.get('title', ''),
                                'kind': hn['group'].split('_')[0]})

    els = []
    for n in g['nodes']:
        if n['id'] not in keep:
            continue
        grp = n['group']; pal = PALETTE.get(grp, ('#8b949e', '#484f58'))
        label = n['label']
        if extra.get(n['id']):
            label = f"{label}  +{extra[n['id']]}"
        bump = (2 if grp.startswith('vuln') else 0) + (3 if grp in ('ip_int', 'sub_int') else 0) \
             + (2 if grp in ('ip_origin', 'vhost') else 0)
        sz = min(72, 13 + bump * 2 + min(deg.get(n['id'], 1), 24) + risk.get(n['id'], 0) + min(extra.get(n['id'], 0), 20))
        d = {'id': n['id'], 'label': label, 'group': grp, 'title': n.get('title', ''),
             'col': pal[0], 'bd': pal[1], 'sz': sz, 'risk': risk.get(n['id'], 0),
             'internal': 1 if grp in ('ip_int', 'sub_int') else 0,
             'dead': 1 if grp == 'sub_dead' else 0,
             'cdn': 1 if grp == 'provider' else 0,
             'kind': ('vuln' if grp.startswith('vuln') else grp.split('_')[0])}
        if n['id'] in parent and parent[n['id']] != n['id'] and parent[n['id']] in keep:
            d['parent'] = parent[n['id']]
        els.append({'data': d})
    for e in g['edges']:
        if e['label'] == 'in' or e['from'] not in keep or e['to'] not in keep:
            continue
        sev = e['label'] if e['label'] in SEVW else ''
        els.append({'data': {'id': e['from'] + '>' + e['to'] + '>' + e['label'],
                             'source': e['from'], 'target': e['to'], 'label': e['label'], 'sev': sev}})
    return els, (len(allhosts), shown, pruned), hidden

def html(g):
    els, meta, hidden = cy_elements(g)
    data = json.dumps(els)
    pal = json.dumps(PALETTE)
    hid = json.dumps(hidden)
    st = g['stats']; sv = st.get('sev', {}); tgt = g.get('target') or 'recon'
    n_hosts, n_shown, pruned = meta
    stat = (f"{st['subdomains']} subs · {st['alive']} alive · {st['ips']} IPs · "
            f"{st['internal_hosts']} internal · {st['asn']} ASN · {st['subnets']} nets · "
            f"{st['providers']} cdn · {st['findings']} vulns")
    if pruned:
        stat += f" · <b style='color:#f0883e'>top {n_shown} of {n_hosts} hosts shown</b>"
    return (_TPL.replace('/*DATA*/0', data).replace('/*PAL*/0', pal).replace('/*HID*/0', hid)
            .replace('__TARGET__', tgt).replace('__STAT__', stat).replace('__N__', str(len(els))))

_TPL = r"""<!doctype html><html><head><meta charset="utf-8"><title>Attack surface — __TARGET__</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
<script src="https://unpkg.com/layout-base@2.0.1/layout-base.js"></script>
<script src="https://unpkg.com/cose-base@2.2.0/cose-base.js"></script>
<script src="https://unpkg.com/cytoscape-fcose@2.2.0/cytoscape-fcose.js"></script>
<script src="https://unpkg.com/cytoscape-expand-collapse@4.1.1/cytoscape-expand-collapse.js"></script>
<style>
 :root{--bg:#ffffff;--fg:#1f2328;--mut:#656d76;--bd:#d0d7de;--card:#f6f8fa;--acc:#0969da;--row:#eef2f6}
 *{box-sizing:border-box} html,body{margin:0;height:100%;overflow:hidden;background:var(--bg);color:var(--fg);
   font:13px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
 #bar{position:fixed;inset:0 0 auto 0;z-index:6;display:flex;gap:9px;align-items:center;flex-wrap:wrap;
   padding:7px 12px;background:var(--card);border-bottom:1px solid var(--bd)}
 #bar b{color:#1f2328} .stat{color:var(--mut);font-size:12px}
 input,button,select{background:#fff;border:1px solid var(--bd);color:var(--fg);border-radius:6px;padding:4px 8px;font-size:12px}
 button:hover{background:#f3f4f6}
 button{cursor:pointer} button:hover{border-color:var(--acc)} button.on{background:#1f6feb33;border-color:var(--acc);color:#fff}
 #chips{display:flex;gap:5px;flex-wrap:wrap} .chip{display:inline-flex;align-items:center;gap:4px;font-size:11px;
   color:var(--mut);cursor:pointer;user-select:none;padding:2px 7px;border:1px solid var(--bd);border-radius:20px}
 .chip.off{opacity:.35;text-decoration:line-through} .chip i{width:9px;height:9px;border-radius:50%}
 #main{position:fixed;inset:46px 0 0 0;display:flex}
 #cy{flex:1;min-width:0;height:100%;background:#fbfcfd;background-image:radial-gradient(#e7ecf1 1px,transparent 1px);background-size:22px 22px}
 #side{width:340px;flex-shrink:0;border-left:1px solid var(--bd);background:var(--card);display:flex;flex-direction:column}
 #sidetabs{display:flex;border-bottom:1px solid var(--bd)}
 #sidetabs button{flex:1;border:0;border-radius:0;background:transparent;padding:7px;color:var(--mut)}
 #sidetabs button.on{color:#1f2328;box-shadow:inset 0 -2px 0 var(--acc)}
 #tablewrap{flex:1;overflow:auto} #detailwrap{flex:1;overflow:auto;padding:12px 14px;white-space:pre-wrap;
   font-family:ui-monospace,monospace;font-size:11px;display:none}
 table{width:100%;border-collapse:collapse;font-size:11px}
 th{position:sticky;top:0;background:var(--card);text-align:left;padding:6px 8px;color:var(--mut);cursor:pointer;
   border-bottom:1px solid var(--bd);white-space:nowrap;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.04em}
 th:hover{color:var(--fg)} td{padding:4px 8px;border-bottom:1px solid #eaeef2;font-family:ui-monospace,monospace}
 tr{cursor:pointer} tr:hover{background:#1f6feb14} tr.sel{background:#1f6feb2e}
 td .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
 .risk{color:#ff7a45;font-weight:700} #detailwrap h3{margin:0 0 6px;color:#1f2328;font:600 13px system-ui}
 #hint{position:fixed;bottom:8px;left:12px;color:#484f58;font-size:11px;z-index:5}
</style></head><body>
<div id="bar">
 <b>🎯 __TARGET__</b><span class="stat">__STAT__</span>
 <input id="q" placeholder="search…" style="width:160px">
 <select id="layout"><option value="fcose">✸ fcose</option><option value="concentric">◎ tiers</option>
   <option value="breadthfirst">⊟ layered</option><option value="cose">cose</option></select>
 <button id="expand">⊕ expand</button><button id="collapse" class="on">⊖ collapse</button>
 <button id="signal" class="on">signal</button><button id="fit">⤢ fit</button>
 <span id="chips"></span>
</div>
<div id="main">
 <div id="cy"></div>
 <div id="side">
   <div id="sidetabs"><button id="tabTable" class="on">Table</button><button id="tabDetail">Detail</button></div>
   <div id="tablewrap"><table id="tbl"><thead><tr>
     <th data-k="type">type</th><th data-k="label">name</th><th data-k="info">info</th><th data-k="risk">risk</th>
   </tr></thead><tbody id="tbody"></tbody></table></div>
   <div id="detailwrap"></div>
 </div>
</div>
<div id="hint">click = focus + attack-path · dbl-click subnet = expand · dbl-click IP(+N) = reveal hosts · click row = jump</div>
<script>
try{cytoscape.use(window.cytoscapeFcose);}catch(e){}
try{cytoscape.use(window.cytoscapeExpandCollapse);}catch(e){}
const ELES=/*DATA*/0, PAL=/*PAL*/0, HIDDEN=/*HID*/0, N=__N__;
const LBL={domain:'domain',sub:'subdomain',sub_dead:'no-http',vhost:'interesting',sub_int:'internal host',
  ip_pub:'IP',ip_int:'internal IP',ip_origin:'origin IP',asn:'ASN',subnet:'subnet',provider:'CDN/CNAME',
  vuln_critical:'critical',vuln_high:'high',vuln_medium:'medium',vuln_low:'low',vuln_info:'info'};
const cy=cytoscape({
 container:document.getElementById('cy'), elements:ELES, wheelSensitivity:0.25,
 textureOnViewport:true, hideEdgesOnViewport:true, pixelRatio:1, motionBlur:false, maxZoom:4, minZoom:0.04,
 style:[
  {selector:'node',style:{'background-color':'data(col)','border-color':'data(bd)','border-width':2,
    'width':'data(sz)','height':'data(sz)','label':'data(label)','color':'#24292f','font-size':9,'font-weight':500,
    'text-valign':'bottom','text-margin-y':2,'text-wrap':'ellipsis','text-max-width':90,
    'min-zoomed-font-size':11,'overlay-opacity':0}},
  {selector:'node[kind="vuln"]',style:{'shape':'triangle','color':'#fff','font-size':8}},
  {selector:'node[group="domain"]',style:{'shape':'round-diamond','font-size':13,'color':'#ffffff','text-valign':'center'}},
  {selector:'node[group="asn"]',style:{'shape':'hexagon'}},
  {selector:':parent',style:{'background-opacity':0.07,'background-color':'#d29922','border-color':'#9e6a03',
    'border-style':'dashed','border-width':1.5,'shape':'round-rectangle','label':'data(label)','color':'#d29922',
    'font-size':10,'text-valign':'top','text-margin-y':-3,'padding':'14px','min-zoomed-font-size':6}},
  {selector:'node.cy-expand-collapse-collapsed-node',style:{'background-opacity':0.22,'border-style':'solid',
    'shape':'round-rectangle','width':'label','height':28,'padding':'8px','font-size':11,'color':'#7a5a00'}},
  {selector:'edge',style:{'width':0.8,'line-color':'#c2cad3','target-arrow-color':'#c2cad3',
    'target-arrow-shape':'triangle','arrow-scale':0.5,'curve-style':'bezier','opacity':0.7}},
  {selector:'edge[sev]',style:{'line-color':'#6e40c9','target-arrow-color':'#6e40c9'}},
  {selector:'edge[label="CNAME"]',style:{'line-style':'dashed','line-color':'#39c5cf'}},
  {selector:'.dim',style:{'opacity':0.06}},
  {selector:'.hl',style:{'opacity':1,'border-width':4,'border-color':'#58a6ff'}},
  {selector:'.path',style:{'line-color':'#58a6ff','target-arrow-color':'#58a6ff','width':3,'opacity':1,'z-index':99}},
  {selector:'.pathnode',style:{'border-color':'#58a6ff','border-width':4,'opacity':1}},
  {selector:'.hidden',style:{'display':'none'}}
 ]
});
function layoutCfg(name){
 if(name==='fcose' && !window.cytoscapeFcose) name='concentric';
 if(name==='fcose') return {name:'fcose',quality:'default',animate:false,randomize:true,packComponents:true,
   nodeSeparation:80,idealEdgeLength:75,nodeRepulsion:6500,gravity:0.25,numIter:1500};
 if(name==='concentric') return {name:'concentric',animate:false,minNodeSpacing:30,spacingFactor:1.1,
   concentric:n=>({domain:9,asn:7,subnet:6,ip_origin:5,ip_pub:5,ip_int:5,vhost:4,sub:3,sub_int:3,sub_dead:2})[n.data('group')]||1,
   levelWidth:()=>2};
 if(name==='breadthfirst') return {name:'breadthfirst',directed:true,animate:false,spacingFactor:1.1,roots:cy.nodes('[group="domain"]')};
 return {name:'cose',animate:false,numIter:800};
}
// expand/collapse (compound subnets) — skeleton-first
let api=null;
try{ api=cy.expandCollapse({layoutBy:null,fisheye:false,animate:false,undoable:false,cueEnabled:true,
  expandCollapseCuePosition:'top-left',expandCollapseCueSize:11}); }catch(e){}
function relayout(){ cy.layout(layoutCfg(document.getElementById('layout').value)).run(); }
function runInit(){
 relayout();
 if(api){ try{api.collapseAll();}catch(e){} setTimeout(()=>{try{cy.fit(40);}catch(e){}},60); }
 else cy.fit(40);
}
cy.ready(runInit);
document.getElementById('layout').onchange=relayout;
document.getElementById('expand').onclick=()=>{if(api){api.expandAll();relayout();}};
document.getElementById('collapse').onclick=()=>{if(api){api.collapseAll();setTimeout(()=>cy.fit(40),60);}};
document.getElementById('fit').onclick=()=>cy.animate({fit:{padding:40}},{duration:250});
// filter chips + signal
const present=[...new Set(ELES.filter(e=>e.data.group).map(e=>e.data.group))];
const ORD=Object.keys(LBL).filter(g=>present.includes(g)); const off=new Set();
document.getElementById('chips').innerHTML=ORD.map(g=>`<span class="chip" data-g="${g}"><i style="background:${(PAL[g]||['#888'])[0]}"></i>${LBL[g]||g}</span>`).join('');
document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{const g=c.dataset.g;c.classList.toggle('off');off.has(g)?off.delete(g):off.add(g);applyVis();});
let signal=true;
document.getElementById('signal').onclick=e=>{signal=!signal;e.target.classList.toggle('on',signal);applyVis();};
function applyVis(){cy.batch(()=>cy.nodes().forEach(n=>{const g=n.data('group');
  n.toggleClass('hidden',off.has(g)||(signal&&g==='provider'));}));}
applyVis();
// ── coordinated TABLE ──
const tbody=document.getElementById('tbody'); let sortK='risk',sortDir=-1;
const rows=ELES.filter(e=>!e.data.source&&e.data.group&&e.data.group!=='subnet').map(e=>({
  id:e.data.id,type:LBL[e.data.group]||e.data.group,label:(e.data.label||'').split('  +')[0],
  info:(e.data.title||'').replace(/\\n/g,' ').slice(0,60),risk:e.data.risk||0,grp:e.data.group,col:e.data.col}));
function renderTable(filter){
 const f=(filter||'').toLowerCase();
 let r=rows.filter(x=>!f||x.label.toLowerCase().includes(f)||x.info.toLowerCase().includes(f));
 r.sort((a,b)=>{const A=a[sortK],B=b[sortK];return (A<B?-1:A>B?1:0)*sortDir;});
 tbody.innerHTML=r.slice(0,600).map(x=>`<tr data-id="${x.id}"><td><span class="dot" style="background:${x.col}"></span>${x.type}</td>`+
   `<td>${x.label}</td><td style="color:var(--mut)">${x.info||''}</td><td class="${x.risk?'risk':''}">${x.risk||''}</td></tr>`).join('');
 tbody.querySelectorAll('tr').forEach(tr=>tr.onclick=()=>{const id=tr.dataset.id;focusNode(cy.$id(id),true);
   tbody.querySelectorAll('tr').forEach(t=>t.classList.remove('sel'));tr.classList.add('sel');});
}
document.querySelectorAll('#tbl th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;
  if(sortK===k)sortDir*=-1;else{sortK=k;sortDir=(k==='risk'?-1:1);}renderTable(document.getElementById('q').value);});
renderTable('');
// side tabs
function sideTab(t){document.getElementById('tablewrap').style.display=t==='table'?'block':'none';
 document.getElementById('detailwrap').style.display=t==='detail'?'block':'none';
 document.getElementById('tabTable').classList.toggle('on',t==='table');
 document.getElementById('tabDetail').classList.toggle('on',t==='detail');}
document.getElementById('tabTable').onclick=()=>sideTab('table');
document.getElementById('tabDetail').onclick=()=>sideTab('detail');
// search (debounced) — graph + table
let qT;const qEl=document.getElementById('q');
qEl.addEventListener('input',()=>{clearTimeout(qT);qT=setTimeout(()=>{const q=qEl.value.toLowerCase().trim();
  renderTable(q);
  if(!q){cy.batch(()=>cy.elements().removeClass('dim hl'));return;}
  const hit=cy.nodes().filter(n=>(n.data('label')||'').toLowerCase().includes(q)||n.id().toLowerCase().includes(q));
  cy.batch(()=>{cy.elements().addClass('dim');hit.closedNeighborhood().removeClass('dim');hit.addClass('hl');});
  if(hit.length&&hit.length<=8)cy.animate({fit:{eles:hit,padding:90}},{duration:250});},150);});
// focus + attack-path + detail
const DET=document.getElementById('detailwrap');
function root(){return cy.nodes('[group="domain"]')[0]||cy.nodes('[group="ip_origin"]')[0]||cy.nodes('[group="ip_pub"]')[0];}
function focusNode(n,fit){
 if(!n||!n.length)return; const r=root();
 cy.batch(()=>{cy.elements().removeClass('dim hl path pathnode').addClass('dim');
  n.closedNeighborhood().removeClass('dim');n.addClass('hl');
  if(r&&r.id()!==n.id()){const p=cy.elements().dijkstra({root:r,directed:false}).pathTo(n);
   if(p&&p.length){p.removeClass('dim').addClass('path');p.nodes().addClass('pathnode');}}});
 const links=n.connectedEdges().map(e=>{const o=e.source().id()===n.id()?e.target():e.source();return (e.data('label')||'')+' → '+o.data('label');});
 DET.innerHTML='<h3>'+n.data('label')+'</h3>'+(LBL[n.data('group')]||n.data('group'))+(n.data('risk')?'  · risk '+n.data('risk'):'')+
   '\n\n'+(n.data('title')||'').replace(/\\n/g,'\n')+'\n\n'+links.length+' links:\n'+links.slice(0,60).map(x=>'• '+x).join('\n');
 sideTab('detail');
 if(fit)cy.animate({fit:{eles:n.closedNeighborhood(),padding:120},},{duration:300});
}
// progressive disclosure: dbl-click an IP with a "+N" badge → lazy-load its hidden hosts
function revealHidden(ip){
 const h=HIDDEN[ip.id()]; if(!h||!h.length||ip.data('revealed'))return;
 ip.data('revealed',1); const add=[];
 h.forEach(d=>{ if(cy.$id(d.id).nonempty())return;
   add.push({data:Object.assign({},d,{internal:(d.group||'').indexOf('int')>-1?1:0,dead:d.group==='sub_dead'?1:0,risk:0})});
   add.push({data:{id:'rev>'+d.id+'>'+ip.id(),source:d.id,target:ip.id(),label:'A'}}); });
 if(add.length){cy.add(add); ip.data('label',(ip.data('label')||'').split('  +')[0]);
   cy.layout({name:'fcose',animate:false,randomize:false,fit:false,nodeSeparation:60,numIter:600}).run();}
}
cy.on('dbltap','node[kind="ip"]',ev=>revealHidden(ev.target));
cy.on('tap','node',ev=>{if(!ev.target.hasClass('cy-expand-collapse-collapsed-node'))focusNode(ev.target,false);});
cy.on('tap',ev=>{if(ev.target===cy){cy.elements().removeClass('dim hl path pathnode');}});
</script></body></html>"""

if __name__ == '__main__':
    main()
