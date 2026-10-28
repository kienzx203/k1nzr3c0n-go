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

# node group -> (fill, border, size)
GROUPS = {
 'domain':  ('#f0f6fc','#1f6feb',28), 'sub':('#58a6ff','#1f6feb',12),
 'sub_dead':('#3d4650','#30363d',8),  'vhost':('#f0883e','#9e4a06',14),
 'sub_int': ('#f85149','#8e1519',14), 'ip_pub':('#3fb950','#1a7f37',14),
 'ip_int':  ('#da3633','#6e0b0b',16), 'ip_origin':('#2ea043','#116329',18),
 'asn':     ('#a371f7','#6639ba',20), 'subnet':('#d29922','#9e6a03',16),
 'provider':('#39c5cf','#1b7f86',14),
 'vuln_critical':('#ff4d4f','#a61d24',20),'vuln_high':('#ff7a45','#ad4e00',18),
 'vuln_medium':('#ffc53d','#ad8b00',16),'vuln_low':('#73d13d','#3f6600',14),
 'vuln_info':('#8b949e','#484f58',12),'vuln_unknown':('#8b949e','#484f58',12),
}
LEGEND = [('domain','domain'),('sub','subdomain'),('sub_dead','no-http'),('vhost','interesting'),
          ('sub_int','internal host'),('ip_pub','IP'),('ip_int','internal IP'),('ip_origin','origin IP'),
          ('asn','ASN'),('subnet','subnet'),('provider','CDN/CNAME'),('vuln_high','vuln')]

def html(g):
    legend = ''.join(f'<label class="lg"><input type="checkbox" checked data-g="{k}"><i style="background:{GROUPS[k][0]}"></i>{lbl}</label>' for k,lbl in LEGEND)
    groups_js = json.dumps({k:{'color':{'background':v[0],'border':v[1]},
        'font':{'color':'#0d1117' if k in('domain','sub','ip_pub','ip_origin','subnet','vuln_medium','vuln_low') else '#fff','size':12},
        'size':v[2]} for k,v in GROUPS.items()})
    data = json.dumps({'nodes':g['nodes'],'edges':g['edges']})
    st=g['stats']; tgt=g.get('target') or 'recon'; sv=st['sev']
    sevbar=' · '.join(f"<b style='color:{GROUPS['vuln_'+s][0]}'>{sv.get(s,0)}</b> {s}" for s in ['critical','high','medium','low'] if sv.get(s,0))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Recon graph — {tgt}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
 :root{{--bg:#0d1117;--fg:#c9d1d9;--mut:#8b949e;--bd:#30363d;--card:#161b22}}
 *{{box-sizing:border-box}} html,body{{margin:0;height:100%;background:var(--bg);color:var(--fg);font:13px/1.5 system-ui,Segoe UI,Roboto,sans-serif}}
 #bar{{position:fixed;top:0;left:0;right:0;z-index:6;display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:8px 14px;background:var(--card);border-bottom:1px solid var(--bd)}}
 #bar b{{color:#f0f6fc}} .st{{color:var(--mut)}} .st b{{color:#58a6ff}}
 #q{{background:#0d1117;border:1px solid var(--bd);color:var(--fg);border-radius:6px;padding:5px 9px;width:190px}}
 .lg{{display:inline-flex;align-items:center;gap:4px;color:var(--mut);font-size:11px;cursor:pointer;user-select:none}}
 .lg i{{width:10px;height:10px;border-radius:50%;display:inline-block}} .lg input{{margin:0}}
 #net{{position:fixed;inset:50px 0 0 0}}
 #panel{{position:fixed;top:58px;right:10px;width:300px;max-height:80vh;overflow:auto;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px 14px;display:none;z-index:7;white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:11px}}
 #panel b{{color:#58a6ff}} #panel .x{{float:right;cursor:pointer;color:var(--mut)}}
</style></head><body>
<div id="bar">
 <b>🕸 {tgt}</b>
 <span class="st"><b>{st['subdomains']}</b> subs (<b>{st['alive']}</b> alive) · <b>{st['ips']}</b> IPs · <b>{st['internal_hosts']}</b> internal · <b>{st['asn']}</b> ASN · <b>{st['subnets']}</b> nets · <b>{st['providers']}</b> cdn · <b>{st['findings']}</b> vulns{(' · '+sevbar) if sevbar else ''}</span>
 <input id="q" placeholder="search…">
 <span id="legend">{legend}</span>
</div>
<div id="net"></div><div id="panel"></div>
<script>
const G={data}, GROUPS={groups_js};
const nodes=new vis.DataSet(G.nodes), edges=new vis.DataSet(G.edges);
const net=new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
 groups:GROUPS, nodes:{{shape:'dot',borderWidth:2}},
 edges:{{color:{{color:'#283039',highlight:'#58a6ff',hover:'#484f58'}},width:0.5,font:{{color:'#6e7681',size:9,strokeWidth:0}},smooth:{{type:'continuous',roundness:0.4}},arrows:{{to:{{enabled:true,scaleFactor:0.35}}}}}},
 physics:{{solver:'forceAtlas2Based',stabilization:{{iterations:250}},forceAtlas2Based:{{gravitationalConstant:-42,springLength:95,avoidOverlap:0.5}}}},
 interaction:{{hover:true,tooltipDelay:120,navigationButtons:true,keyboard:true,multiselect:true}}
}});
// type filter via legend checkboxes
const hidden=new Set();
document.querySelectorAll('.lg input').forEach(cb=>cb.addEventListener('change',()=>{{
 cb.checked?hidden.delete(cb.dataset.g):hidden.add(cb.dataset.g);
 nodes.update(G.nodes.map(n=>({{id:n.id,hidden:hidden.has(n.group)}})));
}}));
// search
document.getElementById('q').addEventListener('input',e=>{{
 const q=e.target.value.toLowerCase().trim();
 const hit=q?G.nodes.filter(n=>n.label.toLowerCase().includes(q)||n.id.toLowerCase().includes(q)):[];
 nodes.update(G.nodes.map(n=>({{id:n.id,opacity:(!q||hit.find(h=>h.id===n.id))?1:0.12}})));
 if(hit.length){{net.selectNodes(hit.map(h=>h.id));if(hit.length<=6)net.focus(hit[0].id,{{scale:1.1,animation:true}});}}
}});
// detail panel on click
const P=document.getElementById('panel');
net.on('click',p=>{{
 if(!p.nodes.length){{P.style.display='none';return;}}
 const n=nodes.get(p.nodes[0]);
 const nb=net.getConnectedNodes(n.id).map(id=>nodes.get(id)).filter(Boolean);
 P.innerHTML='<span class="x" onclick="this.parentElement.style.display=\\'none\\'">✕</span><b>'+n.label+'</b>\\n'+
   (n.title||'').replace(/\\\\n/g,'\\n')+'\\n\\n<b>'+nb.length+' links:</b>\\n'+nb.slice(0,40).map(x=>'• '+x.label).join('\\n');
 P.style.display='block';
}});
net.on('doubleClick',p=>{{if(p.nodes[0])net.focus(p.nodes[0],{{scale:1.5,animation:true}});}});
</script></body></html>"""

if __name__ == '__main__':
    main()
