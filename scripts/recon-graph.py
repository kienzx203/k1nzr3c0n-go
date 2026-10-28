#!/usr/bin/env python3
# recon-graph.py — stitch recon output into an attack-surface graph.
#
# Reads the files a recon run leaves in a workspace / dns-recon output dir and
# links them into nodes + edges:
#
#   subdomain --A--> ip --in_asn--> ASN
#                       --in_subnet--> /24 or BGP-prefix
#                    (internal IPs flagged; interesting hosts flagged)
#   ip <--PTR-- reverse-dns name        host --port--> services (as tooltip)
#
# Inputs (any that exist, several name variants accepted):
#   subdomains.txt / p_dns_zone.txt / passive_merged.txt   (host list)
#   resolved.txt / dns_resolved.txt                        (host<TAB>ip)
#   censys_ip.txt / fofa_ip_port.txt                       (host<TAB>ip<TAB>port)
#   internal_hosts.txt / dns_internal_hosts.txt            (host<TAB>internal-ip)
#   internal_subnets.txt / dns_internal_subnets.txt        (cidr ...)
#   censys_hosts.txt                                       (ip ASN org prefix country revdns)
#   ptr.txt / dns_ptr.txt                                  (ip<TAB>ptr)
#   interesting.txt                                        (host list)
#
# Output: <out>.json (nodes/edges) + <out>.html (interactive vis-network graph).
#
# Usage:  recon-graph.py <workspace_dir> [-o out_prefix] [--target domain] [--open]
import sys, os, re, json, argparse, ipaddress

RE_IP4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False

def find(d, *names):
    for n in names:
        p = os.path.join(d, n)
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            return p
    return None

def lines(path):
    if not path: return []
    with open(path, encoding='utf-8', errors='ignore') as f:
        return [ln.rstrip('\n') for ln in f if ln.strip()]

def cols(path):
    return [re.split(r'[\t ]+', ln.strip()) for ln in lines(path)]

def tcols(path):   # TAB-only (fields may contain spaces, e.g. ASN org name)
    return [ln.split('\t') for ln in lines(path)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('workspace')
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--target', default=None)
    args = ap.parse_args()
    d = args.workspace
    if not os.path.isdir(d): sys.exit(f"not a directory: {d}")
    out = args.out or os.path.join(d, 'recon-graph')

    # ── gather ────────────────────────────────────────────────────────────────
    hosts = set()
    for p in (find(d,'subdomains.txt'), find(d,'p_dns_zone.txt'),
              find(d,'passive_merged.txt'), find(d,'dns_zone_nsec.txt')):
        for h in lines(p): hosts.add(h.lower().strip('.'))

    host_ip = {}        # host -> set(ip)
    for p in (find(d,'resolved.txt'), find(d,'dns_resolved.txt')):
        for c in cols(p):
            if len(c) >= 2 and RE_IP4.match(c[1]):
                host_ip.setdefault(c[0].lower(), set()).add(c[1]); hosts.add(c[0].lower())
    host_ports = {}     # host -> set(port)
    for p in (find(d,'censys_ip.txt'), find(d,'fofa_ip_port.txt')):
        for c in cols(p):
            if len(c) >= 2 and RE_IP4.match(c[1]):
                host_ip.setdefault(c[0].lower(), set()).add(c[1]); hosts.add(c[0].lower())
                if len(c) >= 3 and c[2].isdigit(): host_ports.setdefault(c[0].lower(), set()).add(c[2])

    internal_hosts = set()
    for p in (find(d,'internal_hosts.txt'), find(d,'dns_internal_hosts.txt')):
        for c in cols(p):
            if c: internal_hosts.add(c[0].lower()); hosts.add(c[0].lower())
            if len(c) >= 2 and RE_IP4.match(c[1]):
                host_ip.setdefault(c[0].lower(), set()).add(c[1])

    subnets = [c[0] for c in cols(find(d,'internal_subnets.txt') or find(d,'dns_internal_subnets.txt')) if c and '/' in c[0]]
    interesting = set(h.lower().strip('.') for h in lines(find(d,'interesting.txt')))

    ip_asn, ip_prefix, ip_org, ip_rev = {}, {}, {}, {}
    for c in tcols(find(d,'censys_hosts.txt')):
        if len(c) >= 4 and RE_IP4.match(c[0]):
            ip_asn[c[0]] = c[1]; ip_org[c[0]] = c[2].strip(); ip_prefix[c[0]] = c[3].strip()
            if len(c) >= 6 and c[5].strip() not in ('', '-'): ip_rev[c[0]] = c[5].strip()

    ip_ptr = {}
    for c in cols(find(d,'ptr.txt') or find(d,'dns_ptr.txt')):
        if len(c) >= 2 and RE_IP4.match(c[0]): ip_ptr[c[0]] = c[1]

    target = args.target
    if not target and hosts:
        target = min((h for h in hosts if '.' in h), key=len, default=None)

    # ── build nodes/edges ───────────────────────────────────────────────────────
    nodes, edges, seen_e = {}, [], set()
    def node(nid, label, group, title=''):
        if nid not in nodes: nodes[nid] = {'id': nid, 'label': label, 'group': group, 'title': title or label}
    def edge(a, b, label):
        k = (a, b, label)
        if k not in seen_e: seen_e.add(k); edges.append({'from': a, 'to': b, 'label': label})

    if target: node('dom:'+target, target, 'domain')

    def subnet_of(ip):
        try: return str(ipaddress.ip_network(ip + '/24', strict=False))
        except ValueError: return None

    all_ips = set()
    for ipset in host_ip.values(): all_ips |= ipset

    for h in sorted(hosts):
        internal = h in internal_hosts or any(is_internal(ip) for ip in host_ip.get(h, ()))
        grp = 'sub_int' if internal else ('sub_hot' if h in interesting else 'sub')
        t = h + (('\\nports: ' + ','.join(sorted(host_ports[h], key=int))) if h in host_ports else '')
        node('h:'+h, h.replace('.'+target, '') if target and h.endswith('.'+target) else h, grp, t)

    for h, ips in host_ip.items():
        for ip in ips:
            internal = is_internal(ip)
            title = ip + (('\\nPTR: '+ip_ptr[ip]) if ip in ip_ptr else '') + \
                    (('\\nrevDNS: '+ip_rev[ip]) if ip in ip_rev else '') + \
                    (('\\n'+ip_asn[ip]+' '+ip_org.get(ip,'')) if ip in ip_asn else '')
            node('ip:'+ip, ip, 'ip_int' if internal else 'ip_pub', title)
            edge('h:'+h, 'ip:'+ip, 'A')

    for ip in all_ips:
        if ip in ip_asn:
            node('as:'+ip_asn[ip], ip_asn[ip]+' '+ip_org.get(ip,''), 'asn'); edge('ip:'+ip, 'as:'+ip_asn[ip], 'ASN')
        pfx = ip_prefix.get(ip)
        if not pfx or pfx == '?':
            pfx = subnet_of(ip) if is_internal(ip) else None
        if pfx:
            node('net:'+pfx, pfx, 'subnet'); edge('ip:'+ip, 'net:'+pfx, 'in')
    for s in subnets:
        node('net:'+s, s, 'subnet')

    stats = {'subdomains': len(hosts), 'ips': len(all_ips),
             'internal_hosts': len(internal_hosts),
             'asn': len({v for v in ip_asn.values()}),
             'subnets': len({n for n in nodes if n.startswith('net:')}),
             'nodes': len(nodes), 'edges': len(edges)}
    graph = {'target': target, 'stats': stats,
             'nodes': list(nodes.values()), 'edges': edges}
    with open(out + '.json', 'w', encoding='utf-8') as f:
        json.dump(graph, f, ensure_ascii=False, indent=0)
    with open(out + '.html', 'w', encoding='utf-8') as f:
        f.write(html(graph))
    print(f"recon-graph: {stats['nodes']} nodes / {stats['edges']} edges "
          f"({stats['subdomains']} subs, {stats['ips']} IPs, {stats['internal_hosts']} internal, "
          f"{stats['asn']} ASN, {stats['subnets']} subnets)")
    print(f"  -> {out}.html   {out}.json")

GROUPS = {
    'domain': ('#f0f6fc', '#1f6feb', 26),
    'sub':    ('#58a6ff', '#1f6feb', 12),
    'sub_hot':('#f0883e', '#9e4a06', 14),
    'sub_int':('#f85149', '#8e1519', 14),
    'ip_pub': ('#3fb950', '#1a7f37', 14),
    'ip_int': ('#da3633', '#6e0b0b', 16),
    'asn':    ('#a371f7', '#6639ba', 18),
    'subnet': ('#d29922', '#9e6a03', 16),
}

def html(graph):
    legend = ''.join(
        f'<span class="lg"><i style="background:{c[0]}"></i>{name}</span>'
        for name, c in GROUPS.items())
    groups_js = json.dumps({g: {'color': {'background': c[0], 'border': c[1]},
                                'font': {'color': '#0d1117' if g in ('domain','sub','ip_pub') else '#fff',
                                         'size': 12}, 'size': c[2]}
                            for g, c in GROUPS.items()})
    data = json.dumps({'nodes': graph['nodes'], 'edges': graph['edges']})
    st = graph['stats']; tgt = graph.get('target') or 'recon'
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Recon graph — {tgt}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
 :root{{--bg:#0d1117;--fg:#c9d1d9;--mut:#8b949e;--bd:#30363d}}
 *{{box-sizing:border-box}} html,body{{margin:0;height:100%;background:var(--bg);color:var(--fg);
   font:13px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
 #bar{{position:fixed;top:0;left:0;right:0;z-index:5;display:flex;gap:14px;align-items:center;
   flex-wrap:wrap;padding:8px 14px;background:#161b22;border-bottom:1px solid var(--bd)}}
 #bar b{{color:#f0f6fc}} .st{{color:var(--mut)}} .st b{{color:#58a6ff}}
 #q{{background:#0d1117;border:1px solid var(--bd);color:var(--fg);border-radius:6px;padding:5px 9px;width:200px}}
 .lg{{display:inline-flex;align-items:center;gap:5px;color:var(--mut);font-size:11px}}
 .lg i{{width:11px;height:11px;border-radius:50%;display:inline-block}}
 #net{{position:fixed;top:0;left:0;right:0;bottom:0;padding-top:46px}}
</style></head><body>
<div id="bar">
 <b>🕸 {tgt}</b>
 <span class="st"><b>{st['subdomains']}</b> subs · <b>{st['ips']}</b> IPs ·
   <b>{st['internal_hosts']}</b> internal · <b>{st['asn']}</b> ASN · <b>{st['subnets']}</b> nets</span>
 <input id="q" placeholder="search host / ip / asn…">
 <span id="legend">{legend}</span>
</div>
<div id="net"></div>
<script>
const G={data}, GROUPS={groups_js};
const nodes=new vis.DataSet(G.nodes), edges=new vis.DataSet(G.edges);
const net=new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
  groups:GROUPS,
  nodes:{{shape:'dot',borderWidth:2}},
  edges:{{color:{{color:'#30363d',highlight:'#58a6ff'}},width:0.6,
          font:{{color:'#6e7681',size:9,strokeWidth:0}},smooth:{{type:'continuous'}},
          arrows:{{to:{{enabled:true,scaleFactor:0.4}}}}}},
  physics:{{solver:'forceAtlas2Based',stabilization:{{iterations:220}},
           forceAtlas2Based:{{gravitationalConstant:-45,springLength:90,avoidOverlap:0.4}}}},
  interaction:{{hover:true,tooltipDelay:120,navigationButtons:true,keyboard:true}}
}});
// search → highlight + focus
document.getElementById('q').addEventListener('input',e=>{{
  const q=e.target.value.toLowerCase().trim();
  const hit=q? G.nodes.filter(n=>n.label.toLowerCase().includes(q)||n.id.toLowerCase().includes(q)):[];
  nodes.update(G.nodes.map(n=>({{id:n.id,opacity:(!q||hit.find(h=>h.id===n.id))?1:0.12}})));
  if(hit.length){{net.selectNodes(hit.map(h=>h.id)); if(hit.length<=5) net.focus(hit[0].id,{{scale:1.1,animation:true}});}}
}});
net.on('doubleClick',p=>{{ if(p.nodes[0]) net.focus(p.nodes[0],{{scale:1.4,animation:true}}); }});
</script></body></html>"""

if __name__ == '__main__':
    main()
