package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/graph"
	"github.com/Autumn-27/artex/k1z/store"
)

// graph2 = the Go-native graph engine (BloodHound-style): the server holds the
// whole attack-surface graph per target and the UI pulls subgraphs on demand
// (overview / neighbors / path / search), instead of shipping one giant HTML.

type cachedGraph struct {
	g       *graph.Graph
	builtAt time.Time
}

var (
	graph2Mu    sync.Mutex
	graph2Cache = map[string]*cachedGraph{}
	errNoRuns   = errors.New("no run workspace found for this target")
)

// targetGraph builds (or returns a cached) graph for a target by unioning every
// run's workspace. Rebuilt only when a newer run exists or the generator changed.
func (s *Server) targetGraph(target string) (*graph.Graph, int, error) {
	if target == "" {
		return nil, 400, errors.New("target required")
	}
	runs, _, err := s.St.ListRuns(store.RunFilter{Limit: 200})
	if err != nil {
		return nil, 500, err
	}
	var wss []string
	var newest time.Time
	for _, run := range runs {
		if run.Target != target || run.Workspace == "" || !dirExists(run.Workspace) {
			continue
		}
		wss = append(wss, run.Workspace)
		for _, t := range []time.Time{run.FinishedAt, run.StartedAt, run.CreatedAt} {
			if t.After(newest) {
				newest = t
			}
		}
	}
	if len(wss) == 0 {
		return nil, 404, errNoRuns
	}
	graph2Mu.Lock()
	defer graph2Mu.Unlock()
	if c, ok := graph2Cache[target]; ok && !newest.After(c.builtAt) {
		return c.g, 200, nil
	}
	merged := filepath.Join(config.BaseDir(), "targetgraphs", safeTargetDir(target))
	os.MkdirAll(merged, 0o755)
	for _, f := range graphMergeFiles {
		var buf []byte
		for _, ws := range wss {
			if b, e := os.ReadFile(filepath.Join(ws, f)); e == nil && len(b) > 0 {
				buf = append(buf, b...)
				if b[len(b)-1] != '\n' {
					buf = append(buf, '\n')
				}
			}
		}
		_ = os.WriteFile(filepath.Join(merged, f), buf, 0o644)
	}
	g := graph.Build(merged, target)
	graph2Cache[target] = &cachedGraph{g: g, builtAt: time.Now()}
	return g, 200, nil
}

func (s *Server) graphFor(w http.ResponseWriter, r *http.Request) *graph.Graph {
	g, code, err := s.targetGraph(r.PathValue("name"))
	if err != nil {
		writeDetail(w, code, err.Error())
		return nil
	}
	return g
}

func (s *Server) handleGraph2Overview(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Overview(atoiDefault(r.URL.Query().Get("hostCap"), 150)))
	}
}

func (s *Server) handleGraph2Neighbors(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Neighbors(r.URL.Query().Get("id")))
	}
}

func (s *Server) handleGraph2Path(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Path(r.URL.Query().Get("from"), r.URL.Query().Get("to")))
	}
}

func (s *Server) handleGraph2Search(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, map[string]any{"nodes": g.Search(r.URL.Query().Get("q"), atoiDefault(r.URL.Query().Get("limit"), 50))})
	}
}

func (s *Server) handleGraph2Stats(w http.ResponseWriter, r *http.Request) {
	if g := s.graphFor(w, r); g != nil {
		writeJSON(w, 200, g.Stats())
	}
}

// handleGraph2View serves the WebGL (Sigma.js) client shell — a tiny HTML page
// that pulls subgraphs from the graph2 API (no embedded data), so it stays fast
// regardless of how large the target's graph is.
func (s *Server) handleGraph2View(w http.ResponseWriter, r *http.Request) {
	tj, _ := json.Marshal(r.PathValue("name"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(strings.Replace(graph2Shell, `"__TARGET__"`, string(tj), 1)))
}

const graph2Shell = `<!doctype html><html><head><meta charset="utf-8">
<title>Attack surface</title><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/graphology/0.25.4/graphology.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/sigma.js/2.4.0/sigma.min.js"></script>
<style>
 :root{--bg:#fff;--fg:#1f2328;--mut:#656d76;--bd:#d0d7de;--card:#f6f8fa;--acc:#0969da}
 *{box-sizing:border-box}html,body{margin:0;height:100%;overflow:hidden;background:var(--bg);color:var(--fg);
   font:13px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
 #bar{position:fixed;inset:0 0 auto 0;z-index:5;display:flex;gap:9px;align-items:center;flex-wrap:wrap;
   padding:8px 12px;background:var(--card);border-bottom:1px solid var(--bd)}
 #bar b{color:#0a3069} .stat{color:var(--mut);font-size:12px}
 input,button{background:#fff;border:1px solid var(--bd);color:var(--fg);border-radius:6px;padding:5px 9px;font-size:12px}
 button{cursor:pointer}button:hover{background:#f3f4f6}
 #main{position:fixed;inset:48px 0 0 0;display:flex}
 #cy{flex:1;min-width:0;height:100%;background:#fbfcfd;background-image:radial-gradient(#e7ecf1 1px,transparent 1px);background-size:22px 22px}
 #side{width:330px;flex-shrink:0;border-left:1px solid var(--bd);background:var(--card);overflow:auto;padding:12px 14px;
   white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:11px}
 #side h3{margin:0 0 6px;color:#0a3069;font:600 13px system-ui}
 .lg{display:inline-flex;align-items:center;gap:4px;color:var(--mut);font-size:11px}
 .lg i{width:9px;height:9px;border-radius:50%}
 #hint{position:fixed;bottom:8px;left:12px;color:#8c959f;font-size:11px;z-index:5}
</style></head><body>
<div id="bar">
 <b>🎯 <span id="tgt"></span></b><span class="stat" id="stat">loading…</span>
 <input id="q" placeholder="search host / ip / asn…" style="width:200px">
 <button id="fit">⤢ fit</button><button id="reload">↻</button>
 <span class="lg"><i style="background:#cf222e"></i>internal</span>
 <span class="lg"><i style="background:#1f883d"></i>IP</span>
 <span class="lg"><i style="background:#8250df"></i>ASN</span>
 <span class="lg"><i style="background:#bf8700"></i>subnet</span>
 <span class="lg"><i style="background:#fb8500"></i>interesting</span>
</div>
<div id="main"><div id="cy"></div><div id="side">click a node to expand + see details</div></div>
<div id="hint">click node = expand (fetch neighbors) + detail · drag = pan · scroll = zoom</div>
<script>
const TARGET="__TARGET__";
const BASE="/api/v1/targets/"+encodeURIComponent(TARGET)+"/graph2";
document.getElementById('tgt').textContent=TARGET;
const GraphCtor=(window.graphology&&(window.graphology.Graph||window.graphology))||window.Graph;
const g=new GraphCtor();
const COL={domain:'#0969da',sub:'#54aeff',sub_dead:'#afb8c1',vhost:'#fb8500',sub_int:'#cf222e',
 ip_pub:'#1f883d',ip_int:'#e5484d',ip_origin:'#2da44e',asn:'#8250df',subnet:'#bf8700',provider:'#1b7c83',
 vuln_critical:'#cf222e',vuln_high:'#bc4c00',vuln_medium:'#bf8700',vuln_low:'#1f883d',vuln_info:'#6e7781'};
const TIER={domain:0,asn:1,subnet:1,ip_pub:2,ip_int:2,ip_origin:2,provider:2,vhost:3,sub:3,sub_int:3,sub_dead:3};
function tierOf(grp){return grp&&grp.indexOf('vuln')===0?4:(TIER[grp]!==undefined?TIER[grp]:3);}
function sizeOf(n){let s={0:14,1:10,2:6,3:4,4:7}[tierOf(n.group)]||4; if(n.count)s+=Math.min(8,Math.log2(n.count+1)); if(n.risk)s+=Math.min(8,n.risk); return s;}
function add(sg){
 (sg.nodes||[]).forEach(n=>{ if(g.hasNode(n.id))return;
   g.addNode(n.id,{label:(n.label||n.id)+(n.count?'  ('+n.count+')':''),group:n.group,title:n.title||'',
     risk:n.risk||0,color:COL[n.group]||'#8c959f',size:sizeOf(n),x:Math.random(),y:Math.random()}); });
 (sg.edges||[]).forEach(e=>{ if(g.hasNode(e.from)&&g.hasNode(e.to)&&!g.hasEdge(e.from,e.to)){
   try{g.addEdge(e.from,e.to,{label:e.label,size:0.6,color:(e.label&&'critical high medium low'.indexOf(e.label)>-1)?'#cf222e':'#d0d7de'});}catch(x){} } });
 relayout();
}
function relayout(){ // radial by tier
 const byT={}; g.forEachNode((id,a)=>{const t=tierOf(a.group);(byT[t]=byT[t]||[]).push(id);});
 Object.keys(byT).forEach(t=>{const ids=byT[t],R=t*2.2,n=ids.length;
   ids.forEach((id,i)=>{const ang=(i/Math.max(1,n))*2*Math.PI; g.setNodeAttribute(id,'x',(t==0?0:R*Math.cos(ang)));
     g.setNodeAttribute(id,'y',(t==0?0:R*Math.sin(ang)));});});
}
let renderer=null;
function render(){ // create once; afterwards just refresh so camera/zoom survive expands
 if(!renderer){
   renderer=new Sigma(g,document.getElementById('cy'),{
     defaultEdgeColor:'#d0d7de',labelColor:{color:'#24292f'},labelSize:11,labelWeight:'500',
     labelRenderedSizeThreshold:7,renderEdgeLabels:false,zIndex:true,minCameraRatio:0.05,maxCameraRatio:12});
   renderer.on('clickNode',({node})=>expand(node));
 } else { renderer.refresh(); }
}
function expand(id){
 const a=g.getNodeAttributes(id);
 document.getElementById('side').innerHTML='<h3>'+a.label+'</h3>'+(a.group||'')+(a.risk?'  · risk '+a.risk:'')+'\n\n'+(a.title||'').replace(/\n/g,'\n');
 fetch(BASE+'/neighbors?id='+encodeURIComponent(id)).then(r=>r.json()).then(sg=>{add(sg);render();}).catch(()=>{});
}
function loadOverview(){
 document.getElementById('stat').textContent='loading…';
 fetch(BASE+'/overview?hostCap=150').then(r=>r.json()).then(sg=>{
   g.clear(); add(sg); render(); if(renderer)renderer.getCamera().animatedReset();
   const m=sg.meta||{}; document.getElementById('stat').textContent=(m.shown||g.order)+' of '+(m.total||'?')+' nodes · click to expand';
 }).catch(e=>{document.getElementById('stat').textContent='load failed';});
}
document.getElementById('q').addEventListener('change',e=>{const q=e.target.value.trim();if(!q)return;
 fetch(BASE+'/search?q='+encodeURIComponent(q)+'&limit=30').then(r=>r.json()).then(d=>{
   (d.nodes||[]).forEach(n=>add({nodes:[n],edges:[]}));
   render();
   const first=(d.nodes||[])[0]; if(first&&g.hasNode(first.id)){const a=g.getNodeAttributes(first.id);
     renderer.getCamera().animate({x:a.x,y:a.y,ratio:0.4},{duration:400});}
 });});
document.getElementById('fit').onclick=()=>renderer&&renderer.getCamera().animatedReset();
document.getElementById('reload').onclick=loadOverview;
loadOverview();
</script></body></html>`
