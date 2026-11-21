import sys,os;sys.path.insert(0,'agent_a');sys.path.insert(0,'agent_c');import orchestrator as O
def run(lang,ext,code):
    d='%s/tmp/as_%s_%d'%(os.environ.get('CLAUDE_JOB_DIR','/tmp'),lang,abs(hash(code))%99999);os.makedirs(d,exist_ok=True)
    open(os.path.join(d,'a.'+ext),'w').write(code)
    try: return len([f for f in O.orchestrate(d,lang=lang,db='taint_spec.db')['findings'] if not f.get('search')])
    except Exception as e: return 'ERR:'+type(e).__name__
# remaining languages (the 8 core are already 0-miss in fullaudit.py)
SUITES = {
 'typescript':('ts',{
   'cmdi':'import {exec} from "child_process";function f(req:any){ exec(req.query.c); }',
   'code-eval':'function f(req:any){ eval(req.query.c); }',
   'sqli':'function f(req:any,db:any){ db.query("SELECT "+req.query.id); }',
   'xss-innerhtml':'function f(req:any){ (el as any).innerHTML = req.query.c; }',
 }),
 'kotlin':('kt',{
   'cmdi':'fun f(req:HttpServletRequest){ Runtime.getRuntime().exec(req.getParameter("c")) }',
   'sqli':'fun f(req:HttpServletRequest, st:java.sql.Statement){ st.executeQuery("SELECT "+req.getParameter("id")) }',
 }),
 'swift':('swift',{
   'cmdi':'func f(_ c:String){ let t=Process(); t.launchPath="/bin/sh"; t.arguments=["-c",c]; t.launch() }',
   'sqli':'func f(_ db:OpaquePointer,_ id:String){ sqlite3_exec(db,"SELECT "+id,nil,nil,nil) }',
 }),
 'rust':('rs',{
   'cmdi':'use std::process::Command;fn f(c:String){ Command::new("sh").arg("-c").arg(c).output(); }',
 }),
 'perl':('pl',{
   'cmdi':'sub f{ my $c=$q->param("c"); system($c); }',
   'cmdi-backtick':'sub f{ my $c=$q->param("c"); my $x=`ls $c`; }',
   'code-eval':'sub f{ my $c=$q->param("c"); eval($c); }',
   'open':'sub f{ my $p=$q->param("p"); open(my $fh,$p); }',
 }),
 'objc':('m',{
   'cmdi':'void f(NSString* c){ system([c UTF8String]); }',
   'format':'void f(NSString* u){ NSString* s=[NSString stringWithFormat:u]; }',
 }),
 'vbnet':('vb',{
   'cmdi':'Class A\n Sub F(c As String)\n  Process.Start(c)\n End Sub\nEnd Class',
   'sqli':'Class A\n Sub F(id As String)\n  Dim cmd As New SqlCommand("SELECT " & id)\n End Sub\nEnd Class',
 }),
 'php':('php',{  # re-confirm the fixes stayed
   'backtick-assign':'<?php function f(){ $x=`ping $_GET[c]`; }',
 }),
}
print('%-12s %-16s %s'%('LANG','CLASS','RESULT'))
miss=[]
for lang,(ext,cases) in SUITES.items():
    for cls,code in cases.items():
        n=run(lang,ext,code); ok=isinstance(n,int) and n>0
        if not ok: miss.append((lang,cls,n))
        print('  %-10s %-16s %s %s'%(lang,cls,'OK ' if ok else 'MISS',n))
print('\n=== MISS: %d ==='%len(miss))
for m in miss: print('  ',m)
