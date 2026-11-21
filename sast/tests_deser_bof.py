import sys,os;sys.path.insert(0,'agent_a');sys.path.insert(0,'agent_c');import orchestrator as O
def run(lang,ext,code):
    d='%s/tmp/db_%s_%d'%(os.environ.get('CLAUDE_JOB_DIR','/tmp'),lang,abs(hash(code))%99999);os.makedirs(d,exist_ok=True)
    open(os.path.join(d,'a.'+ext),'w').write(code)
    try: return [(f.get('category'),f.get('sink')) for f in O.orchestrate(d,lang=lang,db='taint_spec.db')['findings'] if not f.get('search')]
    except Exception as e: return 'ERR:'+type(e).__name__
# DESERIALIZATION (idiomatic insecure deserial per language, with a real source)
DESER = {
 'php':('php','<?php function f(){ $d=unserialize($_GET["d"]); }'),
 'python':('py','from flask import request\nimport pickle\ndef f(): pickle.loads(request.args.get("d").encode())'),
 'python-yaml':('py','from flask import request\nimport yaml\ndef f(): yaml.load(request.args.get("d"))'),
 'java':('java','import java.io.*;class A{ void f(javax.servlet.http.HttpServletRequest r) throws Exception{ ObjectInputStream o=new ObjectInputStream(r.getInputStream()); o.readObject(); } }'),
 'ruby':('rb','def f; Marshal.load(params[:d]); end'),
 'ruby-yaml':('rb','def f; YAML.load(params[:d]); end'),
 'csharp':('cs','class A{ void f(){ var b=new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter(); b.Deserialize(Request.InputStream); } }'),
 'javascript':('js','function f(req){ const s=require("node-serialize"); s.unserialize(req.query.d); }'),
 'typescript':('ts','function f(req:any){ const s=require("node-serialize"); s.unserialize(req.query.d); }'),
}
# BUFFER OVERFLOW (unsafe memory ops with tainted/argv data)
BOF = {
 'cpp':('cpp','#include<cstring>\nint main(int c,char**argv){ char buf[10]; strcpy(buf,argv[1]); }'),
 'cpp-sprintf':('cpp','#include<cstdio>\nint main(int c,char**argv){ char buf[10]; sprintf(buf,"%s",argv[1]); }'),
 'cpp-gets':('cpp','#include<cstdio>\nint main(){ char buf[10]; gets(buf); }'),
 'cpp-memcpy':('cpp','#include<cstring>\nvoid f(char*src,int n){ char buf[10]; memcpy(buf,src,n); }'),
 'objc':('m','#include<string.h>\nint main(int c,char**argv){ char buf[10]; strcpy(buf,argv[1]); }'),
}
print('=== DESERIALIZATION ===')
dmiss=[]
for k,(ext,code) in DESER.items():
    lang=k.split('-')[0]; r=run(lang,ext,code); ok=isinstance(r,list) and len(r)>0
    if not ok: dmiss.append(k)
    print('  %-14s %s %s'%(k,'OK ' if ok else 'MISS',r))
print('=== BUFFER OVERFLOW ===')
bmiss=[]
for k,(ext,code) in BOF.items():
    lang=k.split('-')[0]; r=run(lang,ext,code); ok=isinstance(r,list) and len(r)>0
    if not ok: bmiss.append(k)
    print('  %-14s %s %s'%(k,'OK ' if ok else 'MISS',r))
print('\nDESER MISS:',dmiss)
print('BOF MISS:',bmiss)
