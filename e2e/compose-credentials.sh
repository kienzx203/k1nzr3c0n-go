#!/usr/bin/env bash
# Resolve real Compose configuration, inspect its container environment, then
# exercise FromEnv without constructing a provider or making an inference call.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/scopeweaver-compose-credentials.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
# Only reuse an existing image; verification must not download dependencies.
docker image inspect postgres:16-alpine >/dev/null
cat > "$fixture/main.go" <<'GO'
package main
import("encoding/json";"os";"github.com/Autumn-27/artex/agent")
func main(){c,ready:=agent.FromEnv();_=json.NewEncoder(os.Stdout).Encode(map[string]any{"provider":c.Provider(),"ready":ready,"key":c.APIKey})}
GO
(cd "$repo" && go build -o "$fixture/resolve-env" "$fixture/main.go")
python3 - "$repo" "$fixture" <<'PY'
import json,os,pathlib,subprocess,sys
repo,fixture=map(pathlib.Path,sys.argv[1:])
base=os.environ.copy()
for key in list(base):
    if key.startswith(('ARTEX_LLM_', 'SCOPEWEAVER_LLM_')) or key in ('ANTHROPIC_API_KEY','OPENAI_API_KEY','OLLAMA_API_KEY'):
        base.pop(key)
base['POSTGRES_PASSWORD']='fixture-only'
cases=[
 ('anthropic-default',{'ANTHROPIC_API_KEY':'fixture-anthropic'},'anthropic','fixture-anthropic',True),
 ('openai-default',{'OPENAI_API_KEY':'fixture-openai'},'openai','fixture-openai',True),
 ('both-default',{'ANTHROPIC_API_KEY':'fixture-anthropic','OPENAI_API_KEY':'fixture-openai'},'anthropic','fixture-anthropic',True),
 ('explicit-anthropic',{'ARTEX_LLM_PROVIDER':'anthropic','ANTHROPIC_API_KEY':'fixture-anthropic','OPENAI_API_KEY':'fixture-openai'},'anthropic','fixture-anthropic',True),
 ('explicit-openai',{'ARTEX_LLM_PROVIDER':'openai','ANTHROPIC_API_KEY':'fixture-anthropic','OPENAI_API_KEY':'fixture-openai'},'openai','fixture-openai',True),
 ('explicit-responses',{'SCOPEWEAVER_LLM_PROVIDER':'openai-responses','OPENAI_API_KEY':'fixture-openai'},'openai-responses','fixture-openai',True),
 ('ollama-token',{'SCOPEWEAVER_LLM_PROVIDER':'ollama','OLLAMA_API_KEY':'fixture-ollama'},'ollama','fixture-ollama',True),
 ('legacy-generic',{'ARTEX_LLM_PROVIDER':'openai','ARTEX_LLM_API_KEY':'fixture-legacy'},'openai','fixture-legacy',True),
 ('modern-generic',{'SCOPEWEAVER_LLM_PROVIDER':'openai','SCOPEWEAVER_LLM_API_KEY':'fixture-modern','ARTEX_LLM_API_KEY':'fixture-legacy'},'openai','fixture-modern',True),
 ('modern-empty-wins',{'SCOPEWEAVER_LLM_PROVIDER':'ollama','SCOPEWEAVER_LLM_API_KEY':'','ARTEX_LLM_API_KEY':'fixture-legacy','OLLAMA_API_KEY':'fixture-ollama'},'ollama','',True),
 ('legacy-empty-wins',{'SCOPEWEAVER_LLM_PROVIDER':'openai','ARTEX_LLM_API_KEY':'','OPENAI_API_KEY':'fixture-openai'},'openai','',False),
]
for name,overrides,provider,key,ready in cases:
    env=base|overrides
    command=['docker','compose','--env-file',str(repo/'.env.example'),'-f',str(repo/'docker-compose.yml'),'config','--format','json']
    config=json.loads(subprocess.check_output(command,env=env,cwd=fixture))
    resolved=config['services']['scopeweaver']['environment']
    assert resolved['SCOPEWEAVER_LOCAL_LLM_ONLY']=='false',name
    for generic in ('SCOPEWEAVER_LLM_API_KEY','ARTEX_LLM_API_KEY'):
        assert resolved.get(generic)==overrides.get(generic),f'{name}: fabricated generic override'
    # A networkless, dependency-free probe uses precisely the resolved environment.
    # Compose represents absent pass-through values as null; the actual container
    # must omit them rather than turning them into empty strings.
    probe={'services':{'probe':{'image':'postgres:16-alpine','network_mode':'none','entrypoint':['env'],'environment':resolved}}}
    probe_file=fixture/'compose.json';probe_file.write_text(json.dumps(probe))
    output=subprocess.check_output(['docker','compose','-p','scopeweaver-credential-fixture','-f',str(probe_file),'run','--rm','--no-deps','-T','probe'],env=env,cwd=fixture,stderr=subprocess.DEVNULL,text=True)
    actual=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
    for generic in ('SCOPEWEAVER_LLM_API_KEY','ARTEX_LLM_API_KEY'):
        assert (generic in actual)==(generic in overrides),f'{name}: actual environment presence differs'
        if generic in overrides: assert actual[generic]==overrides[generic],name
    actual['SCOPEWEAVER_CONFIG']=str(fixture/'absent-config.json')
    result=json.loads(subprocess.check_output([str(fixture/'resolve-env')],env=actual,cwd=fixture))
    assert result=={'provider':provider,'ready':ready,'key':key},f'{name}: provider credential resolution differs'
    print(f'PASS: {name} Compose environment and provider credential resolution')
PY
