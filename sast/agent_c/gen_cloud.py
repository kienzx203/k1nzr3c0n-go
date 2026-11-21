#!/usr/bin/env python3
"""
Generate CLOUD agents (one per HackTricks-Cloud topic) + their skills.

Covers every pentesting-cloud provider and pentesting-ci-cd platform in the
local HackTricks-Cloud clone (skills/hacktricks/repo-cloud), excluding only
methodology/todo/asset folders. Writes:
  - agent_c/cloud_agents.json   (registry consumed by agents.py)
  - skills/<id>/SKILL.md         (per-agent skill from HackTricks-Cloud)

Run:  python3 agent_c/gen_cloud.py
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOUD = os.path.join(ROOT, "skills", "hacktricks", "repo-cloud")
SKILLS = os.path.join(ROOT, "skills")
OUT = os.path.join(ROOT, "agent_c", "cloud_agents.json")

# (id, name, handle, icon, sev, kind, src-relative-to-repo-cloud)
E = [
    ("aws", "AWS Security", "cloudreaver", "☁", "high", "cloud", "pentesting-cloud/aws-security"),
    ("azure", "Azure Security", "skyforge", "⛅", "high", "cloud", "pentesting-cloud/azure-security"),
    ("gcp", "GCP Security", "nimbus", "☁", "high", "cloud", "pentesting-cloud/gcp-security"),
    ("kubernetes", "Kubernetes Security", "helmsman", "⎈", "high", "cloud", "pentesting-cloud/kubernetes-security"),
    ("workspace", "Google Workspace / O365", "tenantx", "◎", "high", "cloud", "pentesting-cloud/workspace-security"),
    ("digitalocean", "DigitalOcean", "dropletx", "◍", "medium", "cloud", "pentesting-cloud/digital-ocean-pentesting"),
    ("ibmcloud", "IBM Cloud", "bluemix", "◑", "medium", "cloud", "pentesting-cloud/ibm-cloud-pentesting"),
    ("openshift", "OpenShift", "shiftghost", "⬡", "medium", "cloud", "pentesting-cloud/openshift-pentesting"),
    ("confidential", "Confidential Computing", "enclave", "⬢", "medium", "cloud", "pentesting-cloud/confidential-computing"),
    ("envvarinjection", "Cloud Env-Var Injection", "envleak", "⎔", "medium", "cloud", "pentesting-cloud/environment-variable-injection.md"),
    # ---- CI/CD ----
    ("jenkins", "Jenkins", "butler", "⚙", "high", "ci-cd", "pentesting-ci-cd/jenkins-security"),
    ("github", "GitHub Actions", "actionsx", "⎇", "high", "ci-cd", "pentesting-ci-cd/github-security"),
    ("terraform", "Terraform / IaC", "statewraith", "⬡", "high", "ci-cd", "pentesting-ci-cd/terraform-security.md"),
    ("argocd", "ArgoCD", "gitops", "⎈", "high", "ci-cd", "pentesting-ci-cd/argocd-security.md"),
    ("circleci", "CircleCI", "orbit", "◴", "high", "ci-cd", "pentesting-ci-cd/circleci-security.md"),
    ("airflow", "Apache Airflow", "dagster", "⟟", "high", "ci-cd", "pentesting-ci-cd/apache-airflow-security"),
    ("okta", "Okta (IdP)", "identix", "⚿", "high", "ci-cd", "pentesting-ci-cd/okta-security"),
    ("teamcity", "TeamCity", "buildcat", "◰", "medium", "ci-cd", "pentesting-ci-cd/teamcity-security"),
    ("concourse", "Concourse CI", "pipewraith", "▰", "medium", "ci-cd", "pentesting-ci-cd/concourse-security"),
    ("atlantis", "Atlantis", "planwraith", "▱", "medium", "ci-cd", "pentesting-ci-cd/atlantis-security.md"),
    ("travisci", "TravisCI", "travx", "◷", "medium", "ci-cd", "pentesting-ci-cd/travisci-security"),
    ("ansible", "Ansible Tower / AWX", "playghost", "⎙", "medium", "ci-cd", "pentesting-ci-cd/ansible-tower-awx-automation-controller-security.md"),
    ("chef", "Chef Automate", "cookbook", "⎚", "medium", "ci-cd", "pentesting-ci-cd/chef-automate-security"),
    ("cloudflare", "Cloudflare", "edgewraith", "⛆", "medium", "ci-cd", "pentesting-ci-cd/cloudflare-security"),
    ("supabase", "Supabase", "baaswraith", "◪", "medium", "ci-cd", "pentesting-ci-cd/supabase-security.md"),
    ("serverless", "Serverless Framework", "lambdax", "ƛ", "medium", "ci-cd", "pentesting-ci-cd/serverless.com-security.md"),
    ("vercel", "Vercel", "edgeverc", "▲", "medium", "ci-cd", "pentesting-ci-cd/vercel-security.md"),
    ("gitea", "Gitea", "teahouse", "⎇", "medium", "ci-cd", "pentesting-ci-cd/gitea-security"),
    ("gogs", "Gogs", "gogsghost", "⎇", "low", "ci-cd", "pentesting-ci-cd/gogs-security"),
    ("gitblit", "Gitblit", "blitghost", "⎇", "low", "ci-cd", "pentesting-ci-cd/gitblit-security"),
    ("dockerbuild", "Docker Build Context", "contextx", "⬒", "medium", "ci-cd", "pentesting-ci-cd/docker-build-context-abuse.md"),
]

VERIFY = """- CONFIRMED when: the reviewed IaC / config / manifest / pipeline grants the risky
  exposure above — public access, wildcard principal/role, disabled auth or MFA, an
  over-broad scope/permission, a plaintext secret, or an unpinned/untrusted step — with
  no compensating control.
- FALSE POSITIVE when: least privilege is enforced, access is restricted/allow-listed,
  auth/MFA is on, secrets live in a vault/OIDC, steps are pinned, or the resource is
  intentionally and safely public.
- LIKELY when: the risky pattern is present but the surrounding guardrail (SCP, policy
  boundary, network rule, branch protection) is not visible in the reviewed files."""


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def intro(md, fallback):
    for ln in md.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", "!", ">", "|", "-", "*", "<", "{", "[![")):
            continue
        if s.startswith("[") and "](" in s:
            continue
        if len(s) < 25:
            continue
        return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)[:420]
    return fallback


def surface(src_abs):
    """Detail = child topics (dir) or section headings (file)."""
    items = []
    if os.path.isdir(src_abs):
        for name in sorted(os.listdir(src_abs)):
            if name.startswith((".", "_")) or name in ("README.md", "SUMMARY.md"):
                continue
            items.append(name.replace(".md", "").replace("-", " "))
    else:
        for ln in _read(src_abs).splitlines():
            m = re.match(r"^#{1,3}\s+(.+)", ln.strip())
            if m:
                items.append(re.sub(r"[`*]", "", m.group(1)).strip())
    return items[:24]


def ht_url(src):
    return "https://cloud.hacktricks.wiki/en/" + src.replace(".md", "").rstrip("/") + "/"


def build(e):
    _id, name, handle, icon, sev, kind, src = e
    src_abs = os.path.join(CLOUD, src)
    md = _read(os.path.join(src_abs, "README.md") if os.path.isdir(src_abs) else src_abs)
    itx = intro(md, "%s security review: identity, permissions, exposure and secrets." % name)
    surf = surface(src_abs)
    lines = [
        "# %s — @%s cloud skill" % (name, handle),
        "> kind: %s · severity: %s · source: HackTricks-Cloud" % (kind, sev),
        "",
        "## What it is",
        itx,
        "",
        "## Attack surface / review checklist",
    ]
    lines += (["- %s" % s for s in surf] if surf
              else ["- enumerate identity, permissions, public exposure, secrets, logging"])
    lines += [
        "",
        "## VERIFY",
        VERIFY,
        "",
        "## References",
        "- HackTricks Cloud: %s" % ht_url(src),
        "- HackTricks Cloud repo: https://github.com/HackTricks-wiki/hacktricks-cloud",
        "",
    ]
    return "\n".join(lines)


def main():
    reg, made = [], 0
    for e in E:
        _id, name, handle, icon, sev, kind, src = e
        src_abs = os.path.join(CLOUD, src)
        if not os.path.exists(src_abs):
            print("  ! missing source:", src)
            continue
        d = os.path.join(SKILLS, _id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write(build(e))
        made += 1
        reg.append({"id": _id, "name": name, "handle": handle, "icon": icon,
                    "sev": sev, "kind": kind,
                    "desc": "%s — HackTricks-Cloud review." % name})
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, ensure_ascii=False, indent=1)
    print("cloud agents: %d · registry: %s" % (made, OUT))


if __name__ == "__main__":
    main()
