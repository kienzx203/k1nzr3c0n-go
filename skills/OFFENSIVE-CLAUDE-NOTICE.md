# Third-party skills: offensive-claude

The offensive-security skill packages in this directory (domain skills like
web-pentest, active-directory-attack, privesc-*, edr-evasion, cloud-security,
initial-access, red-team-ops, … plus the discipline skills scope-discipline,
opsec-discipline, finding-discipline, threat-model-discipline, engagement-flow,
and their `references/` + `scripts/`) are vendored from:

  https://github.com/hypnguyen1209/offensive-claude  (MIT License)

Only the skill markdown, reference library, and helper scripts were imported.
The upstream plugin's hooks/, engine/, commands/, agents/ and installer were NOT
imported — this fork loads skills via its own `agent.LoadSkillsDir()`.

Full upstream license text: OFFENSIVE-CLAUDE-LICENSE (MIT).
