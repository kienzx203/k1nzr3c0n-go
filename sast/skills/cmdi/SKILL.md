# OS Command Injection — @shellghost skill
> cats: CMDI, ARG_INJECTION · severity: critical
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input reaches an OS command/shell so the attacker runs arbitrary commands.

## Code review — source → sink
- SINKS: `Runtime.exec(String)`, `ProcessBuilder` with a shell, `os.system`,
  `subprocess.*(shell=True)`, `subprocess.call("sh","-c",...)`, Go `exec.Command("sh","-c",x)`,
  PHP `system/exec/shell_exec/passthru/popen/proc_open` + backticks, .NET `Process.Start` with
  `/c`, Ruby `Kernel#system`/backticks/`%x`, Node `child_process.exec`.
- ARG_INJECTION: input becomes a flag/option of a trusted binary (`--output=`, `-o`), or a
  value starting with `-` → option smuggling (e.g. `git`, `tar`, `curl`, `ssh -oProxyCommand`).
- SANITIZERS (SAFE): exec with an **argv array and NO shell**, strict allow-list of commands,
  numeric/enum validation. Quoting alone is weak.

## Exploit payloads
`; id` · `| id` · `&& id` · `$(id)` · `` `id` `` · `%0a id` (newline) · arg-inj `-o ProxyCommand=...`,
leading `--`/`-` smuggling.

## VERIFY
- CONFIRMED when: tainted data is part of a **shell command string** (`sh -c`, `cmd /c`,
  backticks, `shell=True`, a `system()`-family call) with no allow-list.
- FALSE POSITIVE when: passed as a **separate argv element to exec WITHOUT a shell** and the
  program name is constant (classic argv exec is injection-safe), or strictly allow-listed.
- LIKELY when: argv exec but the tainted value could be an **option/flag** (arg injection), or
  shell usage is not fully visible.

## Remediation
Use argv-array exec without a shell; allow-list the binary + args; reject values starting with `-`;
avoid shell interpreters entirely.

## References
- PayloadsAllTheThings/Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/command-injection.html
- Argument injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Argument%20Injection

## HackTricks pages (1)

- [Command Injection](https://hacktricks.wiki/en/pentesting-web/command-injection)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
