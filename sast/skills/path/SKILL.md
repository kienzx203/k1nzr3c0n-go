# Path Traversal / LFI / File Upload — @traverser skill
> cats: PATH, RFI_LFI, UNRESTRICTED_UPLOAD · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input controls a filesystem path (read/write/include) or an upload destination, so
the attacker escapes the intended directory or writes an executable file.

## Code review — source → sink
- SINKS: `open/fopen/File(...)`, `readFile/writeFile`, `include/require` (PHP), `fs.readFile`,
  `os.path.join(base, user)`, `ServletContext.getResource`, `SendFile`, `http.ServeFile`,
  archive extraction (zip-slip), upload `move_uploaded_file`/`transferTo`.
- SANITIZERS (SAFE): canonicalize then verify prefix (`filepath.Clean`+`strings.HasPrefix(base)`,
  `Path.getCanonicalPath().startsWith(base)`, `realpath`), `basename`/`FilenameUtils.getName`
  (strips dirs), allow-list of filenames, random server-generated names for uploads.

## Exploit payloads
`../../../../etc/passwd` · `..%2f..%2f` · `....//` · absolute `/etc/passwd` · null `%00` ·
Windows `..\..\` · zip-slip entry `../../evil.sh` · upload `shell.php`, `shell.php.jpg`, `.htaccess`.

## VERIFY
- CONFIRMED when: tainted filename is joined/used as a path with **no canonicalization + base
  containment check**, or extraction/upload writes attacker-controlled relative paths.
- FALSE POSITIVE when: `basename`/`getName` strips directory components, or the code
  canonicalizes and enforces a base-dir prefix, or uses an allow-list / server-generated name.
- LIKELY when: some stripping is applied but may be bypassable (encoding, double-dot, null byte)
  or the base-dir check is not visible.

## Remediation
Canonicalize + enforce base-dir containment; strip to basename; allow-list; for uploads use
random names, store outside webroot, validate content-type by magic bytes.

## References
- PayloadsAllTheThings/Directory Traversal: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- File Upload: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/

## HackTricks pages (1)

- [Client Side Path Traversal](https://hacktricks.wiki/en/pentesting-web/client-side-path-traversal)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
