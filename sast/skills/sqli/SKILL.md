# SQL Injection — @injektor skill
> cats: SQLI, NOSQLI · severity: critical
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input is placed into a SQL/NoSQL query so the attacker alters the query
structure (auth bypass, data exfiltration, RCE via stacked queries / xp_cmdshell).

## Code review — source → sink
- SOURCES: request params/body/headers/cookies, path vars, imported/stored data (2nd order).
- SINKS: `Statement.execute*`, `createStatement`, JPA `createQuery/createNativeQuery`,
  JdbcTemplate `query*`; Go `db.Query/Exec/QueryContext/...`; PHP `mysqli_query`,`$pdo->query`;
  .NET `SqlCommand`/`ExecuteReader`; Python `cursor.execute`; NoSQL `collection.find`, `$where`.
- SANITIZERS (SAFE): **parameterized query / prepared statement / bound placeholders**
  (`?`, `$1`, `:name`, `setString`, `SqlParameter`, `bindParam`), typed ORM query builders,
  numeric casts for numeric context, allow-listed column/table names.

## Exploit payloads (confirm exploitability)
`' OR '1'='1' -- ` · `' UNION SELECT NULL,version()-- ` · `'; DROP TABLE x;-- `
· time-based `' OR SLEEP(5)-- ` / `';WAITFOR DELAY '0:0:5'--` · NoSQL `{"$ne":null}`,`{"$gt":""}`.

## VERIFY
- CONFIRMED when: the tainted value is **concatenated/interpolated/format-built into the
  query string** and reaches an execute sink with no parameterization/escaping between.
- FALSE POSITIVE when: the value is passed as a **bound parameter / placeholder** (separate
  arg), the query is a constant/allow-listed identifier, or a strong escape is applied for
  the exact context. (`mysqli_real_escape_string`/`addslashes` alone = still LIKELY — charset/second-order bypasses.)
- LIKELY when: dataflow reaches the sink but concatenation vs binding is not fully visible.

## Remediation
Always use prepared statements / parameter binding; never string-build SQL from input;
allow-list identifiers; least-privilege DB user.

## References
- PayloadsAllTheThings/SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- HackTricks SQLi: https://book.hacktricks.wiki/en/pentesting-web/sql-injection/

## HackTricks pages (20)

- [Big Binary Files Upload in PostgreSQL](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/big-binary-files-upload-postgresql)
- [Cypher Injection (Neo4j)](https://hacktricks.wiki/en/pentesting-web/sql-injection/cypher-injection-neo4j)
- [MS Access SQL Injection](https://hacktricks.wiki/en/pentesting-web/sql-injection/ms-access-sql-injection)
- [MSSQL Injection](https://hacktricks.wiki/en/pentesting-web/sql-injection/mssql-injection)
- [MySQL FILE Privilege to Outbound SMB and RCE](https://hacktricks.wiki/en/pentesting-web/sql-injection/mysql-injection/mysql-ssrf)
- [MySQL injection](https://hacktricks.wiki/en/pentesting-web/sql-injection/mysql-injection/README)
- [Network - Privilege Escalation, Port Scanning, and NTLM Challenge-Response Disclosure](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/network-privesc-port-scanner-and-ntlm-chanllenge-response-disclosure)
- [NoSQL injection](https://hacktricks.wiki/en/pentesting-web/nosql-injection)
- [Oracle injection](https://hacktricks.wiki/en/pentesting-web/sql-injection/oracle-injection)
- [PL/pgSQL Password Bruteforce](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/pl-pgsql-password-bruteforce)
- [PostgreSQL dblink and lo_import Data Exfiltration](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/dblink-lo_import-data-exfiltration)
- [PostgreSQL injection](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/README)
- [RCE with PostgreSQL Extensions](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions)
- [RCE with PostgreSQL Languages](https://hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-languages)
- [RSQL Injection](https://hacktricks.wiki/en/pentesting-web/rsql-injection)
- [SQL Injection](https://hacktricks.wiki/en/pentesting-web/sql-injection/README)
- [SQL Login Bypass Payloads](https://hacktricks.wiki/en/pentesting-web/login-bypass/sql-login-bypass)
- [SQLMap](https://hacktricks.wiki/en/pentesting-web/sql-injection/sqlmap)
- [SQLMap - Cheatsheet](https://hacktricks.wiki/en/pentesting-web/sql-injection/sqlmap/README)
- [Second-Order Injection with sqlmap](https://hacktricks.wiki/en/pentesting-web/sql-injection/sqlmap/second-order-injection-sqlmap)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
