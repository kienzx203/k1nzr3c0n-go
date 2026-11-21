# Code / Template / EL Injection — @evalisk skill
> cats: CODE_INJECTION, EL_INJECTION, UNSAFE_REFLECTION · severity: critical
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted input is evaluated as code, a template expression, or a reflection target → RCE.

## Code review — source → sink
- CODE: `eval`, `exec`, `Function()`, `vm.runInContext`, PHP `eval`/`create_function`/`assert`,
  Ruby `eval`/`instance_eval`, `pickle.loads`, `yaml.load` (unsafe).
- TEMPLATE (SSTI): Jinja2 `Template(user).render`, Freemarker, Velocity, Thymeleaf inline,
  Twig, Handlebars, ERB with user template, Go `text/template` fed a user-controlled template.
- EL: Spring SpEL `parseExpression(user)`, OGNL (Struts), MVEL, JEXL.
- REFLECTION: `Class.forName(user)`/`getMethod(user).invoke`, dynamic require/import of a user name.
- SANITIZERS (SAFE): never eval user data; allow-list of symbols/classes; sandboxed ssti off;
  data passed as **template variables**, not as the template itself.

## Exploit payloads
SpEL `T(java.lang.Runtime).getRuntime().exec('id')` · Jinja2 `{{7*7}}`→`{{config.__class__...}}` ·
Freemarker `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` · JS `require('child_process').execSync('id')`.

## VERIFY
- CONFIRMED when: tainted data is the **code/expression/template/class-name** passed to an
  evaluator, not merely a data value.
- FALSE POSITIVE when: user data is bound as a template **variable** (engine renders a fixed
  template), or the symbol/class is allow-listed/constant.
- LIKELY when: it reaches an eval-family sink but whether the user controls the expression vs a
  bound value is unclear.

## Remediation
Don't evaluate user input; pass data as parameters/variables; allow-list reflection targets;
use safe loaders (`yaml.safe_load`); sandbox/disable template code features.

## References
- PayloadsAllTheThings/SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/
- Deserialization/Insecure reflection: https://book.hacktricks.wiki/en/pentesting-web/deserialization/

## HackTricks pages (3)

- [EL - Expression Language](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/el-expression-language)
- [Jinja2 SSTI](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
- [SSTI (Server Side Template Injection)](https://hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/README)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
