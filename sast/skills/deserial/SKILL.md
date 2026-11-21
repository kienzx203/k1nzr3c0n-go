# Insecure Deserialization — @unpickler skill
> cats: DESERIALIZATION · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Untrusted bytes are deserialized by an engine that can instantiate arbitrary types / run
gadget chains → RCE or object injection.

## Code review — source → sink
- SINKS: Java `ObjectInputStream.readObject`, XMLDecoder, `yaml.load` (SnakeYAML), Jackson/
  Fastjson with default typing; Python `pickle.loads`/`cPickle`/`marshal`/`yaml.load`;
  PHP `unserialize`; .NET `BinaryFormatter`/`LosFormatter`/`JavaScriptSerializer`/`NetDataContract`;
  Ruby `Marshal.load`/`YAML.load`; Node `node-serialize`, `funcster`.
- SANITIZERS (SAFE): use data-only formats (JSON without polymorphic typing), allow-list of
  classes/`ObjectInputFilter`, `yaml.safe_load`, signed/encrypted + validated payloads, avoid
  native deserializers on untrusted input.

## Exploit payloads
Java ysoserial gadgets (CommonsCollections, URLDNS) · Python `os.system` via `__reduce__` pickle ·
PHP POP chains (`__wakeup`/`__destruct`) · Fastjson `@type` autotype · SnakeYAML `!!javax...`.

## VERIFY
- CONFIRMED when: untrusted bytes (body/cookie/param/file/queue) hit a **native/polymorphic
  deserializer** with no class allow-list or safe-mode.
- FALSE POSITIVE when: a data-only parser is used (`JSON.parse`, `yaml.safe_load`, Jackson
  without default typing), or an `ObjectInputFilter`/class allow-list is enforced, or input is
  signed+verified before deserializing.
- LIKELY when: the deserializer is risky but the source's trust level or filtering is unclear.

## Remediation
Prefer JSON data binding without polymorphic typing; enforce class allow-lists; `safe_load`;
sign+verify serialized data; isolate/sandbox.

## References
- PayloadsAllTheThings/Insecure Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- HackTricks: https://book.hacktricks.wiki/en/pentesting-web/deserialization/

## HackTricks pages (19)

- [Basic .NET Deserialization (ObjectDataProvider, ExpandedWrapper, and Json.NET)](https://hacktricks.wiki/en/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)
- [Basic Java Deserialization with ObjectInputStream readObject](https://hacktricks.wiki/en/pentesting-web/deserialization/basic-java-deserialization-objectinputstream-readobject)
- [Client Side Prototype Pollution](https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution)
- [CommonsCollections1 Payload - Java Transformers to Runtime.exec() and Thread.sleep()](https://hacktricks.wiki/en/pentesting-web/deserialization/java-transformers-to-rutime-exec-payload)
- [Deserialization](https://hacktricks.wiki/en/pentesting-web/deserialization/README)
- [Exploiting \_\_VIEWSTATE without knowing the secrets](https://hacktricks.wiki/en/pentesting-web/deserialization/exploiting-__viewstate-parameter)
- [Exploiting __VIEWSTATE Knowing the Secret](https://hacktricks.wiki/en/pentesting-web/deserialization/exploiting-__viewstate-knowing-the-secret)
- [Express Prototype Pollution Gadgets](https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets)
- [JNDI - Java Naming and Directory Interface & Log4Shell](https://hacktricks.wiki/en/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell)
- [Java DNS Deserialization, GadgetProbe and Java Deserialization Scanner](https://hacktricks.wiki/en/pentesting-web/deserialization/java-dns-deserialization-and-gadgetprobe)
- [Java JSF ViewState Deserialization](https://hacktricks.wiki/en/pentesting-web/deserialization/java-jsf-viewstate-.faces-deserialization)
- [Java SignedObject-gated Deserialization and Pre-auth Reachability via Error Paths](https://hacktricks.wiki/en/pentesting-web/deserialization/java-signedobject-gated-deserialization)
- [Laravel Livewire Hydration & Synthesizer Abuse](https://hacktricks.wiki/en/pentesting-web/deserialization/livewire-hydration-synthesizer-abuse)
- [Node.js - \_\_proto\_\_ and Prototype Pollution](https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/README)
- [PHP - Deserialization + Autoload Classes](https://hacktricks.wiki/en/pentesting-web/deserialization/php-deserialization-+-autoload-classes)
- [Prototype Pollution to RCE](https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce)
- [Python YAML Deserialization](https://hacktricks.wiki/en/pentesting-web/deserialization/python-yaml-deserialization)
- [Ruby Class Pollution](https://hacktricks.wiki/en/pentesting-web/deserialization/ruby-class-pollution)
- [Ruby on Rails _json pollution](https://hacktricks.wiki/en/pentesting-web/deserialization/ruby-_json-pollution)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
