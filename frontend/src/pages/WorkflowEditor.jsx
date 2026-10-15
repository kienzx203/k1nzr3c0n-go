import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ReactFlow, Background, BackgroundVariant, Controls, MiniMap,
  useNodesState, useEdgesState, addEdge, MarkerType, Panel,
  Handle, Position, NodeToolbar,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import * as yaml from 'js-yaml'
import { api, wsUrl } from '../api.js'
import { MAX_BATCH, parseTargetList } from '../utils/targets.js'

// ─── Phase palette ────────────────────────────────────────────────────────────
const PH = {
  discovery: { label: 'Discovery',   color: '#58a6ff', bg: '#0a1929', icon: '◉' },
  process:   { label: 'Process',     color: '#a371f7', bg: '#150d26', icon: '◈' },
  resolve:   { label: 'Resolve',     color: '#79c0ff', bg: '#0a1f3a', icon: '⊕' },
  scan:      { label: 'Scan',        color: '#f0b429', bg: '#1f1800', icon: '◎' },
  crawl:     { label: 'Crawl',       color: '#3fb950', bg: '#0a1f0e', icon: '◉' },
  brute:     { label: 'Bruteforce',  color: '#ff9966', bg: '#201100', icon: '◎' },
  vuln:      { label: 'Vuln',        color: '#f85149', bg: '#1f0909', icon: '⚑' },
  report:    { label: 'Report',      color: '#56d364', bg: '#081a0b', icon: '▤' },
}

const STEP_PH = {
  // discovery
  subfinder:'discovery', assetfinder:'discovery', findomain:'discovery',
  chaos:'discovery', gobuster_dns:'discovery', amass:'discovery', oneforall:'discovery',
  shuffledns:'discovery', gotator:'discovery', dnsgen:'discovery',
  metabigor:'discovery', cero:'discovery', asnmap:'discovery', mapcidr:'discovery',
  hakrevdns:'discovery', uncover:'discovery', theHarvester:'discovery',
  shodan_cli:'discovery', censys_cli:'discovery', cloud_enum:'discovery',
  pagodo:'discovery', vhostscan:'discovery',
  // resolve
  dnsx_resolve:'resolve', massdns:'resolve', puredns:'resolve',
  // process
  normalize_gobuster:'process', oneforall_collect:'process',
  normalize_oneforall:'process', merge_subdomains:'process', subzy:'process',
  httprobe:'process', cdncheck:'process', anew:'process',
  unfurl:'process', qsreplace:'process', gf_patterns:'process',
  // scan
  naabu:'scan', httpx:'scan', deep_portscan:'scan', nmap:'scan',
  rustscan:'scan', masscan:'scan', wafw00f:'scan', whatweb:'scan',
  sslyze:'scan', sslscan:'scan', testssl:'scan', ssh_audit:'scan',
  nikto:'scan', wpscan:'scan',
  // crawl
  gau:'crawl', gauplus:'crawl', waybackurls:'crawl', waymore:'crawl',
  katana:'crawl', gospider:'crawl', hakrawler:'crawl', cariddi:'crawl',
  urlfinder:'crawl', subjs:'crawl', jsapiscan:'crawl', linkfinder:'crawl',
  jsubfinder:'crawl', photon:'crawl', paramspider:'crawl', meg:'crawl',
  screenshot:'crawl', screenshot_gallery:'crawl', merge_urls:'crawl',
  // brute
  dirbrute:'brute', vhost_fuzz:'brute', kiterunner:'brute',
  feroxbuster:'brute', dirsearch:'brute', ffuf:'brute',
  wfuzz:'brute', gobuster_dir:'brute', x8:'brute',
  fallparams:'brute', fuzzuli:'brute', byp4xx:'brute',
  // vuln
  nuclei:'vuln', nuclei_urls:'vuln', afrog:'vuln', param_discover:'vuln',
  jaeles:'vuln', dalfox:'vuln', crlfuzz:'vuln', gxss:'vuln', kxss:'vuln',
  corsy:'vuln', graphw00f:'vuln', tplmap:'vuln', nosqlmap:'vuln',
  sqlmap:'vuln', ghauri:'vuln', cvemap:'vuln', interactsh:'vuln',
  dnstake:'vuln', subjack:'vuln', takeover:'vuln',
  s3scanner:'vuln', trufflehog:'vuln', gitleaks:'vuln', secretfinder:'vuln',
  // report
  nuclei_report:'report', gowitness:'report', notify:'report',
}

const SC = {
  pending: { color: 'var(--text-3)', icon: '○', glow: false },
  running: { color: '#3fb950', icon: '●', glow: true },
  ok:      { color: '#3fb950', icon: '✓', glow: false },
  failed:  { color: '#f85149', icon: '✗', glow: false },
  skipped: { color: 'var(--text-3)', icon: '⊘', glow: false },
  paused:  { color: '#f0b429', icon: '⏸', glow: false },
}

// ─── Tool Library catalog ─────────────────────────────────────────────────────
const TOOL_LIBRARY = [
  // ── Discovery ────────────────────────────────────────────────────────────────
  { id:'subfinder', phase:'discovery', name:'Subfinder',
    desc:'Passive subdomain enum via cert transparency, APIs, DNS',
    defaultRun:'subfinder -d {target} -all -silent -o {workspace}/subdomains_subfinder.txt 2>/dev/null; true',
  },
  { id:'amass', phase:'discovery', name:'Amass',
    desc:'OWASP Amass — active + passive subdomain enumeration',
    defaultRun:'amass enum -passive -d {target} -o {workspace}/subdomains_amass.txt 2>/dev/null; true',
  },
  { id:'assetfinder', phase:'discovery', name:'Assetfinder',
    desc:'Fast passive subdomain discovery via multiple sources',
    defaultRun:'assetfinder --subs-only {target} 2>/dev/null > {workspace}/subdomains_assetfinder.txt; true',
  },
  { id:'findomain', phase:'discovery', name:'Findomain',
    desc:'Cross-platform subdomain enum via certificate transparency',
    defaultRun:'findomain -t {target} -u {workspace}/subdomains_findomain.txt 2>/dev/null; true',
  },
  { id:'gobuster_dns', phase:'discovery', name:'Gobuster DNS',
    desc:'DNS subdomain brute-force with wordlist',
    defaultRun:'gobuster dns -d {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 --no-error -o {workspace}/subdomains_gobuster_dns.txt 2>/dev/null; true',
  },
  { id:'chaos', phase:'discovery', name:'Chaos',
    desc:'ProjectDiscovery chaos DB — instant subdomain dataset lookup',
    defaultRun:'chaos -d {target} -silent -o {workspace}/subdomains_chaos.txt 2>/dev/null; true',
  },
  { id:'shuffledns', phase:'discovery', name:'ShuffleDNS',
    desc:'Mass DNS resolver with wildcard filtering and custom resolvers',
    defaultRun:'shuffledns -d {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r {vars.dns_resolvers} -silent -o {workspace}/subdomains_shuffledns.txt 2>/dev/null; true',
  },
  { id:'gotator', phase:'discovery', name:'Gotator',
    desc:'Subdomain permutation generator for DNS brute-forcing',
    defaultRun:'gotator -sub {workspace}/subdomains.txt -perm /opt/gotator/permutations.txt -depth 1 -silent 2>/dev/null > {workspace}/subdomains_permutations.txt; true',
  },
  { id:'dnsgen', phase:'discovery', name:'DNSGen',
    desc:'Generates domain name combinations from wordlist + existing subs',
    defaultRun:'cat {workspace}/subdomains.txt | dnsgen - 2>/dev/null > {workspace}/subdomains_dnsgen.txt; true',
  },
  { id:'metabigor', phase:'discovery', name:'Metabigor',
    desc:'OSINT — ASN, IP ranges, org certificates from multiple APIs',
    defaultRun:'metabigor net --org "{target}" -o {workspace}/metabigor_org.txt 2>/dev/null; true',
  },
  { id:'cero', phase:'discovery', name:'Cero',
    desc:'TLS certificate SAN extractor — finds subdomains from certs',
    defaultRun:'cero {target} 2>/dev/null > {workspace}/subdomains_cero.txt; true',
  },
  { id:'asnmap', phase:'discovery', name:'ASNmap',
    desc:'ASN to IP range mapper — maps org/ASN to CIDR blocks',
    defaultRun:'asnmap -d {target} -silent -o {workspace}/asnmap.txt 2>/dev/null; true',
  },
  { id:'mapcidr', phase:'discovery', name:'MapCIDR',
    desc:'CIDR range manipulation — expand IP ranges to individual hosts',
    defaultRun:'mapcidr -cl {workspace}/asnmap.txt -silent 2>/dev/null > {workspace}/ip_ranges.txt; true',
  },
  { id:'hakrevdns', phase:'discovery', name:'HakRevDNS',
    desc:'Reverse DNS lookup on IP ranges to discover hidden subdomains',
    defaultRun:'cat {workspace}/ip_ranges.txt | hakrevdns -d 2>/dev/null > {workspace}/subdomains_revdns.txt; true',
  },
  { id:'uncover', phase:'discovery', name:'Uncover',
    desc:'Passive recon via Shodan, Fofa, Censys, Quake, Hunter APIs',
    defaultRun:'uncover -q {target} -e shodan,censys,fofa -silent -o {workspace}/uncover.txt 2>/dev/null; true',
  },
  { id:'theHarvester', phase:'discovery', name:'theHarvester',
    desc:'OSINT — emails, hosts, IPs from search engines and APIs',
    defaultRun:'theHarvester -d {target} -b all -l 500 -f {workspace}/theharvester 2>/dev/null; true',
  },
  { id:'shodan_cli', phase:'discovery', name:'Shodan',
    desc:'Query Shodan for exposed services and banners on target IP space',
    defaultRun:'shodan domain {target} 2>/dev/null > {workspace}/shodan.txt; true',
  },
  { id:'censys_cli', phase:'discovery', name:'Censys',
    desc:'Query Censys for TLS certs, open ports and banners',
    defaultRun:'censys search "{target}" --index-type hosts -o {workspace}/censys.json 2>/dev/null; true',
  },
  { id:'cloud_enum', phase:'discovery', name:'Cloud Enum',
    desc:'Multi-cloud asset discovery — S3, GCS, Azure Blob, buckets',
    defaultRun:'python3 /opt/cloud_enum/cloud_enum.py -k {target} --disable-azure --disable-gcp -l {workspace}/cloud_enum.txt 2>/dev/null; true',
  },
  { id:'pagodo', phase:'discovery', name:'Pagodo (Google Dorks)',
    desc:'Automated Google dork queries for passive OSINT discovery',
    defaultRun:'python3 /opt/pagodo/pagodo.py -d {target} -g /opt/pagodo/dorks.txt -l 50 -s 2>/dev/null > {workspace}/pagodo.txt; true',
  },
  { id:'vhostscan', phase:'discovery', name:'VHostScan',
    desc:'Virtual host scanner — discovers hidden vhosts on shared IPs',
    defaultRun:'VHostScan -t {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -oN {workspace}/vhostscan.txt 2>/dev/null; true',
  },
  // ── Resolve ──────────────────────────────────────────────────────────────────
  { id:'dnsx_resolve', phase:'resolve', name:'DNSX',
    desc:'Resolve subdomains to IPs and filter wildcard responses',
    defaultRun:'cat {workspace}/subdomains.txt | dnsx -r {vars.dns_resolvers} -t 200 -silent -o {workspace}/subdomains_resolved.txt 2>/dev/null; true',
  },
  { id:'massdns', phase:'resolve', name:'MassDNS',
    desc:'High-performance DNS resolver — millions of queries per second',
    defaultRun:'massdns -r {vars.dns_resolvers} -t A -o S -w {workspace}/massdns_raw.txt {workspace}/subdomains.txt 2>/dev/null; true',
  },
  { id:'puredns', phase:'resolve', name:'PureDNS',
    desc:'Accurate mass DNS resolver + wildcard filter powered by massdns',
    defaultRun:'puredns resolve {workspace}/subdomains.txt -r {vars.dns_resolvers} -w {workspace}/subdomains_resolved.txt 2>/dev/null; true',
  },
  // ── Process ──────────────────────────────────────────────────────────────────
  { id:'merge_subdomains', phase:'process', name:'Merge Subdomains',
    desc:'Merge and deduplicate all subdomain source files',
    defaultRun:'cat {workspace}/subdomains_*.txt 2>/dev/null | sort -u > {workspace}/subdomains.txt; true',
  },
  { id:'httpx', phase:'process', name:'HTTPX Probe',
    desc:'HTTP probe — status codes, titles, tech detection, CDN',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | httpx -silent -threads 200 -o {workspace}/httpx.jsonl -json -follow-redirects -title -tech-detect -status-code 2>/dev/null; true',
  },
  { id:'httprobe', phase:'process', name:'Httprobe',
    desc:'Lightweight HTTP/HTTPS prober — outputs live URLs only',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | httprobe 2>/dev/null > {workspace}/httprobe.txt; true',
  },
  { id:'cdncheck', phase:'process', name:'CDNcheck',
    desc:'Detect CDN, WAF and cloud provider for resolved IPs',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | cdncheck -silent -o {workspace}/cdncheck.txt 2>/dev/null; true',
  },
  { id:'subzy', phase:'process', name:'Subzy',
    desc:'Subdomain takeover detection across 50+ services',
    defaultRun:'subzy run --targets {workspace}/subdomains_resolved.txt --hide-fails --output {workspace}/subzy.txt 2>/dev/null; true',
  },
  { id:'anew', phase:'process', name:'Anew',
    desc:'Append new lines to a file — dedup filter for pipeline chains',
    defaultRun:'cat {workspace}/urls_new.txt | anew {workspace}/urls_all.txt 2>/dev/null; true',
  },
  { id:'unfurl', phase:'process', name:'Unfurl',
    desc:'Extract URL components — domains, paths, params, keys',
    defaultRun:'cat {workspace}/urls_all.txt | unfurl --unique domains 2>/dev/null > {workspace}/unfurl_domains.txt; true',
  },
  { id:'qsreplace', phase:'process', name:'QSReplace',
    desc:'Replace query string parameter values for injection testing',
    defaultRun:'cat {workspace}/urls_all.txt | qsreplace FUZZ 2>/dev/null > {workspace}/urls_fuzzable.txt; true',
  },
  { id:'gf_patterns', phase:'process', name:'GF Patterns',
    desc:'Grep for interesting URL patterns — SQLi, XSS, SSRF, redirect',
    defaultRun:'cat {workspace}/urls_all.txt | gf xss 2>/dev/null > {workspace}/gf_xss.txt; cat {workspace}/urls_all.txt | gf sqli 2>/dev/null > {workspace}/gf_sqli.txt; cat {workspace}/urls_all.txt | gf ssrf 2>/dev/null > {workspace}/gf_ssrf.txt; true',
  },
  // ── Scan ─────────────────────────────────────────────────────────────────────
  { id:'naabu', phase:'scan', name:'Naabu',
    desc:'Fast TCP port scanner with CDN exclusion and SYN mode',
    defaultRun:'naabu -list {workspace}/subdomains_resolved.txt -p {vars.naabu_top_ports} -rate {vars.naabu_rate} -exclude-cdn -silent -o {workspace}/naabu.jsonl -json 2>/dev/null; true',
  },
  { id:'nmap', phase:'scan', name:'Nmap',
    desc:'Network exploration, port scan and service version detection',
    defaultRun:'nmap -iL {workspace}/hosts.txt -sV --open -T4 -oN {workspace}/nmap.txt 2>/dev/null; true',
  },
  { id:'rustscan', phase:'scan', name:'RustScan',
    desc:'Ultra-fast port scanner — finds open ports then pipes to Nmap',
    defaultRun:'rustscan -a {workspace}/subdomains_resolved.txt --ulimit 5000 -- -sV -oN {workspace}/rustscan.txt 2>/dev/null; true',
  },
  { id:'masscan', phase:'scan', name:'Masscan',
    desc:'Internet-scale port scanner — 10M+ packets/second',
    defaultRun:'masscan -iL {workspace}/ip_ranges.txt -p 80,443,8080,8443 --rate 10000 -oJ {workspace}/masscan.json 2>/dev/null; true',
  },
  { id:'wafw00f', phase:'scan', name:'Wafw00f',
    desc:'WAF detection and fingerprinting for web applications',
    defaultRun:'wafw00f -i {workspace}/httpx_urls.txt -o {workspace}/wafw00f.txt 2>/dev/null; true',
  },
  { id:'whatweb', phase:'scan', name:'WhatWeb',
    desc:'Web technology fingerprinting — CMS, frameworks, libraries',
    defaultRun:'whatweb -i {workspace}/httpx_urls.txt --log-json={workspace}/whatweb.json -q 2>/dev/null; true',
  },
  { id:'sslyze', phase:'scan', name:'SSLyze',
    desc:'Fast SSL/TLS configuration analyser — ciphers, cert, HSTS',
    defaultRun:'python3 -m sslyze --json_out={workspace}/sslyze.json $(cat {workspace}/httpx_urls.txt | sed "s|https://||" | head -20 | tr "\\n" " ") 2>/dev/null; true',
  },
  { id:'sslscan', phase:'scan', name:'SSLScan',
    desc:'SSL/TLS cipher and certificate enumeration',
    defaultRun:'sslscan --show-certificate {target}:443 2>/dev/null > {workspace}/sslscan.txt; true',
  },
  { id:'testssl', phase:'scan', name:'testssl.sh',
    desc:'Thorough TLS/SSL testing — vulnerabilities, ciphers, protocols',
    defaultRun:'testssl --jsonfile={workspace}/testssl.json --quiet {target}:443 2>/dev/null; true',
  },
  { id:'ssh_audit', phase:'scan', name:'SSH Audit',
    desc:'SSH server audit — algorithms, vulnerabilities, fingerprint',
    defaultRun:'ssh-audit -j {target} 2>/dev/null > {workspace}/ssh_audit.txt; true',
  },
  { id:'nikto', phase:'scan', name:'Nikto',
    desc:'Web server vulnerability scanner — misconfigs, outdated software',
    defaultRun:'nikto -h {target} -o {workspace}/nikto.txt -Format txt 2>/dev/null; true',
  },
  { id:'wpscan', phase:'scan', name:'WPScan',
    desc:'WordPress security scanner — plugins, themes, users, vulns',
    defaultRun:'wpscan --url https://{target} --enumerate p,t,u --format json --output {workspace}/wpscan.json 2>/dev/null; true',
  },
  // ── Crawl ────────────────────────────────────────────────────────────────────
  { id:'katana', phase:'crawl', name:'Katana',
    desc:'Fast JS-aware web crawler with headless browser support',
    defaultRun:'katana -list {workspace}/httpx.jsonl -depth {vars.katana_depth} -silent -jc -o {workspace}/katana.jsonl -jsonl 2>/dev/null; true',
  },
  { id:'gau', phase:'crawl', name:'GAU',
    desc:'Fetch URLs from AlienVault, Wayback, URLScan, Common Crawl',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | gau --blacklist png,jpg,gif,svg,css,woff --threads 5 --json 2>/dev/null > {workspace}/gau.jsonl; true',
  },
  { id:'gauplus', phase:'crawl', name:'GAUplus',
    desc:'Extended URL collection — Wayback, CommonCrawl, URLScan, OTX',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | gauplus -t 5 --blacklist png,jpg,gif,svg,css,woff 2>/dev/null > {workspace}/gauplus.txt; true',
  },
  { id:'waybackurls', phase:'crawl', name:'Wayback URLs',
    desc:'Harvest all Wayback Machine URL snapshots for a domain',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | waybackurls 2>/dev/null > {workspace}/waybackurls.txt; true',
  },
  { id:'waymore', phase:'crawl', name:'Waymore',
    desc:'Extended Wayback + URLScan harvester with filtering options',
    defaultRun:'waymore -i {target} -mode U -oU {workspace}/waymore_urls.txt 2>/dev/null; true',
  },
  { id:'gospider', phase:'crawl', name:'Gospider',
    desc:'Fast web spider — JS parsing, robots.txt, sitemap, CORS',
    defaultRun:'gospider -S {workspace}/httpx_urls.txt -o {workspace}/gospider -t 5 --json 2>/dev/null; true',
  },
  { id:'hakrawler', phase:'crawl', name:'Hakrawler',
    desc:'Simple web crawler for link and endpoint extraction',
    defaultRun:'cat {workspace}/httpx_urls.txt | hakrawler -depth 2 -subs 2>/dev/null > {workspace}/hakrawler.txt; true',
  },
  { id:'cariddi', phase:'crawl', name:'Cariddi',
    desc:'Web crawler + secret/API endpoint detection in one pass',
    defaultRun:'cariddi -l {workspace}/httpx_urls.txt -e -s -o {workspace}/cariddi.txt 2>/dev/null; true',
  },
  { id:'urlfinder', phase:'crawl', name:'URLFinder',
    desc:'Crawl target and extract URLs from JS/HTML responses',
    defaultRun:'urlfinder -d {target} -silent -o {workspace}/urlfinder.txt 2>/dev/null; true',
  },
  { id:'subjs', phase:'crawl', name:'Subjs',
    desc:'Collect JS files from a list of URLs for further analysis',
    defaultRun:'cat {workspace}/httpx_urls.txt | subjs 2>/dev/null > {workspace}/js_files.txt; true',
  },
  { id:'jsapiscan', phase:'crawl', name:'JSAPIScan',
    desc:'Extract API endpoints from JavaScript files automatically',
    defaultRun:'jsapiscan -l {workspace}/js_files.txt -o {workspace}/jsapiscan.txt 2>/dev/null; true',
  },
  { id:'linkfinder', phase:'crawl', name:'LinkFinder',
    desc:'Discover endpoints and URLs in JavaScript source files',
    defaultRun:'python3 /opt/linkfinder/linkfinder.py -i {workspace}/js_files.txt -o cli 2>/dev/null > {workspace}/linkfinder.txt; true',
  },
  { id:'jsubfinder', phase:'crawl', name:'JSubFinder',
    desc:'Find subdomains and secrets hidden in JS/HTML source',
    defaultRun:'jsubfinder search -f {workspace}/js_files.txt -o {workspace}/jsubfinder.txt 2>/dev/null; true',
  },
  { id:'photon', phase:'crawl', name:'Photon',
    desc:'Incredibly fast web crawler — extracts URLs, secrets, keys',
    defaultRun:'python3 -m photon -u https://{target} -l 3 -t 50 -o {workspace}/photon 2>/dev/null; true',
  },
  { id:'paramspider', phase:'crawl', name:'ParamSpider',
    desc:'Mine parameters from web archives — finds all GET/POST params',
    defaultRun:'paramspider -d {target} -o {workspace}/paramspider.txt 2>/dev/null; true',
  },
  { id:'meg', phase:'crawl', name:'Meg',
    desc:'Fetch URLs for many hosts at once — efficient bulk requests',
    defaultRun:'meg -d 1000 -v /wp-login.php {workspace}/subdomains_resolved.txt {workspace}/meg_out 2>/dev/null; true',
  },
  // ── Brute ────────────────────────────────────────────────────────────────────
  { id:'feroxbuster', phase:'brute', name:'Feroxbuster',
    desc:'Fast recursive directory brute-force written in Rust',
    defaultRun:'jq -r \'.url\' {workspace}/httpx.jsonl | feroxbuster --stdin -w {vars.dir_wordlist} -t 50 --silent --json -o {workspace}/feroxbuster.json 2>/dev/null; true',
  },
  { id:'dirsearch', phase:'brute', name:'Dirsearch',
    desc:'Web path scanner — finds hidden files, directories and endpoints',
    defaultRun:'dirsearch -l {workspace}/httpx_urls.txt -w {vars.dir_wordlist} -o {workspace}/dirsearch.txt --format=plain -q 2>/dev/null; true',
  },
  { id:'ffuf', phase:'brute', name:'FFUF',
    desc:'Fast web fuzzer — directories, params, vhost brute-forcing',
    defaultRun:'ffuf -w {vars.dir_wordlist} -u https://{target}/FUZZ -mc 200,301,302,403 -o {workspace}/ffuf.json -of json -s 2>/dev/null; true',
  },
  { id:'kiterunner', phase:'brute', name:'Kiterunner',
    desc:'Context-aware API route discovery using OpenAPI/Swagger specs',
    defaultRun:'kr scan {workspace}/httpx.jsonl -w {vars.kr_wordlist} -j 2>/dev/null > {workspace}/kiterunner.txt; true',
  },
  { id:'wfuzz', phase:'brute', name:'Wfuzz',
    desc:'Advanced web fuzzer — multiple injection points, filter options',
    defaultRun:'wfuzz -w {vars.dir_wordlist} -u https://{target}/FUZZ --hc 404 -f {workspace}/wfuzz.json,json 2>/dev/null; true',
  },
  { id:'gobuster_dir', phase:'brute', name:'Gobuster Dir',
    desc:'Directory/file enumeration with status code filtering',
    defaultRun:'gobuster dir -u https://{target} -w {vars.dir_wordlist} -t 50 -o {workspace}/gobuster_dir.txt -q 2>/dev/null; true',
  },
  { id:'x8', phase:'brute', name:'X8',
    desc:'Hidden parameter discovery with response change detection',
    defaultRun:'x8 -u "https://{target}/" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -o {workspace}/x8.txt 2>/dev/null; true',
  },
  { id:'fallparams', phase:'brute', name:'FallParams',
    desc:'Parameter discovery tool using various fuzzing techniques',
    defaultRun:'fallparams -u https://{target}/ -o {workspace}/fallparams.txt 2>/dev/null; true',
  },
  { id:'fuzzuli', phase:'brute', name:'Fuzzuli',
    desc:'Backup and sensitive file discovery via pattern-based fuzzing',
    defaultRun:'cat {workspace}/httpx_urls.txt | fuzzuli -t 50 2>/dev/null > {workspace}/fuzzuli.txt; true',
  },
  { id:'byp4xx', phase:'brute', name:'Byp4xx',
    desc:'Bypass 403/401 responses via HTTP method and header tricks',
    defaultRun:'cat {workspace}/feroxbuster.json | jq -r "select(.status==403) | .url" | byp4xx 2>/dev/null > {workspace}/byp4xx.txt; true',
  },
  // ── Vuln ─────────────────────────────────────────────────────────────────────
  { id:'nuclei', phase:'vuln', name:'Nuclei',
    desc:'Template-based vuln scanner — 9000+ community templates',
    defaultRun:'nuclei -l {workspace}/httpx.jsonl -es info -silent -jsonl -o {workspace}/nuclei.jsonl 2>/dev/null; true',
  },
  { id:'nuclei_urls', phase:'vuln', name:'Nuclei on URLs',
    desc:'Run Nuclei on crawled URLs — XSS, SSRF, SQLi, IDOR templates',
    defaultRun:'nuclei -l {workspace}/urls_all.txt -t http/vulnerabilities -es info -silent -jsonl -o {workspace}/nuclei_urls.jsonl 2>/dev/null; true',
  },
  { id:'afrog', phase:'vuln', name:'Afrog',
    desc:'Fast PoC vulnerability scanner with 400+ built-in checks',
    defaultRun:'afrog -T {workspace}/httpx.jsonl -o {workspace}/afrog.jsonl -json 2>/dev/null; true',
  },
  { id:'param_discover', phase:'vuln', name:'Param Discovery',
    desc:'Discover hidden GET/POST parameters with Arjun',
    defaultRun:'arjun -i {workspace}/urls_params.txt --rate-limit {vars.arjun_rate} -oJ {workspace}/arjun.json 2>/dev/null; true',
  },
  { id:'jaeles', phase:'vuln', name:'Jaeles',
    desc:'Signature-based web vulnerability scanner with 200+ checks',
    defaultRun:'jaeles scan -s /root/.jaeles/base-signatures -U {workspace}/httpx_urls.txt -o {workspace}/jaeles 2>/dev/null; true',
  },
  { id:'dalfox', phase:'vuln', name:'Dalfox',
    desc:'Fast XSS scanner and param analysis with DOM detection',
    defaultRun:'dalfox file {workspace}/gf_xss.txt -b {vars.interact_server} --skip-bav -o {workspace}/dalfox.txt 2>/dev/null; true',
  },
  { id:'crlfuzz', phase:'vuln', name:'CRLFuzz',
    desc:'Fast CRLF injection scanner — HTTP response splitting',
    defaultRun:'crlfuzz -l {workspace}/httpx_urls.txt -o {workspace}/crlfuzz.txt 2>/dev/null; true',
  },
  { id:'gxss', phase:'vuln', name:'Gxss',
    desc:'Detect reflected XSS sinks in parameter values',
    defaultRun:'cat {workspace}/gf_xss.txt | gxss -c 100 2>/dev/null > {workspace}/gxss.txt; true',
  },
  { id:'kxss', phase:'vuln', name:'Kxss',
    desc:'Find reflected XSS parameters with special char reflection check',
    defaultRun:'cat {workspace}/gf_xss.txt | kxss 2>/dev/null > {workspace}/kxss.txt; true',
  },
  { id:'corsy', phase:'vuln', name:'Corsy',
    desc:'CORS misconfiguration scanner — all common bypass techniques',
    defaultRun:'python3 /opt/Corsy/corsy.py -i {workspace}/httpx_urls.txt -t 10 --headers "User-Agent: GoogleBot" 2>/dev/null > {workspace}/corsy.txt; true',
  },
  { id:'graphw00f', phase:'vuln', name:'GraphW00F',
    desc:'GraphQL engine fingerprinting — detects engine type and version',
    defaultRun:'python3 /opt/graphw00f/main.py -d -f -t https://{target} 2>/dev/null > {workspace}/graphw00f.txt; true',
  },
  { id:'tplmap', phase:'vuln', name:'Tplmap',
    desc:'SSTI exploitation tool — detects and exploits template injection',
    defaultRun:'python3 /opt/tplmap/tplmap.py -l {workspace}/gf_ssti.txt --level 5 2>/dev/null > {workspace}/tplmap.txt; true',
  },
  { id:'nosqlmap', phase:'vuln', name:'NoSQLMap',
    desc:'NoSQL injection scanner — MongoDB, CouchDB, Redis attacks',
    defaultRun:'python3 /opt/NoSQLMap/nosqlmap.py --attack 1 -u "https://{target}" 2>/dev/null > {workspace}/nosqlmap.txt; true',
  },
  { id:'sqlmap', phase:'vuln', name:'SQLMap',
    desc:'Automated SQL injection detection and exploitation',
    defaultRun:'sqlmap -m {workspace}/gf_sqli.txt --batch --random-agent --level 3 --risk 2 -o {workspace}/sqlmap 2>/dev/null; true',
  },
  { id:'ghauri', phase:'vuln', name:'Ghauri',
    desc:'Advanced SQL injection detection — WAF bypass, tamper scripts',
    defaultRun:'ghauri -m {workspace}/gf_sqli.txt --batch --dbs -o {workspace}/ghauri.txt 2>/dev/null; true',
  },
  { id:'cvemap', phase:'vuln', name:'CVEmap',
    desc:'CVE database search — map technologies to known CVEs',
    defaultRun:'cvemap -l {workspace}/httpx.jsonl -silent -json -o {workspace}/cvemap.json 2>/dev/null; true',
  },
  { id:'interactsh', phase:'vuln', name:'Interactsh Client',
    desc:'OAST client — detect blind SSRF, XXE, OS injection via DNS/HTTP',
    defaultRun:'interactsh-client -server {vars.interact_server} -o {workspace}/interactsh.txt 2>/dev/null; true',
  },
  { id:'dnstake', phase:'vuln', name:'DNStake',
    desc:'DNS takeover detection via dangling CNAME chain analysis',
    defaultRun:'cat {workspace}/subdomains_resolved.txt | dnstake -o {workspace}/dnstake.txt 2>/dev/null; true',
  },
  { id:'subjack', phase:'vuln', name:'Subjack',
    desc:'Subdomain takeover scanner — fingerprints 50+ cloud providers',
    defaultRun:'subjack -w {workspace}/subdomains_resolved.txt -t 100 -ssl -c /go/pkg/mod/github.com/haccer/subjack*/fingerprints.json -o {workspace}/subjack.txt 2>/dev/null; true',
  },
  { id:'takeover', phase:'vuln', name:'Takeover',
    desc:'Subdomain takeover detection with custom fingerprint database',
    defaultRun:'python3 /opt/takeover/takeover.py -l {workspace}/subdomains_resolved.txt -o {workspace}/takeover.txt 2>/dev/null; true',
  },
  { id:'s3scanner', phase:'vuln', name:'S3Scanner',
    desc:'Open cloud storage bucket scanner — S3, GCS, Azure, DigitalOcean',
    defaultRun:'s3scanner scan --domains-file {workspace}/subdomains.txt --json 2>/dev/null > {workspace}/s3scanner.json; true',
  },
  { id:'trufflehog', phase:'vuln', name:'TruffleHog',
    desc:'Secret scanning — finds leaked credentials, API keys in repos/URLs',
    defaultRun:'trufflehog filesystem {workspace} --json 2>/dev/null > {workspace}/trufflehog.json; true',
  },
  { id:'gitleaks', phase:'vuln', name:'Gitleaks',
    desc:'Scan git repos for leaked secrets and sensitive information',
    defaultRun:'gitleaks detect --source /workspace/repos --report-path {workspace}/gitleaks.json --no-git 2>/dev/null; true',
  },
  { id:'secretfinder', phase:'vuln', name:'SecretFinder',
    desc:'Discover sensitive data (API keys, tokens) in JS source files',
    defaultRun:'python3 /opt/SecretFinder/SecretFinder.py -i {workspace}/js_files.txt -o cli 2>/dev/null > {workspace}/secretfinder.txt; true',
  },
  // ── Report ───────────────────────────────────────────────────────────────────
  { id:'nuclei_report', phase:'report', name:'Nuclei Report',
    desc:'Generate HTML + JSON vulnerability report from Nuclei findings',
    defaultRun:'python {vars.scripts_dir}/scripts/nuclei_report.py --input {workspace}/nuclei.jsonl {workspace}/nuclei_urls.jsonl --out {workspace}/nuclei_report; true',
  },
  { id:'gowitness', phase:'report', name:'Gowitness',
    desc:'Chromium-based screenshot tool for web services and URLs',
    defaultRun:'gowitness file -f {workspace}/httpx_urls.txt --screenshot-path {workspace}/screenshots --db-path {workspace}/gowitness.db 2>/dev/null; true',
  },
  { id:'notify', phase:'report', name:'Notify',
    desc:'Send findings to Slack, Discord, Telegram, or email via templates',
    defaultRun:'cat {workspace}/nuclei.jsonl | notify -bulk -provider-config /root/.config/notify/provider-config.yaml 2>/dev/null; true',
  },
]

// ─── Variable Documentation Catalog ──────────────────────────────────────────
// risk: 'safe' | 'careful' | 'noisy'   impact: 'perf' | 'scope' | 'toggle'
const VAR_DOCS = {
  // ── DNS / Resolve ───────────────────────────────────────────────────────────
  dns_resolvers: {
    desc: 'Path to custom DNS resolver list (one IP per line)',
    detail: 'Use a curated list of fast, reliable public resolvers. Default includes 1.1.1.1, 8.8.8.8 and others. A bad resolver list causes false negatives (live subdomains appear dead).',
    type: 'path', risk: 'safe',
    presets: [
      { label: 'default', value: '/app/wordlists/resolvers.txt' },
      { label: 'cf+google', value: '/app/wordlists/resolvers_trusted.txt' },
    ],
  },
  dnsx_threads: {
    desc: 'Concurrent DNS resolution threads',
    detail: 'Controls how many DNS queries run in parallel. Very high values may exhaust the resolver pool or trigger rate-limiting on the resolver side.',
    type: 'number', unit: 'threads', risk: 'careful',
    riskNote: 'values > 300 may trigger resolver rate-limiting',
    presets: [
      { label: 'safe', value: '50' },
      { label: 'normal', value: '200' },
      { label: 'fast', value: '500' },
    ],
  },
  dnsx_retry: {
    desc: 'DNS query retries before marking a host as dead',
    detail: 'Higher retries reduce false negatives on flaky networks but slow down the resolve phase.',
    type: 'number', unit: 'retries', risk: 'safe',
    presets: [{ label: '1', value: '1' }, { label: '3', value: '3' }, { label: '5', value: '5' }],
  },
  gobuster_threads: {
    desc: 'Goroutine thread count for Gobuster DNS brute-force',
    detail: 'More threads = faster DNS brute-force but also more noisy. Keep under 100 for stealth.',
    type: 'number', unit: 'threads', risk: 'careful',
    presets: [{ label: '20', value: '20' }, { label: '50', value: '50' }, { label: '100', value: '100' }],
  },
  gobuster_timeout: {
    desc: 'Per-request timeout for Gobuster DNS queries',
    detail: 'Lower values speed up brute-force but may miss slow resolvers.',
    type: 'text', unit: 'e.g. 2s', risk: 'safe',
    presets: [{ label: '1s', value: '1s' }, { label: '2s', value: '2s' }, { label: '5s', value: '5s' }],
  },

  // ── Port Scan ───────────────────────────────────────────────────────────────
  naabu_rate: {
    desc: 'SYN packets per second sent by Naabu port scanner',
    detail: 'The primary speed knob for port scanning. Higher rates mean faster scans but are much noisier — likely to trigger IDS, WAF, and firewall blocks. Reduce on sensitive targets or when stealth matters. CDN IPs are auto-excluded.',
    type: 'number', unit: 'pkt/s', risk: 'noisy',
    riskNote: 'high values will trigger IDS / firewall blocks',
    presets: [
      { label: 'stealth', value: '200' },
      { label: 'normal',  value: '1000' },
      { label: 'fast',    value: '3000' },
      { label: 'max',     value: '10000' },
    ],
  },
  naabu_top_ports: {
    desc: 'Port range preset for Naabu to scan',
    detail: '"top-100" covers the most common services. "top-1000" is good for thorough assessments. "full" (0–65535) takes significantly longer but may reveal non-standard service ports.',
    type: 'enum', risk: 'careful',
    options: [
      { value: 'top-100',  label: 'Top 100',   desc: 'Fastest — common services only' },
      { value: 'top-1000', label: 'Top 1000',  desc: 'Balanced — good for most targets' },
      { value: 'full',     label: 'Full range', desc: '0–65535 — thorough but slow' },
    ],
  },

  // ── HTTP Probe ──────────────────────────────────────────────────────────────
  httpx_threads: {
    desc: 'Concurrent HTTP connections for HTTPX probing',
    detail: 'HTTPX sends HTTP requests to each resolved host to check if it\'s live. More threads speed this up but create more concurrent connections per target host. Very high values may trigger WAF rate-limiting.',
    type: 'number', unit: 'threads', risk: 'careful',
    riskNote: 'too high may trigger WAF / CDN rate limiting',
    presets: [
      { label: 'safe', value: '50' },
      { label: 'normal', value: '150' },
      { label: 'fast', value: '300' },
    ],
  },

  // ── Web Crawl ───────────────────────────────────────────────────────────────
  katana_depth: {
    desc: 'Maximum crawl depth from each seed URL',
    detail: 'Depth 1 = only the seed page links. Depth 3 follows links 3 hops deep. Deeper crawls exponentially increase requests and time. JavaScript rendering is enabled by default (-jc flag).',
    type: 'number', unit: 'hops', risk: 'careful',
    riskNote: 'depth > 4 can generate thousands of requests per host',
    presets: [
      { label: 'shallow', value: '2' },
      { label: 'normal',  value: '3' },
      { label: 'deep',    value: '5' },
    ],
  },
  screenshot_threads: {
    desc: 'Concurrent browser instances for screenshot capture',
    detail: 'Each thread spawns a headless browser. High values consume significant memory. Recommended: 2–5 per available CPU core.',
    type: 'number', unit: 'browsers', risk: 'careful',
    presets: [{ label: '3', value: '3' }, { label: '5', value: '5' }, { label: '10', value: '10' }],
  },

  // ── Brute-force ─────────────────────────────────────────────────────────────
  dir_wordlist: {
    desc: 'Path to wordlist used for directory/file brute-forcing',
    detail: 'Larger wordlists find more endpoints but generate far more HTTP traffic. common.txt is a good baseline. Use raft-large for thorough assessments on permissive targets.',
    type: 'path', risk: 'careful',
    presets: [
      { label: 'common',     value: '/usr/share/seclists/Discovery/Web-Content/common.txt' },
      { label: 'big',        value: '/usr/share/seclists/Discovery/Web-Content/big.txt' },
      { label: 'raft-large', value: '/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt' },
      { label: 'api',        value: '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt' },
    ],
  },
  vhost_wordlist: {
    desc: 'Wordlist for virtual host (vhost) discovery',
    detail: 'Used to brute-force Host: headers. A hit means the server responds differently to a non-standard hostname — potentially a hidden internal site.',
    type: 'path', risk: 'careful',
    presets: [
      { label: 'vhosts',   value: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt' },
    ],
  },
  kr_wordlist: {
    desc: 'Kiterunner API route wordlist (.kite or .txt format)',
    detail: 'Kiterunner uses pre-compiled OpenAPI/Swagger route lists to probe REST endpoints with valid HTTP methods and headers — much smarter than naive directory brute-forcing.',
    type: 'path', risk: 'safe',
    presets: [
      { label: 'routes-small', value: '/app/wordlists/routes-small.kite' },
      { label: 'routes-large', value: '/app/wordlists/routes-large.kite' },
    ],
  },
  param_wordlist: {
    desc: 'Wordlist for HTTP parameter discovery',
    detail: 'Used by Arjun to discover hidden GET/POST parameters. Larger lists find more params but take much longer.',
    type: 'path', risk: 'safe',
  },

  // ── Vuln / Rate ─────────────────────────────────────────────────────────────
  arjun_rate: {
    desc: 'Arjun requests per second for parameter discovery',
    detail: 'Arjun sends many requests with parameter combinations. Very high rates risk triggering WAF blocking. Lower rates are more stealthy. 5–20 is good for most bug bounty targets.',
    type: 'number', unit: 'req/s', risk: 'careful',
    riskNote: 'too high may trigger WAF / account rate-limiting',
    presets: [
      { label: 'stealth', value: '5' },
      { label: 'normal',  value: '15' },
      { label: 'fast',    value: '50' },
    ],
  },

  // ── Misc / Internal ─────────────────────────────────────────────────────────
  scripts_dir: {
    desc: 'Base directory where report generation scripts are located',
    detail: 'Usually /app in the Docker container. Only change if you have a custom installation path.',
    type: 'path', risk: 'safe',
    presets: [{ label: '/app', value: '/app' }],
  },

  // ── Phase toggles ───────────────────────────────────────────────────────────
  run_discovery: {
    desc: 'Enable subdomain discovery phase (Subfinder, Amass, etc.)',
    detail: 'Passive and active subdomain enumeration. This is always the first phase and should be enabled unless you already have a known host list.',
    type: 'bool', risk: 'safe',
  },
  run_portscan: {
    desc: 'Enable port scanning (Naabu)',
    detail: 'Identifies open TCP ports. Active — sends SYN packets to each resolved host. Skip on strictly passive assessments or when in scope restrictions prohibit port scanning.',
    type: 'bool', risk: 'noisy',
  },
  run_crawl: {
    desc: 'Enable web crawling (Katana + GAU + Wayback Machine)',
    detail: 'Discovers URLs and endpoints from crawling, passive archives, and JavaScript parsing. Creates the URL surface used by Nuclei and param discovery.',
    type: 'bool', risk: 'careful',
  },
  run_screenshot: {
    desc: 'Enable web screenshots (headless browser)',
    detail: 'Captures a screenshot of each live HTTP host. Useful for quick visual triage of large scopes. Slow on large target sets.',
    type: 'bool', risk: 'safe',
  },
  run_st_pivot_scan: {
    desc: '⚠️ Flow 2: scan SecurityTrails pivot domains (scope-sensitive)',
    detail: 'OFF by default. When enabled, a SEPARATE flow scans the root domains in st_pivot_domains.txt (other orgs sharing NS/MX with the target): naabu port scan (passive + 100 web ports) → httpx probe on every live port → screenshots merged into the gallery. Those domains may belong to third parties (shared hosting/CDN customers) — enable ONLY when your program scope covers org-wide assets. Flow 2 is isolated: no crawl, no vuln scan (nuclei/afrog/katana) touches those domains.',
    type: 'bool', risk: 'noisy',
  },
  run_dirbrute: {
    desc: 'Enable directory/file brute-forcing (Feroxbuster, Dirsearch, FFUF)',
    detail: 'Actively brute-forces paths on each live host. Very noisy — generates a large volume of 404s and is easy to detect in WAF logs. Only enable on targets with explicit pentest scope.',
    type: 'bool', risk: 'noisy',
  },
  run_nuclei: {
    desc: 'Enable Nuclei template-based vulnerability scanning',
    detail: 'Runs 9000+ community templates against all live HTTP hosts. Detects CVEs, misconfigurations, exposed panels, default credentials and more. Rate-limited internally to avoid overwhelming targets.',
    type: 'bool', risk: 'careful',
  },
  run_afrog: {
    desc: 'Enable Afrog PoC-based vulnerability scanner',
    detail: 'Complements Nuclei with a different template set focused on PoC-verified vulnerabilities. Running both provides broader coverage.',
    type: 'bool', risk: 'careful',
  },
  run_params: {
    desc: 'Enable parameter discovery (Arjun)',
    detail: 'Discovers hidden GET/POST parameters by testing a large wordlist. Useful for finding reflected input, potential injection points, and undocumented API params.',
    type: 'bool', risk: 'careful',
  },
  run_vhost: {
    desc: 'Enable virtual host brute-forcing',
    detail: 'Discovers hidden vhosts by brute-forcing the HTTP Host header. Can reveal internal applications not accessible via DNS.',
    type: 'bool', risk: 'noisy',
  },
  run_deep_scan: {
    desc: 'Enable deep port scanning (Nmap service detection)',
    detail: 'Runs Nmap -sV service version detection on discovered open ports. Slow but provides rich service information for manual analysis.',
    type: 'bool', risk: 'careful',
  },
}

const RISK_BADGE = {
  safe:    { label: 'safe',    color: '#3fb950', bg: '#0a1f0e', border: '#3fb95033' },
  careful: { label: 'careful', color: '#f0b429', bg: '#1f1800', border: '#f0b42933' },
  noisy:   { label: 'noisy',   color: '#f85149', bg: '#1f0909', border: '#f8514933' },
}

// ─── Tool Flag Catalog ────────────────────────────────────────────────────────
// Each entry: { desc, categories:[{label, flags:[{key,flag,type,label,desc,...}]}], prefix[], suffix }
// type: 'bool' | 'number' | 'string' | 'enum'
const TOOL_FLAGS = {
  subfinder: {
    desc: 'Passive subdomain enumeration via cert transparency, threat intel APIs and DNS datasets',
    categories: [
      { label: 'Sources', flags: [
        { key:'all',       flag:'-all',       type:'bool',   label:'All Sources',       default:true,
          desc:'Activate every passive source, including those requiring API keys. Finds more but slower.',  risk:'safe' },
        { key:'recursive', flag:'-recursive', type:'bool',   label:'Recursive',
          desc:'Enumerate subdomains of each discovered subdomain. Exponential — use on small scopes.',      risk:'careful' },
        { key:'es',        flag:'-es',        type:'string', label:'Exclude Sources',   placeholder:'github,gitlab',
          desc:'Comma-separated list of sources to skip. Useful when a source is slow or rate-limited.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',       flag:'-t',       type:'number', label:'Threads',    default:'10',  unit:'threads',
          desc:'Concurrent goroutines for source queries. Raising this rarely helps — sources are the bottleneck.' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout',    default:'30',  unit:'sec',
          desc:'Per-source timeout. Increase on slow networks; decrease to skip slow sources faster.' },
        { key:'rl',      flag:'-rl',      type:'number', label:'Rate Limit', unit:'req/s',
          desc:'Maximum API requests per second. Set when a source starts returning 429 errors.',  risk:'safe' },
      ]},
      { label: 'Output', flags: [
        { key:'silent', flag:'-silent', type:'bool', label:'Silent mode',  default:true,
          desc:'Suppress banner and info lines — output only results. Required for clean piping.' },
        { key:'oJ',     flag:'-oJ',     type:'bool', label:'JSON format',
          desc:'Write JSON instead of plain text. Enables richer downstream processing.' },
        { key:'cs',     flag:'-cs',     type:'bool', label:'Show sources',
          desc:'Append the source name to each found subdomain. Useful for provenance tracking.' },
      ]},
    ],
    prefix: ['subfinder', '-d {target}'],
    suffix: '-o {workspace}/subdomains_subfinder.txt 2>/dev/null; true',
  },

  amass: {
    desc: 'OWASP Amass — active + passive subdomain enumeration with graph-based correlation',
    categories: [
      { label: 'Mode', flags: [
        { key:'passive', flag:'-passive', type:'bool', label:'Passive only', default:true,
          desc:'Use only passive data sources — zero active DNS queries. Recommended for stealthy recon.', risk:'safe' },
        { key:'active',  flag:'-active',  type:'bool', label:'Active probing',
          desc:'Send DNS queries and zone transfer attempts directly. More coverage but leaves footprint.', risk:'noisy' },
        { key:'brute',   flag:'-brute',   type:'bool', label:'DNS brute-force',
          desc:'Append wordlist-based brute-force to the enum. Very slow on large wordlists.', risk:'noisy' },
        { key:'norecursive', flag:'-norecursive', type:'bool', label:'No recursion',
          desc:'Disable recursive subdomain enumeration. Faster but shallower.' },
      ]},
      { label: 'Performance', flags: [
        { key:'timeout',  flag:'-timeout', type:'number', label:'Timeout',     unit:'min',
          desc:'Total enumeration timeout in minutes. 0 = no limit.' },
        { key:'dns-qps',  flag:'-dns-qps', type:'number', label:'DNS QPS',     unit:'queries/s',
          desc:'DNS queries per second. Too high triggers resolver rate limits.', risk:'careful' },
        { key:'max-dns-queries', flag:'-max-dns-queries', type:'number', label:'Max DNS queries',
          desc:'Cap on total DNS queries. Use to limit scope on large targets.' },
      ]},
    ],
    prefix: ['amass', 'enum', '-d {target}'],
    suffix: '-o {workspace}/subdomains_amass.txt 2>/dev/null; true',
  },

  gobuster_dns: {
    desc: 'DNS subdomain brute-force using a wordlist — finds subdomains not in passive sources',
    categories: [
      { label: 'Wordlist', flags: [
        { key:'w', flag:'-w', type:'string', label:'Wordlist path', default:'/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
          desc:'Path to subdomain wordlist. Larger = more coverage but slower and noisier.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',       flag:'-t',       type:'number', label:'Threads',    default:'50',  unit:'threads',
          desc:'Goroutine thread count. More threads = faster brute-force but more DNS traffic.', risk:'careful' },
        { key:'timeout', flag:'-timeout', type:'string', label:'Timeout',    default:'2s',  unit:'e.g. 2s',
          desc:'Per-request DNS timeout. Lower to skip slow resolvers faster.' },
      ]},
      { label: 'Output', flags: [
        { key:'no-error', flag:'--no-error', type:'bool', label:'Suppress errors', default:true,
          desc:'Hide DNS error messages (NXDOMAIN, etc.) from output.' },
        { key:'wildcard', flag:'-wildcard', type:'bool', label:'Wildcard detection',
          desc:'Detect and filter wildcard DNS responses. Required for accurate results on wildcard domains.' },
      ]},
    ],
    prefix: ['gobuster', 'dns', '-d {target}'],
    suffix: '-o {workspace}/subdomains_gobuster_dns.txt 2>/dev/null; true',
  },

  dnsx_resolve: {
    desc: 'Fast DNS resolver — validate which subdomains are live and get their IPs',
    categories: [
      { label: 'Resolver', flags: [
        { key:'r',    flag:'-r',    type:'string', label:'Resolvers file',  default:'{vars.dns_resolvers}',
          desc:'Path to custom resolver list. Use trusted resolvers to avoid false negatives.' },
        { key:'t',    flag:'-t',    type:'number', label:'Threads',          default:'200', unit:'threads',
          desc:'Concurrent DNS resolution threads.', risk:'careful' },
        { key:'retry',flag:'-retry',type:'number', label:'Retries',          default:'3',
          desc:'Query retries before marking a host as dead.' },
      ]},
      { label: 'Query types', flags: [
        { key:'a',    flag:'-a',    type:'bool', label:'A record',    default:true, desc:'Resolve IPv4 addresses' },
        { key:'aaaa', flag:'-aaaa', type:'bool', label:'AAAA record', desc:'Resolve IPv6 addresses' },
        { key:'cname',flag:'-cname',type:'bool', label:'CNAME record',desc:'Include CNAME chain in output' },
        { key:'mx',   flag:'-mx',   type:'bool', label:'MX record',   desc:'Mail exchange records' },
        { key:'ns',   flag:'-ns',   type:'bool', label:'NS record',   desc:'Nameserver records' },
        { key:'txt',  flag:'-txt',  type:'bool', label:'TXT record',  desc:'Text records — often contain SPF, DMARC, API keys' },
      ]},
      { label: 'Filtering', flags: [
        { key:'resp',         flag:'-resp',         type:'bool', label:'Show response', desc:'Print DNS response alongside each resolved host' },
        { key:'cdn',          flag:'-cdn',          type:'bool', label:'CDN detection', desc:'Detect and label CDN-hosted subdomains in output' },
        { key:'wildcard-threshold', flag:'-wildcard-threshold', type:'number', label:'Wildcard threshold', default:'5',
          desc:'Wildcard detection threshold — subdomains matching this many random queries are excluded.' },
      ]},
    ],
    prefix: ['cat {workspace}/subdomains.txt |', 'dnsx'],
    suffix: '-silent -o {workspace}/subdomains_resolved.txt 2>/dev/null; true',
  },

  httpx: {
    desc: 'Fast HTTP probe — finds live web servers, extracts metadata and fingerprints technologies',
    categories: [
      { label: 'Probe', flags: [
        { key:'follow-redirects', flag:'-follow-redirects', type:'bool', label:'Follow redirects', default:true,
          desc:'Follow HTTP 301/302 redirects. Required to find the final destination of proxied services.' },
        { key:'threads',          flag:'-threads',          type:'number', label:'Threads', default:'200', unit:'threads',
          desc:'Concurrent HTTP connections. Very high values may trigger WAF rate limiting.', risk:'careful' },
        { key:'timeout',          flag:'-timeout',          type:'number', label:'Timeout', default:'10',  unit:'sec',
          desc:'HTTP request timeout. Increase for slow servers; decrease to skip unresponsive ones.' },
        { key:'random-agent',     flag:'-random-agent',     type:'bool',   label:'Random UA',
          desc:'Send a random User-Agent per request. Reduces fingerprint consistency.' },
      ]},
      { label: 'Extraction', flags: [
        { key:'title',      flag:'-title',       type:'bool', label:'Page title',       default:true, desc:'Extract HTML <title> tag content' },
        { key:'tech-detect',flag:'-tech-detect', type:'bool', label:'Tech detection',   default:true, desc:'Fingerprint web technologies (frameworks, CMS, CDN)' },
        { key:'status-code',flag:'-status-code', type:'bool', label:'Status codes',     default:true, desc:'Include HTTP status code in output' },
        { key:'content-length', flag:'-content-length', type:'bool', label:'Content length', desc:'Include response body size' },
        { key:'web-server', flag:'-web-server',  type:'bool', label:'Server header',    desc:'Extract the Server: response header' },
        { key:'ip',         flag:'-ip',          type:'bool', label:'IP address',       desc:'Include resolved IP address in output' },
        { key:'cdn',        flag:'-cdn',         type:'bool', label:'CDN detection',    desc:'Detect and label CDN-hosted hosts' },
        { key:'screenshot', flag:'-screenshot',  type:'bool', label:'Screenshot',       desc:'Capture browser screenshot of each live host (slow)' , risk:'careful' },
      ]},
      { label: 'Filtering', flags: [
        { key:'mc', flag:'-mc', type:'string', label:'Match status codes', placeholder:'200,301,302',
          desc:'Only output hosts returning these HTTP status codes. Default: all 2xx/3xx.' },
        { key:'fc', flag:'-fc', type:'string', label:'Filter status codes', placeholder:'404,403',
          desc:'Exclude hosts returning these status codes.' },
        { key:'ms', flag:'-ms', type:'number', label:'Min content size', unit:'bytes',
          desc:'Exclude responses smaller than this size (filters empty pages).' },
        { key:'fs', flag:'-fs', type:'number', label:'Filter size',      unit:'bytes',
          desc:'Exclude responses exactly this size (filters identical error pages).' },
      ]},
      { label: 'Output', flags: [
        { key:'silent', flag:'-silent', type:'bool', label:'Silent mode', default:true, desc:'Suppress banner — output only results' },
        { key:'json',   flag:'-json',   type:'bool', label:'JSON output', default:true, desc:'Output in JSON format with all extracted fields' },
      ]},
    ],
    prefix: ['cat {workspace}/subdomains_resolved.txt |', 'httpx'],
    suffix: '-o {workspace}/httpx.jsonl 2>/dev/null; true',
  },

  naabu: {
    desc: 'Fast TCP port scanner using SYN/CONNECT packets — finds open ports across all resolved hosts',
    categories: [
      { label: 'Ports', flags: [
        { key:'p', flag:'-p', type:'enum', label:'Port range', default:'top-100',
          desc:'Which ports to scan.',
          options: [
            { value:'top-100',  label:'Top 100',        desc:'Most common services — fast' },
            { value:'top-1000', label:'Top 1000',       desc:'Comprehensive — good for assessments' },
            { value:'full',     label:'Full (0-65535)', desc:'All ports — very slow, very thorough' },
            { value:'80,443,8080,8443,8000,9090,3000', label:'Web only', desc:'Common web ports only' },
            { value:'21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443', label:'Critical', desc:'High-value service ports' },
          ],
        },
      ]},
      { label: 'Rate / Performance', flags: [
        { key:'rate',    flag:'-rate',    type:'number', label:'Packet rate', default:'2000', unit:'pkt/s',
          desc:'SYN packets per second. High values are very noisy — IDS will see this.', risk:'noisy' },
        { key:'retries', flag:'-retries', type:'number', label:'Retries',     default:'3',
          desc:'How many times to retry a port before marking it closed.' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout',     default:'10',  unit:'ms',
          desc:'Milliseconds to wait for a SYN-ACK response.' },
        { key:'warm-up-time', flag:'-warm-up-time', type:'number', label:'Warm-up', default:'2', unit:'sec',
          desc:'Seconds to warm up before full-rate scanning. Reduces false negatives.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'exclude-cdn',    flag:'-exclude-cdn',    type:'bool', label:'Exclude CDN',       default:true,
          desc:'Skip CDN-hosted IPs (Cloudflare, Akamai, etc.). Port scanning CDN IPs is pointless and noisy.' },
        { key:'scan-all-ips',   flag:'-scan-all-ips',   type:'bool', label:'Scan all IPs',
          desc:'Scan all resolved IPs per hostname — not just the first. Important for load-balanced targets.' },
        { key:'host-discovery', flag:'-host-discovery', type:'bool', label:'Host discovery only',
          desc:'Only detect live hosts (no port details). Very fast alternative to a full scan.' },
      ]},
      { label: 'Output', flags: [
        { key:'silent', flag:'-silent', type:'bool', label:'Silent',      default:true, desc:'Output results only' },
        { key:'json',   flag:'-json',   type:'bool', label:'JSON output', default:true, desc:'Emit JSON per open port' },
      ]},
    ],
    prefix: ['naabu', '-list {workspace}/subdomains_resolved.txt'],
    suffix: '-o {workspace}/naabu.jsonl 2>/dev/null; true',
  },

  katana: {
    desc: 'Next-generation web crawler with JavaScript parsing, form filling and headless browser support',
    categories: [
      { label: 'Crawl', flags: [
        { key:'depth',   flag:'-depth',     type:'number', label:'Depth',        default:'3', unit:'hops',
          desc:'Max crawl depth from seed URL. Depth 3 follows 3 link levels. More = slower + more requests.', risk:'careful' },
        { key:'jc',      flag:'-jc',        type:'bool',   label:'JS crawling',  default:true,
          desc:'Parse JavaScript files and extract endpoints. Finds API calls hidden in JS bundles.' },
        { key:'aff',     flag:'-aff',       type:'bool',   label:'Auto form fill', default:true,
          desc:'Automatically fill and submit forms to discover additional endpoints.' },
        { key:'headless',flag:'-headless',  type:'bool',   label:'Headless browser',
          desc:'Use a full headless browser (slower but handles SPAs and complex JS).', risk:'careful' },
        { key:'kf',      flag:'-kf',        type:'string', label:'Known files',  default:'robotstxt,sitemapxml',
          desc:'Automatically fetch and parse known URL sources like robots.txt and sitemap.xml.' },
      ]},
      { label: 'Scope', flags: [
        { key:'d',       flag:'-d',        type:'number', label:'Max depth',    unit:'hops',
          desc:'Alternative depth flag (same as -depth).' },
        { key:'fs',      flag:'-field-scope', type:'enum', label:'Scope field',
          options:[{value:'rdn',label:'Root domain',desc:'Stay within root domain'},{value:'fqdn',label:'FQDN',desc:'Stay on exact hostname'},{value:'dn',label:'Domain',desc:'All subdomains'}],
          desc:'Which part of the URL defines the in-scope boundary.' },
        { key:'xhr',     flag:'-xhr',      type:'bool', label:'XHR requests', desc:'Capture XHR/Fetch API requests made by the page.' },
      ]},
      { label: 'Performance', flags: [
        { key:'c',       flag:'-c',         type:'number', label:'Concurrency', default:'10', unit:'workers',
          desc:'Number of concurrent crawl workers.' },
        { key:'rl',      flag:'-rate-limit', type:'number', label:'Rate limit', unit:'req/s',
          desc:'Max requests per second. Use to stay under WAF thresholds.', risk:'careful' },
        { key:'timeout', flag:'-timeout',   type:'number', label:'Timeout',     default:'10', unit:'sec',
          desc:'Per-request timeout in seconds.' },
      ]},
      { label: 'Output', flags: [
        { key:'silent', flag:'-silent', type:'bool', label:'Silent',      default:true,  desc:'Suppress banner output' },
        { key:'jsonl',  flag:'-jsonl',  type:'bool', label:'JSONL format',default:true,  desc:'Output one JSON object per line (required for downstream tools)' },
        { key:'no-scope-check', flag:'-no-scope-check', type:'bool', label:'No scope check',
          desc:'Crawl without scope enforcement — follows all links. Use carefully.' },
      ]},
    ],
    prefix: ['katana', '-list {workspace}/httpx.jsonl'],
    suffix: '-o {workspace}/katana.jsonl 2>/dev/null; true',
  },

  feroxbuster: {
    desc: 'Recursive directory and file brute-forcer written in Rust — fast, configurable content discovery',
    categories: [
      { label: 'Wordlist & Extensions', flags: [
        { key:'w', flag:'-w', type:'string', label:'Wordlist', default:'{vars.dir_wordlist}',
          desc:'Path to directory wordlist. Bigger wordlist = more coverage but more noise and time.' },
        { key:'x', flag:'-x', type:'string', label:'Extensions', placeholder:'php,html,js,json,txt,bak',
          desc:'File extensions to append to each wordlist entry. Common: php,asp,aspx,json,xml,bak.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',          flag:'-t',          type:'number', label:'Threads',       default:'50',  unit:'threads',
          desc:'Concurrent request threads. High values generate enormous traffic.', risk:'noisy' },
        { key:'rate-limit', flag:'--rate-limit', type:'number', label:'Rate limit',   unit:'req/s',
          desc:'Max requests per second. Use to stay below WAF detection threshold.', risk:'careful' },
        { key:'timeout',    flag:'--timeout',    type:'number', label:'Timeout',      default:'7',   unit:'sec',
          desc:'Per-request timeout in seconds.' },
        { key:'depth',      flag:'-d',           type:'number', label:'Recursion depth', default:'4',
          desc:'Maximum recursion depth for directory brute-forcing. 0 = unlimited (dangerous).', risk:'careful' },
      ]},
      { label: 'Filtering', flags: [
        { key:'s',  flag:'-s',  type:'string', label:'Match codes',  placeholder:'200,301,302,403',
          desc:'Only show responses with these HTTP status codes. Default includes 200,204,301,302,307,308,401,403,405,500.' },
        { key:'fc', flag:'--filter-status', type:'string', label:'Filter codes', placeholder:'404',
          desc:'Hide responses with these status codes.' },
        { key:'fs', flag:'--filter-size',   type:'number', label:'Filter size',  unit:'bytes',
          desc:'Hide responses of exactly this size — useful to filter identical error pages.' },
        { key:'fw', flag:'--filter-words',  type:'number', label:'Filter words',
          desc:'Hide responses containing exactly this many words.' },
      ]},
      { label: 'Behavior', flags: [
        { key:'r',       flag:'-r',       type:'bool',   label:'Follow redirects', desc:'Follow HTTP redirects automatically.' },
        { key:'k',       flag:'-k',       type:'bool',   label:'Skip TLS verify',  desc:'Ignore SSL/TLS certificate errors.' },
        { key:'A',       flag:'-A',       type:'bool',   label:'Random UA',        desc:'Send a random User-Agent per request.' },
        { key:'H',       flag:'-H',       type:'string', label:'Custom header',    placeholder:'Authorization: Bearer TOKEN',
          desc:'Add a custom HTTP header to every request.' },
        { key:'silent',  flag:'--silent', type:'bool',   label:'Silent output',    default:true, desc:'Output only discovered paths.' },
        { key:'json',    flag:'--json',   type:'bool',   label:'JSON output',      default:true, desc:'Write results in JSON format.' },
      ]},
    ],
    prefix: ['jq -r \'.url\' {workspace}/httpx.jsonl |', 'feroxbuster', '--stdin'],
    suffix: '-o {workspace}/feroxbuster.json 2>/dev/null; true',
  },

  ffuf: {
    desc: 'Fast web fuzzer — directory brute-force, parameter fuzzing and virtual host discovery',
    categories: [
      { label: 'Target & Wordlist', flags: [
        { key:'w',  flag:'-w',  type:'string', label:'Wordlist',     default:'{vars.dir_wordlist}',
          desc:'Path to wordlist. FUZZ keyword in the URL is replaced with each word.' },
        { key:'u',  flag:'-u',  type:'string', label:'URL pattern',  default:'https://{target}/FUZZ',
          desc:'URL with FUZZ placeholder. Can also be in headers or POST body.' },
        { key:'X',  flag:'-X',  type:'enum',   label:'HTTP Method',
          options:[{value:'GET',label:'GET'},{value:'POST',label:'POST'},{value:'HEAD',label:'HEAD'}],
          desc:'HTTP method to use for requests.' },
        { key:'d',  flag:'-d',  type:'string', label:'POST data',    placeholder:'key=FUZZ',
          desc:'POST body data. Use FUZZ to mark the injection point.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'mc', flag:'-mc', type:'string', label:'Match codes',   default:'200,301,302,403',
          desc:'Show only responses with these HTTP status codes.' },
        { key:'ms', flag:'-ms', type:'number', label:'Match size',    unit:'bytes',
          desc:'Show only responses of exactly this content length.' },
        { key:'fc', flag:'-fc', type:'string', label:'Filter codes',  placeholder:'404,500',
          desc:'Hide responses with these status codes.' },
        { key:'fs', flag:'-fs', type:'number', label:'Filter size',   unit:'bytes',
          desc:'Hide responses of exactly this size — filters identical error pages.' },
        { key:'fw', flag:'-fw', type:'number', label:'Filter words',
          desc:'Hide responses with exactly this word count.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',  flag:'-t',  type:'number', label:'Threads',      default:'40',  unit:'threads',
          desc:'Concurrent goroutines. High values will hammer the server.', risk:'noisy' },
        { key:'rate',flag:'-rate', type:'number', label:'Rate limit', unit:'req/s',
          desc:'Max requests per second. Use to avoid WAF blocks.', risk:'careful' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout', default:'10', unit:'sec',
          desc:'HTTP request timeout in seconds.' },
      ]},
      { label: 'Output', flags: [
        { key:'s',  flag:'-s',  type:'bool',   label:'Silent mode',  default:true, desc:'Suppress progress bar — print only matches.' },
        { key:'o',  flag:'-o',  type:'string', label:'Output file',  default:'{workspace}/ffuf.json',
          desc:'Path to write results file.' },
        { key:'of', flag:'-of', type:'enum',   label:'Output format', default:'json',
          options:[{value:'json',label:'JSON'},{value:'csv',label:'CSV'},{value:'all',label:'All formats'}],
          desc:'Output file format.' },
        { key:'H',  flag:'-H',  type:'string', label:'Custom header', placeholder:'Cookie: session=abc',
          desc:'Add a custom HTTP header. Can be used multiple times.' },
      ]},
    ],
    prefix: ['ffuf'],
    suffix: '2>/dev/null; true',
  },

  nuclei: {
    desc: 'Template-based vulnerability scanner — 9000+ community templates for CVEs, misconfigs and exposures',
    categories: [
      { label: 'Templates', flags: [
        { key:'t',     flag:'-t',     type:'string', label:'Template path', placeholder:'http/vulnerabilities',
          desc:'Specific template file or directory to run. Default: all templates.' },
        { key:'tags',  flag:'-tags',  type:'string', label:'Include tags',  placeholder:'cve,xss,ssrf,sqli,rce',
          desc:'Run only templates matching these tags. Comma-separated. Use to focus on a specific class.' },
        { key:'etags', flag:'-etags', type:'string', label:'Exclude tags',  default:'dns',
          desc:'Skip templates with these tags. "dns" tags are excluded by default to avoid slow DNS checks on URL lists.', risk:'safe' },
        { key:'severity', flag:'-severity', type:'string', label:'Min severity', placeholder:'medium,high,critical',
          desc:'Only run templates of these severity levels. Skip "info" to reduce noise.' },
        { key:'es',    flag:'-es',    type:'string', label:'Exclude severity', default:'info',
          desc:'Skip templates at these severity levels. "info" templates are informational and rarely actionable.' },
      ]},
      { label: 'Rate & Concurrency', flags: [
        { key:'rl', flag:'-rl', type:'number', label:'Rate limit',   default:'150', unit:'req/s',
          desc:'Max HTTP requests per second. The most important knob for controlling noise.', risk:'careful' },
        { key:'c',  flag:'-c',  type:'number', label:'Concurrency',  default:'25',  unit:'templates',
          desc:'Number of templates running in parallel. Higher = faster but more concurrent connections.' },
        { key:'bs', flag:'-bs', type:'number', label:'Bulk size',     default:'25',
          desc:'Number of hosts per template batch.' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout', default:'8', unit:'sec',
          desc:'Per-request timeout. Low values speed up scanning but miss slow responses.', },
        { key:'retries', flag:'-retries', type:'number', label:'Retries', default:'1',
          desc:'Retry count on failed requests.' },
      ]},
      { label: 'Behavior', flags: [
        { key:'headless',flag:'-headless',   type:'bool', label:'Headless browser',
          desc:'Enable headless browser for DOM-based XSS and client-side vulnerability templates.', risk:'careful' },
        { key:'sa',      flag:'-sa',         type:'bool', label:'Scan all IPs',
          desc:'Probe all IP addresses per hostname — not just the first resolved IP.' },
        { key:'ni',      flag:'-ni',         type:'bool', label:'No interactsh',
          desc:'Disable out-of-band interactsh server for SSRF/blind tests. Use on isolated networks.' },
        { key:'proxy',   flag:'-proxy',      type:'string', label:'Proxy', placeholder:'http://127.0.0.1:8080',
          desc:'Route all traffic through this proxy. Use with Burp Suite for manual review alongside scan.' },
      ]},
      { label: 'Output', flags: [
        { key:'jsonl',  flag:'-jsonl',   type:'bool', label:'JSONL output',   default:true,  desc:'Output one JSON object per finding — required for report generation.' },
        { key:'silent', flag:'-silent',  type:'bool', label:'Silent mode',    default:true,  desc:'Suppress informational output.' },
        { key:'nmhe',   flag:'-nmhe',    type:'bool', label:'No meta header', default:true,  desc:'No extra metadata headers in requests. Reduces fingerprint.' },
        { key:'stats',  flag:'-stats',   type:'bool', label:'Show statistics',
          desc:'Print a live statistics table during the scan.' },
      ]},
    ],
    prefix: ['nuclei', '-l {workspace}/httpx.jsonl'],
    suffix: '-o {workspace}/nuclei.jsonl 2>/dev/null; touch {workspace}/nuclei.jsonl',
  },

  kiterunner: {
    desc: 'API route discovery using compiled OpenAPI/Swagger spec wordlists — finds REST endpoints with correct HTTP methods',
    categories: [
      { label: 'Wordlist', flags: [
        { key:'w', flag:'-w', type:'string', label:'Routes wordlist', default:'{vars.kr_wordlist}',
          desc:'Path to .kite or .txt API routes wordlist. kite files are pre-compiled and much faster.' },
      ]},
      { label: 'Performance', flags: [
        { key:'x',       flag:'-x',       type:'number', label:'Concurrency',  default:'20', unit:'workers',
          desc:'Concurrent request workers. Balance against WAF sensitivity.', risk:'careful' },
        { key:'timeout', flag:'-timeout', type:'string', label:'Timeout',       default:'3s', unit:'e.g. 3s',
          desc:'Per-request timeout.' },
        { key:'delay',   flag:'-delay',   type:'string', label:'Delay between', placeholder:'100ms',
          desc:'Delay between requests per worker. Adds stealth at the cost of speed.' },
        { key:'max-connection-errors', flag:'--max-connection-errors', type:'number', label:'Max conn errors', default:'10',
          desc:'Stop scanning a host after this many connection errors.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'fail-status-codes', flag:'--fail-status-codes', type:'string', label:'Ignore codes', default:'400,401,404,403,501,502,426,411',
          desc:'Treat these response codes as non-findings.' },
        { key:'quarantine-threshold', flag:'--quarantine-threshold', type:'number', label:'Quarantine threshold', default:'10',
          desc:'Quarantine a host after this many failed requests in a row.' },
      ]},
    ],
    prefix: ['kr', 'scan', '{workspace}/httpx.jsonl'],
    suffix: '-j 2>/dev/null > {workspace}/kiterunner.txt; true',
  },

  afrog: {
    desc: 'PoC-based vulnerability scanner — 400+ built-in checks with verified exploit templates',
    categories: [
      { label: 'Templates', flags: [
        { key:'s',   flag:'-s',   type:'string', label:'Severity filter', placeholder:'medium,high,critical',
          desc:'Run only templates of these severities. Lowercase, comma-separated.' },
        { key:'st',  flag:'-st',  type:'string', label:'Search template', placeholder:'cve-2021',
          desc:'Filter templates by ID substring or tag.' },
      ]},
      { label: 'Rate', flags: [
        { key:'c',  flag:'-c',  type:'number', label:'Concurrency', default:'25', unit:'workers',
          desc:'Concurrent scan workers.', risk:'careful' },
        { key:'rl', flag:'-rl', type:'number', label:'Rate limit',  unit:'req/s',
          desc:'Max HTTP requests per second.', risk:'careful' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout', default:'10', unit:'sec',
          desc:'HTTP request timeout.' },
      ]},
      { label: 'Output', flags: [
        { key:'json',   flag:'-json',   type:'bool', label:'JSON output', default:true, desc:'Write results in JSON format.' },
        { key:'silent', flag:'-silent', type:'bool', label:'Silent mode', desc:'Suppress progress output.' },
      ]},
    ],
    prefix: ['afrog', '-T {workspace}/httpx.jsonl'],
    suffix: '-o {workspace}/afrog.jsonl 2>/dev/null; true',
  },

  // ── Passive subdomain tools ───────────────────────────────────────────────

  assetfinder: {
    desc: 'Passive subdomain finder via Facebook Certificate Transparency, CertSpotter, crt.sh, and Wayback Machine',
    categories: [
      { label: 'Mode', flags: [
        { key:'subs-only', flag:'--subs-only', type:'bool', label:'Subdomains only', default:true,
          desc:'Output only subdomains, not related associated domains. Required for clean output.' },
      ]},
    ],
    prefix: ['assetfinder', '{target}'],
    suffix: '> {workspace}/assetfinder.txt 2>/dev/null; touch {workspace}/assetfinder.txt',
  },

  sublist3r: {
    desc: 'Multi-engine subdomain enumerator querying Google, Bing, Baidu, Netcraft, VirusTotal, DNSdumpster, ThreatCrowd',
    categories: [
      { label: 'Sources', flags: [
        { key:'e', flag:'-e', type:'string', label:'Engines', default:'DNSdumpster,Virustotal,ThreatCrowd',
          placeholder:'Google,Bing,Baidu,Yahoo,Netcraft,DNSdumpster,Virustotal,ThreatCrowd',
          desc:'Comma-separated list of search engines and APIs to query. All are passive sources.' },
        { key:'b', flag:'-b', type:'bool', label:'Brute-force', risk:'noisy',
          desc:'Enable DNS brute-force on top of passive enumeration. Requires -w flag.' },
        { key:'w', flag:'-w', type:'string', label:'Wordlist for brute',
          placeholder:'/app/wordlists/subdomains-top1million-5000.txt',
          desc:'Wordlist to use when brute-force is enabled with -b.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t', flag:'-t', type:'number', label:'Threads', default:'10', unit:'threads',
          desc:'Number of threads for brute-force mode. Has no effect if -b is not set.' },
        { key:'p', flag:'-p', type:'number', label:'Ports', placeholder:'80,443',
          desc:'Scan found subdomains for open ports. Comma-separated list.' },
      ]},
      { label: 'Output', flags: [
        { key:'v', flag:'-v', type:'bool', label:'Verbose',
          desc:'Enable verbose output — shows which engine found each subdomain.' },
        { key:'n', flag:'-n', type:'bool', label:'No color',
          desc:'Disable ANSI color codes in output. Useful for log capture.' },
      ]},
    ],
    prefix: ['sublist3r', '-d {target}'],
    suffix: '-o {workspace}/sublist3r.txt 2>/dev/null; touch {workspace}/sublist3r.txt',
  },

  findomain: {
    desc: 'Fast subdomain finder using certificate transparency logs and multiple passive APIs (crt.sh, Facebook, Virustotal, SecurityTrails)',
    categories: [
      { label: 'Discovery', flags: [
        { key:'q', flag:'-q', type:'bool', label:'Quiet mode', default:true,
          desc:'Suppress banner — output only results. Required for clean piping.' },
        { key:'unique-output', flag:'--unique-output', type:'bool', label:'Unique output',
          desc:'Deduplicate subdomains before writing. Reduces file size on large targets.' },
        { key:'exclude-sources', flag:'--exclude-sources', type:'string', label:'Exclude sources',
          placeholder:'spyse,bufferover',
          desc:'Comma-separated list of sources to exclude. Use when a source is consistently unreliable.' },
        { key:'p', flag:'-p', type:'bool', label:'HTTP probe',
          desc:'Probe discovered subdomains for open HTTP/HTTPS ports. Slow but useful.', risk:'careful' },
      ]},
      { label: 'Rate / Timeout', flags: [
        { key:'rate-limit',         flag:'--rate-limit',         type:'number', label:'Rate limit', unit:'req/s',
          desc:'Max requests per second to passive sources.' },
        { key:'rate-limit-resolver',flag:'--rate-limit-resolver',type:'number', label:'DNS rate limit', unit:'q/s',
          desc:'Max DNS queries per second during probing.' },
        { key:'timeout',            flag:'--timeout',            type:'number', label:'Timeout', unit:'sec',
          desc:'Per-request timeout for passive source queries.' },
      ]},
    ],
    prefix: ['findomain', '-t {target}'],
    suffix: '-u {workspace}/findomain.txt',
  },

  chaos: {
    desc: 'ProjectDiscovery Chaos dataset — crowd-sourced subdomain inventory for thousands of bug bounty programs',
    categories: [
      { label: 'Query', flags: [
        { key:'silent', flag:'-silent', type:'bool', label:'Silent mode', default:true,
          desc:'Output only subdomains, suppress progress messages.' },
        { key:'count', flag:'-count', type:'bool', label:'Show count',
          desc:'Print number of subdomains for the domain before listing them.' },
        { key:'filter-wildcards', flag:'-filter-wildcards', type:'bool', label:'Filter wildcards',
          desc:'Remove wildcard DNS records from the output. Reduces noise.' },
        { key:'update', flag:'-update', type:'bool', label:'Update index',
          desc:'Update the local Chaos index before querying. Ensures freshest data.' },
      ]},
    ],
    prefix: ['chaos', '-d {target}', '-key {vars.chaos_key}'],
    suffix: '-o {workspace}/chaos.txt 2>/dev/null; touch {workspace}/chaos.txt',
  },

  // ── Post-DNS tools ────────────────────────────────────────────────────────

  subzy: {
    desc: 'Subdomain takeover checker — detects CNAMEs pointing to unclaimed third-party services (GitHub Pages, Heroku, S3, etc.)',
    categories: [
      { label: 'Scan', flags: [
        { key:'verify', flag:'--verify', type:'bool', label:'Verify takeovers', default:true,
          desc:'Verify each potential takeover by fingerprinting the response body. Reduces false positives.' },
        { key:'https', flag:'--https', type:'bool', label:'Prefer HTTPS',
          desc:'Try HTTPS before HTTP when probing potential takeovers.' },
        { key:'hide-fails', flag:'--hide-fails', type:'bool', label:'Hide non-vuln',
          desc:'Only show vulnerable subdomains, not the full scan output.' },
      ]},
      { label: 'Performance', flags: [
        { key:'concurrency', flag:'--concurrency', type:'number', label:'Concurrency', default:'10', unit:'workers',
          desc:'Number of concurrent subdomain takeover checks.', risk:'careful' },
        { key:'timeout',     flag:'--timeout',     type:'number', label:'Timeout',     default:'10', unit:'sec',
          desc:'HTTP request timeout per probe.' },
      ]},
      { label: 'Output', flags: [
        { key:'output', flag:'--output', type:'string', label:'Output file',
          default:'{workspace}/subzy.txt',
          desc:'Write results to this file (in addition to stdout).' },
      ]},
    ],
    prefix: ['subzy', 'run', '--targets {steps.dnsx_resolve.resolved}'],
    suffix: '> {workspace}/subzy.txt 2>/dev/null; touch {workspace}/subzy.txt',
  },

  // ── Passive URL mining ────────────────────────────────────────────────────

  gau: {
    desc: 'getallurls — mines URLs from Wayback Machine, Common Crawl, OTX AlienVault, and URLScan for each resolved subdomain',
    categories: [
      { label: 'Sources', flags: [
        { key:'providers', flag:'--providers', type:'string', label:'Providers',
          default:'wayback,commoncrawl,otx,urlscan',
          desc:'Comma-separated list of URL sources. Remove sources to speed up enumeration.' },
        { key:'subs', flag:'--subs', type:'bool', label:'Include subdomains',
          desc:'Also fetch URLs for subdomains of the target domain. Significantly increases output.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'blacklist', flag:'--blacklist', type:'string', label:'Blacklist ext',
          default:'png,jpg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,pdf,zip',
          desc:'Comma-separated list of file extensions to exclude. Static assets are not useful for param discovery.' },
        { key:'mc',      flag:'--mc',      type:'string', label:'Match codes',  placeholder:'200,301,302',
          desc:'Only return URLs that historically returned these HTTP status codes.' },
        { key:'fp',      flag:'--fp',      type:'bool',   label:'Filter params',
          desc:'Filter duplicate URLs keeping only unique parameter names. Reduces output by 60–80%.' },
        { key:'from',    flag:'--from',    type:'string', label:'Date from',    placeholder:'202001',
          desc:'Only include URLs indexed after this date (YYYYMM format).' },
        { key:'to',      flag:'--to',      type:'string', label:'Date to',      placeholder:'202612',
          desc:'Only include URLs indexed before this date (YYYYMM format).' },
      ]},
      { label: 'Performance', flags: [
        { key:'threads', flag:'--threads', type:'number', label:'Threads',  default:'5',  unit:'threads',
          desc:'Number of concurrent domain fetch workers.' },
        { key:'timeout', flag:'--timeout', type:'number', label:'Timeout',  default:'30', unit:'sec',
          desc:'Per-source request timeout in seconds.' },
        { key:'retries', flag:'--retries', type:'number', label:'Retries',  default:'3',
          desc:'Number of retries on network failure.' },
        { key:'rate-limit', flag:'--rate-limit', type:'number', label:'Rate limit', unit:'req/s',
          desc:'Max requests per second globally. Use to avoid rate limiting from providers.' },
      ]},
      { label: 'Output', flags: [
        { key:'json', flag:'--json', type:'bool', label:'JSON output', default:true,
          desc:'Output JSON objects with URL, status code, and source. Required for downstream processing.' },
        { key:'verbose', flag:'--verbose', type:'bool', label:'Verbose',
          desc:'Show debug info and per-provider progress.' },
      ]},
    ],
    prefix: ['cat {steps.dnsx_resolve.resolved} |', 'gau'],
    suffix: '2>/dev/null > {workspace}/gau.jsonl || true',
  },

  waybackurls: {
    desc: 'Fetches all URLs that the Wayback Machine knows about for a list of domains — purely passive, no active requests to target',
    categories: [
      { label: 'Options', flags: [
        { key:'dates', flag:'-dates', type:'bool', label:'Include dates',
          desc:'Include the date each URL was archived. Useful for tracking how long endpoints have existed.' },
        { key:'no-subs', flag:'-no-subs', type:'bool', label:'No subdomains',
          desc:'Only return URLs for the exact domain, not for subdomains. Reduces output on large scopes.' },
        { key:'get-versions', flag:'-get-versions', type:'bool', label:'Get versions',
          desc:'Return all known versions of each URL, not just the most recent one.' },
      ]},
    ],
    prefix: ['cat {steps.dnsx_resolve.resolved} |', 'timeout 120 waybackurls'],
    suffix: '2>/dev/null | sort -u > {workspace}/waybackurls.txt || true',
  },

  // ── Screenshots ────────────────────────────────────────────────────────────

  screenshot: {
    desc: 'gowitness — headless Chrome screenshot capture for all live HTTP/HTTPS hosts, stored in SQLite for gallery viewing',
    categories: [
      { label: 'Browser', flags: [
        { key:'chrome-path',     flag:'--chrome-path',     type:'string', label:'Chrome path',
          default:'/usr/local/bin/chromium-docker',
          desc:'Path to the Chromium/Chrome executable. Must be a headless-capable build.' },
        { key:'T',               flag:'-T',                type:'number', label:'Page timeout', default:'30', unit:'sec',
          desc:'Seconds to wait for a page to load before taking the screenshot.' },
        { key:'delay',           flag:'--delay',           type:'number', label:'Delay after load', unit:'ms',
          desc:'Extra milliseconds to wait after page load before capturing. Useful for JS-heavy SPAs.' },
        { key:'resolution',      flag:'--resolution',      type:'string', label:'Resolution', default:'1440,900',
          desc:'Viewport resolution in WIDTHxHEIGHT format.' },
        { key:'skip-html',       flag:'--skip-html',       type:'bool',   label:'Skip HTML pages',
          desc:'Do not capture pages that serve plain HTML without significant JS. Skips boilerplate.' },
      ]},
      { label: 'Performance', flags: [
        { key:'threads',         flag:'--threads',         type:'number', label:'Threads', default:'10', unit:'browsers',
          desc:'Number of headless browser instances running in parallel. More = faster but more RAM.', risk:'careful' },
        { key:'disable-logging', flag:'--disable-logging', type:'bool',   label:'No browser logs',
          desc:'Suppress Chrome\'s verbose DevTools logging.' },
      ]},
      { label: 'Database', flags: [
        { key:'write-db',        flag:'--write-db',        type:'bool', label:'Write to DB', default:true,
          desc:'Store screenshot metadata and base64 images in the SQLite database.' },
        { key:'write-db-uri',    flag:'--write-db-uri',    type:'string', label:'DB path',
          default:'sqlite://{workspace}/gowitness.sqlite3',
          desc:'SQLite URI for the gowitness database. Must use sqlite:// prefix.' },
      ]},
    ],
    prefix: ['gowitness', 'scan', 'file', '-f {workspace}/live_urls.txt', '-s {workspace}/screenshots'],
    suffix: '-q 2>{workspace}/gowitness.log || true',
  },

  // ── Port scanning ─────────────────────────────────────────────────────────

  rustscan: {
    desc: 'Ultra-fast port scanner written in Rust — finds all open ports in seconds, then passes them to nmap for service detection',
    categories: [
      { label: 'Target & Range', flags: [
        { key:'range', flag:'--range', type:'string', label:'Port range', default:'1-65535',
          desc:'Port range to scan. Default is all 65535 ports. "1-1000" for a faster sweep.', risk:'noisy' },
        { key:'scan-order', flag:'--scan-order', type:'enum', label:'Scan order',
          options:[
            { value:'random',     label:'Random',     desc:'Randomize port order — harder to detect by IDS' },
            { value:'serial',     label:'Sequential', desc:'Scan ports in order 1,2,3... — predictable but faster' },
          ],
          default:'random', desc:'Order in which ports are probed.' },
      ]},
      { label: 'Performance', flags: [
        { key:'batch-size',  flag:'--batch-size',  type:'number', label:'Batch size',  default:'5000', unit:'sockets',
          desc:'Number of sockets open simultaneously. Higher = faster but may exhaust ulimit.', risk:'noisy' },
        { key:'timeout',     flag:'--timeout',     type:'number', label:'Timeout',      default:'2000', unit:'ms',
          desc:'Milliseconds to wait for a response per port. Low values miss slow hosts.' },
        { key:'tries',       flag:'--tries',       type:'number', label:'Retries',      default:'2',
          desc:'Number of times to try each port before marking it closed.' },
        { key:'ulimit',      flag:'--ulimit',      type:'number', label:'ulimit',       default:'5000',
          desc:'Set the system file descriptor limit. Must be >= batch-size.' },
      ]},
    ],
    prefix: ['rustscan', '-a {target}'],
    suffix: '-- -Pn -sV -sC -oN {workspace}/rustscan.txt',
  },

  nmap_tcp: {
    desc: 'nmap TCP scan — service version detection and default script scan on all TCP ports',
    categories: [
      { label: 'Scan technique', flags: [
        { key:'sV',   flag:'-sV',   type:'bool', label:'Version detection', default:true,
          desc:'Probe open ports to determine service name and version. Essential for exploitation.' },
        { key:'sC',   flag:'-sC',   type:'bool', label:'Default scripts', default:true,
          desc:'Run default NSE scripts: banner grab, auth check, vuln detection basics.' },
        { key:'A',    flag:'-A',    type:'bool', label:'Aggressive mode',
          desc:'Enable OS detection, version detection, scripts, and traceroute all at once.', risk:'noisy' },
        { key:'sS',   flag:'-sS',   type:'bool', label:'SYN stealth scan',
          desc:'Half-open SYN scan — less likely to be logged than full TCP connect.', risk:'careful' },
        { key:'sT',   flag:'-sT',   type:'bool', label:'TCP connect scan',
          desc:'Full TCP connect — works without root but leaves entries in connection logs.', risk:'careful' },
      ]},
      { label: 'Host / Timing', flags: [
        { key:'Pn',   flag:'-Pn',   type:'bool', label:'No ping', default:true,
          desc:'Skip host discovery — treat all hosts as online. Required when ICMP is blocked.' },
        { key:'p',    flag:'-p',    type:'string', label:'Port range', default:'-',
          desc:'Ports to scan. "-" means all 65535 ports. Comma or range notation.' },
        { key:'T',    flag:'-T',    type:'enum',   label:'Timing template',
          options:[
            { value:'1', label:'T1 — Sneaky',  desc:'Very slow, evades IDS' },
            { value:'2', label:'T2 — Polite',  desc:'Slow, reduces bandwidth' },
            { value:'3', label:'T3 — Normal',  desc:'Default speed' },
            { value:'4', label:'T4 — Aggressive', desc:'Fast — assumes reliable network' },
          ], default:'3',
          desc:'Timing template controls scan speed and stealth trade-off.', risk:'careful' },
        { key:'min-rate', flag:'--min-rate', type:'number', label:'Min packets/s', unit:'pkt/s',
          desc:'Minimum packet send rate. Overrides timing templates for throughput control.', risk:'noisy' },
      ]},
      { label: 'Scripts', flags: [
        { key:'script', flag:'--script', type:'string', label:'NSE scripts', placeholder:'vuln,auth,default',
          desc:'Comma-separated list of NSE script categories or names to run. "vuln" runs all vuln checks.' },
        { key:'script-args', flag:'--script-args', type:'string', label:'Script args', placeholder:'http.useragent=Mozilla',
          desc:'Arguments passed to NSE scripts.' },
      ]},
      { label: 'Output', flags: [
        { key:'oX', flag:'-oX', type:'bool', label:'Also XML output',
          desc:'Write XML output alongside the normal file. Useful for Metasploit/external tools.' },
        { key:'v',  flag:'-v',  type:'bool', label:'Verbose',
          desc:'Show open ports as they are discovered during the scan.' },
      ]},
    ],
    prefix: ['nmap'],
    suffix: '-oN {workspace}/nmap_tcp.txt {target}',
  },

  nmap_udp: {
    desc: 'nmap UDP scan — detects DNS, SNMP, NTP, TFTP and other critical UDP services that TCP scans miss entirely',
    categories: [
      { label: 'Scan technique', flags: [
        { key:'sU',         flag:'-sU',         type:'bool', label:'UDP scan', default:true,
          desc:'Enable UDP port scanning. Much slower than TCP — each port waits for ICMP unreachable or response.' },
        { key:'Pn',         flag:'-Pn',         type:'bool', label:'No ping', default:true,
          desc:'Skip host discovery. Required on most firewalled targets.' },
        { key:'sV',         flag:'-sV',         type:'bool', label:'Version detection',
          desc:'Probe open UDP ports for service versions. Very slow — use only on important hosts.' },
        { key:'top-ports',  flag:'--top-ports',  type:'number', label:'Top ports', default:'200',
          desc:'Scan only the N most commonly open UDP ports. Full UDP scan is impractical.', },
      ]},
      { label: 'Timing', flags: [
        { key:'T',          flag:'-T',           type:'enum', label:'Timing template',
          options:[
            { value:'2', label:'T2 — Polite',    desc:'Reduces false negatives on UDP' },
            { value:'3', label:'T3 — Normal',    desc:'Default' },
            { value:'4', label:'T4 — Aggressive',desc:'Faster but more false positives' },
          ], default:'3', desc:'UDP scanning is inherently slow — T3 is usually the best balance.' },
        { key:'min-rate',   flag:'--min-rate',   type:'number', label:'Min rate', unit:'pkt/s',
          desc:'Minimum packet rate. Too high = many false open/filtered results on UDP.' },
        { key:'max-retries',flag:'--max-retries',type:'number', label:'Retries', default:'6',
          desc:'UDP ports require more retries due to packet loss and ICMP rate limiting.' },
      ]},
      { label: 'Output', flags: [
        { key:'oX', flag:'-oX', type:'bool', label:'Also XML output',
          desc:'Write XML output alongside the normal file.' },
        { key:'v',  flag:'-v',  type:'bool', label:'Verbose',
          desc:'Show open ports as discovered.' },
      ]},
    ],
    prefix: ['nmap'],
    suffix: '-oN {workspace}/nmap_udp.txt {target}',
  },

  // ── Directory/endpoint brute-force ────────────────────────────────────────

  // gobuster dir mode — used in dirbrute fanout (sub.id = 'gobuster', cmd contains ' dir ')
  gobuster: {
    desc: 'gobuster dir — URL path brute-force. Probes a single target with a wordlist. For virtual host mode see gobuster_vhost.',
    categories: [
      { label: 'Wordlist & Extensions', flags: [
        { key:'w',  flag:'-w',  type:'string', label:'Wordlist',   default:'{vars.dir_wordlist}',
          desc:'Path to wordlist. Each line is a path segment to probe.' },
        { key:'x',  flag:'-x',  type:'string', label:'Extensions', placeholder:'php,html,js,json,txt,bak,config',
          desc:'Comma-separated file extensions appended to each word. Essential for discovering hidden files.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'b',  flag:'-b',             type:'string', label:'Exclude codes', default:'404,403,400,429,302',
          desc:'HTTP status codes to exclude from results.' },
        { key:'s',  flag:'-s',             type:'string', label:'Match codes',   placeholder:'200,301',
          desc:'Show only these HTTP status codes. Overrides -b when set.' },
        { key:'el', flag:'--exclude-length',type:'number', label:'Filter size',  unit:'bytes',
          desc:'Exclude responses of exactly this byte length — removes identical blank/error pages.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',            flag:'-t',            type:'number', label:'Threads',        default:'50',  unit:'threads',
          desc:'Concurrent request threads.', risk:'careful' },
        { key:'timeout',      flag:'--timeout',     type:'string', label:'Timeout',        default:'10s',
          desc:'Per-request HTTP timeout. Include time unit: "10s", "30s", "1m".' },
        { key:'k',            flag:'-k',            type:'bool',   label:'Skip TLS verify',
          desc:'Ignore SSL/TLS certificate errors. Required for self-signed certs.' },
        { key:'r',            flag:'-r',            type:'bool',   label:'Follow redirects',
          desc:'Follow HTTP redirects automatically.' },
        { key:'random-agent', flag:'--random-agent',type:'bool',   label:'Random UA',
          desc:'Send a random User-Agent with each request.' },
      ]},
      { label: 'Output', flags: [
        { key:'q',           flag:'-q',           type:'bool', label:'Quiet',       default:true, desc:'Suppress banner.' },
        { key:'no-progress', flag:'--no-progress',type:'bool', label:'No progress', default:true, desc:'Suppress live progress display.' },
        { key:'no-error',    flag:'--no-error',   type:'bool', label:'No errors',   default:true, desc:'Suppress connection error messages.' },
      ]},
    ],
    prefix: ['gobuster', 'dir', '-u {vars.scheme}://{target}'],
    suffix: '-o {workspace}/gobuster_dir.txt',
  },

  // gobuster vhost mode — used in vhost_fuzz fanout (sub.id = 'gobuster', cmd contains ' vhost ')
  gobuster_vhost: {
    desc: 'gobuster vhost — virtual host enumeration by fuzzing the Host header. Finds hidden sub-apps on the same IP.',
    categories: [
      { label: 'Wordlist', flags: [
        { key:'w', flag:'-w', type:'string', label:'Wordlist', default:'{vars.vhost_wordlist}',
          desc:'Subdomain wordlist. Each word becomes the Host header prefix tested.' },
        { key:'append-domain', flag:'--append-domain', type:'bool', label:'Append domain', default:true,
          desc:'Auto-append the target domain to each word (e.g. WORD.example.com). Required for most setups.' },
        { key:'domain', flag:'--domain', type:'string', label:'Override domain', placeholder:'example.com',
          desc:'Override the base domain appended to each word. Defaults to the -u target.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'el', flag:'--exclude-length', type:'number', label:'Filter size', unit:'bytes',
          desc:'Exclude responses of exactly this size — removes the default 404 page to reduce noise.' },
        { key:'s',  flag:'-s', type:'string', label:'Match codes', placeholder:'200,302',
          desc:'Only report responses with these HTTP status codes.' },
        { key:'b',  flag:'-b', type:'string', label:'Exclude codes', default:'404,400,302',
          desc:'Exclude responses with these status codes.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',            flag:'-t',            type:'number', label:'Threads',  default:'100', unit:'threads',
          desc:'Concurrent request threads. vhost scanning is lightweight — high thread counts are safe.', risk:'careful' },
        { key:'timeout',      flag:'--timeout',     type:'string', label:'Timeout',  default:'10s',
          desc:'Per-request HTTP timeout.' },
        { key:'random-agent', flag:'--random-agent',type:'bool',   label:'Random UA',
          desc:'Send a random User-Agent per request.' },
        { key:'k',            flag:'-k',            type:'bool',   label:'Skip TLS verify',
          desc:'Ignore certificate errors. Use when scanning over HTTP or with self-signed certs.' },
      ]},
      { label: 'Output', flags: [
        { key:'q',           flag:'-q',           type:'bool', label:'Quiet',       default:true, desc:'Suppress banner.' },
        { key:'no-progress', flag:'--no-progress',type:'bool', label:'No progress', default:true, desc:'Suppress live progress.' },
        { key:'no-error',    flag:'--no-error',   type:'bool', label:'No errors',   default:true, desc:'Suppress connection error messages.' },
      ]},
    ],
    prefix: ['gobuster', 'vhost', '-u http://{target}'],
    suffix: '-o {workspace}/gobuster_vhost.txt',
  },

  dirsearch: {
    desc: 'Recursive web path scanner with smart filtering, extension support and delay control — Python-based, good default wordlists',
    categories: [
      { label: 'Target & Wordlist', flags: [
        { key:'w', flag:'-w', type:'string', label:'Wordlist',   placeholder:'/app/wordlists/common.txt',
          desc:'Path to wordlist. If omitted, dirsearch uses its built-in database.' },
        { key:'e', flag:'-e', type:'string', label:'Extensions', placeholder:'php,asp,aspx,json,bak,config,xml',
          desc:'Comma-separated extensions to append to each word.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'x',            flag:'-x',             type:'string', label:'Exclude codes',  default:'400,404,403,429',
          desc:'HTTP status codes to exclude. Wildcards supported: 3xx hides all redirects.' },
        { key:'mc',           flag:'--mc',            type:'string', label:'Match codes',    placeholder:'200,301,302',
          desc:'Only show responses with these status codes.' },
        { key:'exclude-sizes',flag:'--exclude-sizes', type:'string', label:'Exclude sizes',  placeholder:'0,120',
          desc:'Comma-separated response sizes to exclude — filters identical blank/error pages.' },
        { key:'exclude-texts',flag:'--exclude-texts', type:'string', label:'Exclude text',   placeholder:'Not Found',
          desc:'Exclude responses whose body contains this string.' },
        { key:'min-response-size', flag:'--min-response-size', type:'number', label:'Min size', unit:'bytes',
          desc:'Skip responses smaller than this size (removes blank pages).' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',       flag:'-t',        type:'number', label:'Threads',   default:'25',  unit:'threads',
          desc:'Concurrent request threads.', risk:'careful' },
        { key:'timeout', flag:'--timeout', type:'number', label:'Timeout',   default:'10',  unit:'sec',
          desc:'Per-request HTTP timeout.' },
        { key:'delay',   flag:'--delay',   type:'number', label:'Delay',     unit:'sec',
          desc:'Seconds to wait between requests. Improves stealth at cost of speed.' },
        { key:'retries', flag:'--retries', type:'number', label:'Retries',   default:'2',
          desc:'Number of request retries on network failure.' },
        { key:'rate-limit', flag:'--rate-limit', type:'number', label:'Rate limit', unit:'req/s',
          desc:'Max requests per second. Override thread-based rate.', risk:'careful' },
      ]},
      { label: 'Behavior', flags: [
        { key:'recursive',       flag:'-r',              type:'bool', label:'Recursive',        risk:'careful',
          desc:'Recursively scan discovered directories. Exponential growth — use with depth limit.' },
        { key:'recursion-depth', flag:'--recursion-depth', type:'number', label:'Recursion depth', default:'3',
          desc:'Maximum recursion depth when -r is enabled.' },
        { key:'random-agent',    flag:'--random-agent',  type:'bool', label:'Random UA',  default:true,
          desc:'Send a random User-Agent per request.' },
        { key:'no-color',        flag:'--no-color',      type:'bool', label:'No color',   default:true,
          desc:'Disable ANSI color codes. Recommended for file output and log capture.' },
        { key:'follow-redirects',flag:'-R',              type:'bool', label:'Follow redirects',
          desc:'Follow HTTP redirects. Useful for finding content behind CMS login pages.' },
        { key:'headers',         flag:'-H',              type:'string', label:'Custom header', placeholder:'Authorization: Bearer TOKEN',
          desc:'Custom HTTP header added to all requests. Repeat for multiple headers.' },
      ]},
    ],
    prefix: ['dirsearch', '-u {vars.scheme}://{target}'],
    suffix: '-o {workspace}/dirsearch.txt',
  },

  fuzzuli: {
    desc: 'Fuzzes for backup and temporary files (*.bak, *.old, *.tar.gz) using URL patterns derived from known paths',
    categories: [
      { label: 'Mode', flags: [
        { key:'mt', flag:'-mt', type:'enum', label:'Match type', default:'all',
          options:[
            { value:'all',     label:'All',      desc:'Try all pattern types — most thorough' },
            { value:'backup',  label:'Backup',   desc:'Only .bak, .old, .copy patterns' },
            { value:'archive', label:'Archive',  desc:'Only .zip, .tar.gz, .tar.bz2 patterns' },
            { value:'config',  label:'Config',   desc:'Only .conf, .config, .env patterns' },
          ],
          desc:'Which pattern types to fuzz for. "all" covers backup files, archives, and config files.' },
      ]},
      { label: 'Performance', flags: [
        { key:'t',       flag:'-t',       type:'number', label:'Threads',  default:'50', unit:'threads',
          desc:'Concurrent request threads.', risk:'careful' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout',  default:'10', unit:'sec',
          desc:'Per-request HTTP timeout.' },
      ]},
      { label: 'Filtering', flags: [
        { key:'mc', flag:'-mc', type:'string', label:'Match codes', placeholder:'200,206',
          desc:'Only show responses with these HTTP status codes.' },
        { key:'fc', flag:'-fc', type:'string', label:'Filter codes', default:'404,403',
          desc:'Hide responses with these status codes.' },
        { key:'ms', flag:'-ms', type:'number', label:'Min size', unit:'bytes',
          desc:'Minimum response body size to report.' },
      ]},
    ],
    prefix: ['echo {vars.scheme}://{target} |', 'fuzzuli'],
    suffix: '> {workspace}/fuzzuli.txt 2>/dev/null || true',
  },

  // ── Parameter discovery ───────────────────────────────────────────────────

  arjun: {
    desc: 'HTTP parameter discovery — finds hidden GET/POST parameters using smart wordlists and differential response analysis',
    categories: [
      { label: 'Target', flags: [
        { key:'m', flag:'-m', type:'enum', label:'Method', default:'GET',
          options:[
            { value:'GET',  label:'GET',   desc:'Inject parameters in URL query string' },
            { value:'POST', label:'POST',  desc:'Inject parameters in request body' },
            { value:'JSON', label:'JSON',  desc:'Inject parameters in JSON body' },
            { value:'XML',  label:'XML',   desc:'Inject parameters in XML body' },
          ],
          desc:'HTTP method to use for parameter injection.' },
        { key:'w', flag:'-w', type:'string', label:'Wordlist', default:'{vars.param_wordlist}',
          desc:'Path to parameter name wordlist. Arjun includes a good built-in list.' },
        { key:'include', flag:'--include', type:'string', label:'Always include', placeholder:'token,csrf',
          desc:'Comma-separated parameters to always include in every request (e.g. CSRF tokens).' },
      ]},
      { label: 'Rate / Stability', flags: [
        { key:'rate-limit', flag:'--rate-limit', type:'number', label:'Rate limit', default:'20', unit:'req/s',
          desc:'Max requests per second. Too high triggers WAF blocks on param discovery.', risk:'careful' },
        { key:'stable', flag:'--stable', type:'bool', label:'Stable mode', default:true,
          desc:'Use conservative chunking — slower but more accurate on unstable targets.' },
        { key:'t',    flag:'-t',         type:'number', label:'Threads',    default:'5',  unit:'threads',
          desc:'Concurrent threads. Low default is intentional — too many requests flag WAFs.' },
        { key:'timeout', flag:'-T',      type:'number', label:'Timeout',    default:'15', unit:'sec',
          desc:'HTTP timeout per request batch.' },
        { key:'chunk-size', flag:'--chunk-size', type:'number', label:'Chunk size', default:'50',
          desc:'Number of parameters tested per request. Smaller = more accurate but slower.' },
      ]},
      { label: 'Output', flags: [
        { key:'oJ', flag:'-oJ', type:'bool', label:'JSON output', default:true, desc:'Write results in JSON format.' },
        { key:'q',  flag:'-q',  type:'bool', label:'Quiet',
          desc:'Suppress non-essential output. Only print found parameters.' },
      ]},
    ],
    prefix: ['arjun', '-i {workspace}/urls_params.txt'],
    suffix: '-oJ {workspace}/arjun.json 2>/dev/null || true; touch {workspace}/arjun.json',
  },

  x8: {
    desc: 'HTTP parameter discovery using wordlists with diff-based analysis — faster than Arjun for large URL lists',
    categories: [
      { label: 'Target', flags: [
        { key:'X', flag:'-X', type:'enum', label:'Method', default:'GET',
          options:[
            { value:'GET',   label:'GET',   desc:'Inject in URL query string' },
            { value:'POST',  label:'POST',  desc:'Inject in form body' },
            { value:'PATCH', label:'PATCH', desc:'Inject in PATCH body' },
          ],
          desc:'HTTP method for parameter injection.' },
        { key:'w', flag:'-w', type:'string', label:'Wordlist', default:'{vars.param_wordlist}',
          desc:'Parameter name wordlist path.' },
        { key:'headers', flag:'--headers', type:'string', label:'Custom headers', placeholder:'Authorization: Bearer TOKEN',
          desc:'Additional request headers, separated by newlines.' },
      ]},
      { label: 'Performance', flags: [
        { key:'c',       flag:'-c',       type:'number', label:'Concurrency', default:'1', unit:'workers',
          desc:'Number of concurrent tests per URL. Keep at 1 for accuracy on most targets.' },
        { key:'t',       flag:'-t',       type:'number', label:'Timeout',     default:'10', unit:'sec',
          desc:'HTTP request timeout.' },
        { key:'delay',   flag:'--delay',  type:'number', label:'Delay', unit:'ms',
          desc:'Milliseconds between requests. Adds stealth for WAF-sensitive targets.' },
        { key:'value-size', flag:'--value-size', type:'number', label:'Value size', default:'5',
          desc:'Length of random parameter values. Increase if the app filters short values.' },
      ]},
      { label: 'Output', flags: [
        { key:'output-format', flag:'--output-format', type:'enum', label:'Output format', default:'json',
          options:[
            { value:'json',  label:'JSON',  desc:'Structured JSON output' },
            { value:'curl',  label:'curl',  desc:'Reproduce finding as curl command' },
            { value:'table', label:'Table', desc:'Human-readable table' },
          ],
          desc:'Output format for discovered parameters.' },
        { key:'disable-progress-bar', flag:'--disable-progress-bar', type:'bool', label:'No progress bar', default:true,
          desc:'Disable the live progress indicator. Required for clean log capture.' },
      ]},
    ],
    prefix: ['x8', '-u "$url"'],
    suffix: '2>/dev/null >> {workspace}/x8.json; done || true; touch {workspace}/x8.json',
  },

  fallparams: {
    desc: 'Passive parameter discovery via Wayback Machine — extracts historically observed GET parameters without sending any requests to the target',
    categories: [
      { label: 'Options', flags: [
        { key:'c', flag:'-c', type:'bool', label:'Crawl related', default:true,
          desc:'Also crawl related domains found in the Wayback index.' },
        { key:'d', flag:'-d', type:'number', label:'Depth', default:'2',
          desc:'Depth of Wayback Machine URL traversal. Higher values find more params but take longer.' },
        { key:'r', flag:'-r', type:'bool', label:'Include robots',
          desc:'Include parameters found via robots.txt and sitemap.xml parsing.' },
        { key:'p', flag:'-p', type:'number', label:'Threads', unit:'threads',
          desc:'Concurrent workers for Wayback API requests.' },
      ]},
    ],
    prefix: ['fallparams', '-u "$url"'],
    suffix: '2>/dev/null >> {workspace}/fallparams.txt; done || true; touch {workspace}/fallparams.txt',
  },

  // nuclei_urls — same tool as nuclei, different input (crawled URL list instead of live hosts)
  nuclei_urls: {
    desc: 'nuclei scan against crawled URL surface (katana + gau + waybackurls) — finds param-based vulns, injection points, and endpoint-specific CVEs',
    categories: [
      { label: 'Templates', flags: [
        { key:'t',        flag:'-t',        type:'string', label:'Template path',   placeholder:'http/vulnerabilities',
          desc:'Specific template or directory to run. Default: all templates.' },
        { key:'tags',     flag:'-tags',     type:'string', label:'Include tags',    placeholder:'cve,xss,ssrf,sqli,rce,lfi',
          desc:'Run only templates matching these tags. For URL lists, xss/sqli/lfi are most relevant.' },
        { key:'etags',    flag:'-etags',    type:'string', label:'Exclude tags',    default:'dns',
          desc:'Skip templates with these tags. DNS tags are always excluded on URL inputs.', risk:'safe' },
        { key:'severity', flag:'-severity', type:'string', label:'Severity filter', placeholder:'medium,high,critical',
          desc:'Run only templates at these severity levels.' },
        { key:'es',       flag:'-es',       type:'string', label:'Exclude severity',default:'info',
          desc:'Skip templates at these severity levels. "info" is rarely actionable on URL scans.' },
      ]},
      { label: 'Rate & Concurrency', flags: [
        { key:'rl',      flag:'-rl',      type:'number', label:'Rate limit',  default:'100', unit:'req/s',
          desc:'Max HTTP requests per second. URL lists can be large — keep lower than host scans.', risk:'careful' },
        { key:'c',       flag:'-c',       type:'number', label:'Concurrency', default:'20',  unit:'templates',
          desc:'Number of templates running in parallel.' },
        { key:'timeout', flag:'-timeout', type:'number', label:'Timeout',     default:'8',   unit:'sec',
          desc:'Per-request timeout.' },
        { key:'retries', flag:'-retries', type:'number', label:'Retries',     default:'1',
          desc:'Retry count on connection failure.' },
      ]},
      { label: 'Behavior', flags: [
        { key:'headless', flag:'-headless', type:'bool', label:'Headless browser',
          desc:'Enable headless browser for DOM XSS templates. Very slow on large URL lists.', risk:'careful' },
        { key:'ni',       flag:'-ni',       type:'bool', label:'No interactsh',
          desc:'Disable out-of-band interactsh callbacks. Use on isolated/internal networks.' },
        { key:'proxy',    flag:'-proxy',    type:'string', label:'Proxy',   placeholder:'http://127.0.0.1:8080',
          desc:'Route all nuclei traffic through this proxy (e.g. Burp Suite).' },
      ]},
      { label: 'Output', flags: [
        { key:'jsonl',  flag:'-jsonl',  type:'bool', label:'JSONL output',   default:true, desc:'One JSON finding per line.' },
        { key:'silent', flag:'-silent', type:'bool', label:'Silent mode',    default:true, desc:'Suppress informational output.' },
        { key:'nmhe',   flag:'-nmhe',   type:'bool', label:'No meta header', default:true, desc:'No extra metadata headers in requests.' },
        { key:'stats',  flag:'-stats',  type:'bool', label:'Statistics',
          desc:'Print a live stats table. Useful for monitoring progress on large URL lists.' },
      ]},
    ],
    prefix: ['timeout 3600', 'nuclei', '-l {workspace}/urls_all.txt'],
    suffix: '-o {workspace}/nuclei_urls.jsonl 2>/dev/null || true; touch {workspace}/nuclei_urls.jsonl',
  },

  // swaggerspy — Python script for Swagger/OpenAPI spec discovery (disabled by default)
  swaggerspy: {
    desc: 'SwaggerSpy — discovers exposed Swagger/OpenAPI spec files on a target and extracts endpoint and parameter information',
    categories: [
      { label: 'Options', flags: [
        { key:'proxy', flag:'--proxy', type:'string', label:'Proxy', placeholder:'http://127.0.0.1:8080',
          desc:'Route requests through a proxy. Useful for inspecting SwaggerSpy\'s HTTP traffic in Burp.' },
        { key:'timeout', flag:'--timeout', type:'number', label:'Timeout', default:'10', unit:'sec',
          desc:'HTTP request timeout per path probe.' },
        { key:'threads', flag:'--threads', type:'number', label:'Threads', default:'10', unit:'threads',
          desc:'Concurrent request threads for path discovery.' },
        { key:'json', flag:'--json', type:'bool', label:'JSON output',
          desc:'Output results in JSON format instead of plain text.' },
      ]},
    ],
    prefix: ['python', '{vars.tools_root}/SwaggerSpy/swaggerspy.py', '{target}'],
    suffix: '> {workspace}/swaggerspy.txt 2>/dev/null || true',
  },
}

// ─── Generic flag parser (regex-based) ───────────────────────────────────────
function parseToolFlags(toolId, cmd) {
  const def  = TOOL_FLAGS[toolId]
  if (!def) return {}
  const result = {}
  for (const cat of def.categories) {
    for (const f of cat.flags) {
      if (!f.flag) continue                        // skip pseudo-flags (empty flag key)
      const esc = f.flag.replace(/[-]/g, '\\-')
      if (f.type === 'bool') {
        // (?=[\s;|]|$) — correctly matches flag at end-of-string
        const re = new RegExp(`(?:^|[\\s;|])${esc}(?=[\\s;|]|$)`)
        if (re.test(cmd)) result[f.key] = true
      } else {
        // Match "-flag value" or "-flag=value", capture up to next whitespace
        const re = new RegExp(`${esc}[= ]([^\\s]+)`)
        const m = cmd.match(re)
        if (m) result[f.key] = m[1]
      }
    }
  }
  return result
}

// ─── Build command from flag values ──────────────────────────────────────────
function buildToolCmd(toolId, flagValues) {
  const def = TOOL_FLAGS[toolId]
  if (!def) return ''
  const flagParts = []
  for (const cat of def.categories) {
    for (const f of cat.flags) {
      if (!f.flag) continue                        // skip pseudo-flags (empty flag key)
      const val = flagValues[f.key]
      if (val === undefined || val === false || val === '') continue
      if (f.type === 'bool') {
        flagParts.push(f.flag)
      } else {
        flagParts.push(`${f.flag} ${val}`)
      }
    }
  }
  const parts = [...def.prefix, ...flagParts]
  if (def.suffix) parts.push(def.suffix)
  return parts.join(' ')
}

// ─── CommandBuilder component ─────────────────────────────────────────────────
function CommandBuilder({ stepId, currentCmd, vars, onApply }) {
  const def = TOOL_FLAGS[stepId]
  const [flagValues, setFlagValues] = useState(() => {
    const defaults = {}
    if (def) {
      for (const cat of def.categories) {
        for (const f of cat.flags) {
          if (f.default !== undefined && f.default !== false) defaults[f.key] = f.default
        }
      }
    }
    return { ...defaults, ...parseToolFlags(stepId, currentCmd) }
  })
  const [openCat, setOpenCat] = useState(null)

  if (!def) {
    return (
      <div style={{ fontSize:10, color:'var(--text-3)', fontStyle:'italic', padding:'8px 0' }}>
        No flag catalog for <code style={{ color:'#f0b429' }}>{stepId}</code> yet.
        Use the raw command editor above.
      </div>
    )
  }

  function setFlag(key, val) {
    setFlagValues(prev => ({ ...prev, [key]: val }))
  }

  const preview = buildToolCmd(stepId, flagValues)

  return (
    <div style={{ marginTop: 0 }}>
      {/* Category tabs */}
      {def.categories.map(cat => {
        const isOpen = openCat === cat.label || (openCat === null && def.categories.indexOf(cat) === 0)
        const activeCount = cat.flags.filter(f => {
          const v = flagValues[f.key]
          return v !== undefined && v !== false && v !== ''
        }).length

        return (
          <div key={cat.label} style={{ marginBottom: 4 }}>
            <button onClick={() => setOpenCat(isOpen ? '__none__' : cat.label)}
              style={{
                width:'100%', textAlign:'left', background: isOpen ? 'var(--surface)' : 'var(--bg-soft)',
                border: `1px solid ${isOpen ? 'var(--border)' : 'var(--surface-2)'}`,
                borderRadius: isOpen ? '6px 6px 0 0' : 6,
                padding:'6px 10px', cursor:'pointer',
                display:'flex', alignItems:'center', justifyContent:'space-between',
              }}>
              <span style={{ fontSize:10, fontWeight:700, color: isOpen ? 'var(--text)' : 'var(--text-2)',
                letterSpacing:'.03em' }}>{cat.label}</span>
              <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                {activeCount > 0 && (
                  <span style={{ fontSize:8.5, color:'#58a6ff', background:'#0a1929',
                    border:'1px solid #58a6ff33', borderRadius:3, padding:'1px 5px' }}>
                    {activeCount} active
                  </span>
                )}
                <span style={{ fontSize:9, color:'var(--text-3)' }}>{isOpen ? '▲' : '▼'}</span>
              </div>
            </button>

            {isOpen && (
              <div style={{
                background:'var(--surface)', border:'1px solid #30363d', borderTop:'none',
                borderRadius:'0 0 6px 6px', padding:'8px 10px',
                display:'flex', flexDirection:'column', gap:7,
              }}>
                {cat.flags.map(f => {
                  const val    = flagValues[f.key]
                  const isOn   = val !== undefined && val !== false && val !== ''
                  const risk   = f.risk ? RISK_BADGE[f.risk] : null

                  return (
                    <div key={f.key}>
                      {/* Flag header */}
                      <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom: f.type==='bool' ? 0 : 4 }}>
                        {f.type === 'bool' ? (
                          <input type="checkbox"
                            checked={!!val}
                            onChange={e => setFlag(f.key, e.target.checked ? true : undefined)}
                            style={{ accentColor:'#58a6ff', width:12, height:12, flexShrink:0 }} />
                        ) : (
                          <div style={{ width:8, height:8, borderRadius:'50%', flexShrink:0,
                            background: isOn ? '#58a6ff' : 'var(--border)' }} />
                        )}
                        <span style={{ fontSize:9.5, fontWeight:700, color: isOn ? 'var(--text)' : 'var(--text-2)',
                          flex:1 }}>{f.label}</span>
                        <code style={{ fontSize:8.5, color:'var(--text-3)', fontFamily:'monospace' }}>{f.flag}</code>
                        {risk && (
                          <span style={{ fontSize:7.5, color:risk.color, border:`1px solid ${risk.border}`,
                            borderRadius:3, padding:'1px 4px', fontWeight:700 }}>{risk.label}</span>
                        )}
                      </div>
                      {/* Description */}
                      <div style={{ fontSize:9, color:'var(--text-3)', marginLeft:18, marginBottom: f.type!=='bool' ? 4 : 0,
                        lineHeight:1.5 }}>{f.desc}</div>
                      {/* Value input */}
                      {f.type === 'enum' && (
                        <select className="input" value={val ?? (f.options?.[0]?.value || '')}
                          onChange={e => setFlag(f.key, e.target.value)}
                          style={{ marginLeft:18, width:'calc(100% - 18px)', fontSize:9.5, padding:'3px 6px' }}>
                          {f.options?.map(o => (
                            <option key={o.value} value={o.value}>{o.label}{o.desc ? ` — ${o.desc}` : ''}</option>
                          ))}
                        </select>
                      )}
                      {(f.type === 'number' || f.type === 'string') && (
                        <input className="input"
                          type={f.type === 'number' ? 'number' : 'text'}
                          value={val ?? f.default ?? ''}
                          placeholder={f.placeholder || f.default || ''}
                          onChange={e => setFlag(f.key, e.target.value || undefined)}
                          style={{ marginLeft:18, width:'calc(100% - 18px)', fontSize:9.5, padding:'3px 6px',
                            fontFamily:'monospace', boxSizing:'border-box' }} />
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}

      {/* Apply button + preview */}
      <div style={{ marginTop: 8, padding:'8px 10px', background:'#0a1929',
        border:'1px solid #0d2d4a', borderRadius:6 }}>
        <div style={{ fontSize:8.5, color:'var(--text-3)', marginBottom:5, fontWeight:700,
          letterSpacing:'.06em', textTransform:'uppercase' }}>Preview</div>
        <div style={{ fontFamily:'monospace', fontSize:8.5, color:'#58a6ff99',
          wordBreak:'break-all', whiteSpace:'pre-wrap', lineHeight:1.6, marginBottom:8 }}>
          {preview}
        </div>
        <button
          onClick={() => onApply(preview)}
          style={{
            width:'100%', background:'#0a1929', border:'1px solid #58a6ff55',
            borderRadius:5, color:'#58a6ff', fontSize:10, fontWeight:700,
            padding:'5px 0', cursor:'pointer', letterSpacing:'.03em',
          }}>
          ◈ Apply to command
        </button>
      </div>
    </div>
  )
}

// ─── Templates ────────────────────────────────────────────────────────────────
const TEMPLATES = {
  'Quick Recon': {
    desc: 'Passive discovery + port scan + HTTP probe + nuclei',
    icon: '⚡',
    vars: { run_discovery:'true', run_portscan:'true', run_crawl:'false',
            run_screenshot:'false', run_deep_scan:'false', run_params:'false',
            run_nuclei:'true', run_afrog:'false', run_dirbrute:'false', run_vhost:'false' },
  },
  'Full Audit': {
    desc: 'Everything enabled — takes hours on large targets',
    icon: '🔥',
    vars: { run_discovery:'true', run_portscan:'true', run_crawl:'true',
            run_screenshot:'true', run_deep_scan:'false', run_params:'true',
            run_nuclei:'true', run_afrog:'true', run_dirbrute:'true', run_vhost:'true' },
  },
  'Passive Only': {
    desc: 'Discovery + DNS resolve — zero active noise',
    icon: '🥷',
    vars: { run_discovery:'true', run_portscan:'false', run_vhost:'false',
            run_crawl:'false', run_screenshot:'false', run_dirbrute:'false',
            run_nuclei:'false', run_afrog:'false', run_params:'false' },
  },
  'API Focus': {
    desc: 'Crawl + parameter discovery + kiterunner API routes',
    icon: '🔌',
    vars: { run_discovery:'true', run_portscan:'false', run_crawl:'true',
            run_params:'true', run_dirbrute:'true', run_nuclei:'true',
            run_afrog:'false', run_screenshot:'false', run_vhost:'false' },
  },
}

// ─── Layout algorithm (topological levels) ───────────────────────────────────
function computeLayout(steps) {
  if (!steps.length) return {}
  const levels = {}
  steps.forEach(s => { levels[s.id] = 0 })
  for (let iter = 0; iter < steps.length * 2; iter++) {
    steps.forEach(s => {
      ;(s.depends_on || []).forEach(dep => {
        if (levels[dep] != null)
          levels[s.id] = Math.max(levels[s.id], levels[dep] + 1)
      })
    })
  }
  const byLevel = {}
  steps.forEach(s => {
    const l = levels[s.id] ?? 0
    ;(byLevel[l] = byLevel[l] || []).push(s.id)
  })
  const NW = 230, NH = 95, GX = 80, GY = 18
  const maxRows = Math.max(...Object.values(byLevel).map(a => a.length))
  const pos = {}
  Object.entries(byLevel).forEach(([lStr, ids]) => {
    const l = parseInt(lStr)
    const totalH = ids.length * (NH + GY)
    const startY = (maxRows * (NH + GY) - totalH) / 2
    ids.forEach((id, i) => {
      pos[id] = { x: l * (NW + GX) + 32, y: startY + i * (NH + GY) + 32 }
    })
  })
  return pos
}

// ─── Evaluate when condition against vars ─────────────────────────────────────
function evalWhen(when, vars) {
  if (!when || when === 'true') return true
  if (when === 'false' || when === "'false'" || when === '"false"') return false
  const resolved = when.replace(/\{vars\.(\w+)\}/g, (_, k) => vars?.[k] ?? 'false')
  return resolved.split('&&').every(p => {
    const t = p.trim().replace(/['"]/g, '')
    return t === 'true' || t === '1'
  })
}

// ─── Resolve phase for a step (supports _phase for custom steps) ──────────────
function resolvePhase(step) {
  return STEP_PH[step.id] || step._phase || 'scan'
}

// ─── YAML workflow → React Flow graph ─────────────────────────────────────────
function wfToGraph(wf, savedPositions = {}, onDelete) {
  if (!wf?.steps) return { nodes: [], edges: [] }
  const topSteps = wf.steps
  const autoPos = computeLayout(topSteps)
  const nodes = [], edges = []
  topSteps.forEach(step => {
    const phase = resolvePhase(step)
    const ph = PH[phase]
    const isOn = evalWhen(step.when, wf.vars)
    nodes.push({
      id: step.id,
      type: 'stepNode',
      position: savedPositions[step.id] || autoPos[step.id] || { x: 0, y: 0 },
      data: { step, phase, ph, isOn, onDelete },
    })
    ;(step.depends_on || []).forEach(dep => {
      edges.push({
        id: `${dep}→${step.id}`,
        source: dep, target: step.id,
        type: 'smoothstep',
        style: { stroke: 'var(--border)', strokeWidth: 1.5 },
        markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--border)', width: 10, height: 10 },
      })
    })
  })
  return { nodes, edges }
}

// ─── React Flow → workflow steps ─────────────────────────────────────────────
function graphToSteps(nodes, edges, originalSteps) {
  const stepById = {}
  originalSteps.forEach(s => { stepById[s.id] = s })
  const depMap = {}
  edges.forEach(e => {
    ;(depMap[e.target] = depMap[e.target] || []).push(e.source)
  })
  const visited = new Set(), order = []
  function visit(id) {
    if (visited.has(id)) return
    visited.add(id)
    ;(depMap[id] || []).forEach(visit)
    order.push(id)
  }
  nodes.forEach(n => visit(n.id))
  const result = []
  order.forEach(id => {
    const { _phase, ...step } = { ...(stepById[id] || { id }) }
    step.depends_on = depMap[id] || []
    if (!step.depends_on.length) delete step.depends_on
    if (_phase) step._phase = _phase  // preserve for custom steps
    result.push(step)
  })
  return result
}

// ─── Custom StepNode ─────────────────────────────────────────────────────────
function StepNode({ data, selected }) {
  const { step, ph, isOn } = data
  const sc = data.liveStatus ? SC[data.liveStatus] : null
  const hasFanout = step.fanout?.length > 0

  return (
    <>
      <NodeToolbar isVisible={selected} position={Position.Top} style={{ padding: 0 }}>
        <button
          onClick={() => data.onDelete?.(step.id)}
          style={{
            background: '#1f0909', border: '1px solid #f8514966', borderRadius: 4,
            color: '#f85149', fontSize: 10, fontWeight: 700, padding: '3px 10px',
            cursor: 'pointer', letterSpacing: '.03em',
          }}>
          ✕ Delete Step
        </button>
      </NodeToolbar>

      <Handle type="target" position={Position.Left}
        style={{ background: 'var(--border)', border: 'none', width: 8, height: 8, left: -4 }} />
      <div style={{
        background: ph.bg, border: `1.5px solid ${selected ? ph.color : (sc ? sc.color : 'var(--surface-2)')}`,
        borderRadius: 8, padding: '8px 12px', minWidth: 230, minHeight: 80,
        opacity: isOn === false ? 0.38 : 1,
        boxShadow: sc?.glow ? `0 0 14px ${sc.color}55` : selected ? `0 0 0 2px ${ph.color}33` : 'none',
        transition: 'border-color .2s, box-shadow .2s, opacity .2s',
        cursor: 'pointer', userSelect: 'none',
      }}>
        {/* Header row */}
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom: 4 }}>
          <span style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: '.08em',
            color: ph.color, textTransform: 'uppercase' }}>
            {ph.icon} {ph.label}
          </span>
          <div style={{ display:'flex', alignItems:'center', gap: 5 }}>
            {!isOn && <span style={{ fontSize:8.5, color:'var(--text-3)', letterSpacing:'.05em' }}>DISABLED</span>}
            {sc && <span style={{ fontSize:11, color:sc.color,
              animation: sc.glow ? 'nodeGlow 1.4s ease-in-out infinite' : 'none' }}>{sc.icon}</span>}
          </div>
        </div>
        {/* Step ID */}
        <div style={{ fontSize:11.5, fontWeight:700, color:'var(--text)', fontFamily:'monospace', marginBottom:2 }}>
          {step.id}
        </div>
        {/* Name */}
        {step.name && (
          <div style={{ fontSize:10, color:'var(--text-2)', lineHeight:1.3,
            overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:206 }}>
            {step.name}
          </div>
        )}
        {/* Tags */}
        <div style={{ display:'flex', gap:4, marginTop:5, flexWrap:'wrap' }}>
          {step.optional && <NodeTag label="optional" c="var(--text-3)" />}
          {step.when && step.when !== 'true' && <NodeTag label="when" c={ph.color} />}
          {step.timeout && <NodeTag label={step.timeout} c="var(--text-3)" />}
          {hasFanout && <NodeTag label={`${step.fanout.length}× parallel`} c={ph.color} />}
          {step.skip_if_exists && <NodeTag label="resume" c="var(--text-3)" />}
          {(step.retries > 0 || step.retries === '1') && <NodeTag label={`retry×${step.retries}`} c="var(--text-3)" />}
        </div>
        {/* Fanout sub-steps */}
        {hasFanout && (
          <div style={{ marginTop:6, borderTop:'1px solid #21262d', paddingTop:4 }}>
            {step.fanout.map(sub => {
              const ss = data.fanoutStatus?.[sub.id]
              const ssc = ss ? SC[ss] : null
              return (
                <div key={sub.id} style={{
                  fontSize:9.5, color:'var(--text-2)', fontFamily:'monospace',
                  display:'flex', alignItems:'center', gap:5, padding:'1.5px 0',
                }}>
                  <span style={{ color:ssc?.color || 'var(--text-3)', fontSize:9 }}>{ssc?.icon || '○'}</span>
                  {sub.id}
                </div>
              )
            })}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Right}
        style={{ background: 'var(--border)', border: 'none', width: 8, height: 8, right: -4 }} />
    </>
  )
}

function NodeTag({ label, c }) {
  return (
    <span style={{ fontSize:7.5, color:c, border:`1px solid ${c}44`,
      borderRadius:3, padding:'0 3px', letterSpacing:'.04em', lineHeight:1.6 }}>
      {label}
    </span>
  )
}

const nodeTypes = { stepNode: StepNode }

// ─── Resolve effective TOOL_FLAGS key for a fanout sub-step ─────────────────
// Some sub-steps share the same id but run different modes (e.g. gobuster dir vs vhost).
// Parse mode from the current command to pick the right catalog entry.
function resolveSubStepId(subId, cmd) {
  if (subId === 'gobuster') {
    if (/\bgobuster\s+vhost\b/.test(cmd)) return 'gobuster_vhost'
    return 'gobuster'   // dir mode (default)
  }
  return subId
}

// ─── Fanout sub-step with per-step CommandBuilder ────────────────────────────
function FanoutSubStep({ sub, ph, vars, onChange }) {
  const [showBuilder, setShowBuilder] = useState(false)
  const resolvedId = resolveSubStepId(sub.id, sub.run || '')
  const hasDef = !!TOOL_FLAGS[resolvedId]
  return (
    <div style={{ marginBottom:8, background:'var(--surface)', borderRadius:6, border:'1px solid #21262d', overflow:'hidden' }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', gap:6, padding:'5px 10px',
        borderBottom:'1px solid #21262d', background:'var(--bg-soft)' }}>
        <span style={{ fontSize:10, fontWeight:700, color:ph.color, fontFamily:'monospace', flex:1 }}>{sub.id}</span>
        {hasDef && (
          <button onClick={() => setShowBuilder(p => !p)} style={{
            background: showBuilder ? '#0a1f0e' : 'none',
            border: `1px solid ${showBuilder ? '#3fb95044' : 'var(--border)'}`,
            borderRadius:4, color: showBuilder ? '#3fb950' : 'var(--text-3)',
            fontSize:8.5, padding:'1px 7px', cursor:'pointer', fontWeight:700,
          }}>⚙ Flags</button>
        )}
      </div>
      <div style={{ padding:'8px 10px' }}>
        {!showBuilder && (
          <textarea className="input" rows={3}
            value={sub.run || ''}
            style={{ fontFamily:'monospace', fontSize:9.5, resize:'vertical' }}
            onChange={e => onChange(e.target.value)} />
        )}
        {showBuilder && (
          <CommandBuilder
            stepId={resolvedId}
            currentCmd={sub.run || ''}
            vars={vars}
            onApply={cmd => { onChange(cmd); setShowBuilder(false) }}
          />
        )}
      </div>
    </div>
  )
}

// ── Annotated var row ─────────────────────────────────────────────────────────
function VarRow({ varKey, vars, onVarChange, ph }) {
  const [expanded, setExpanded] = useState(false)
    const val  = vars?.[varKey] ?? ''
    const doc  = VAR_DOCS[varKey]
    const risk = doc?.risk ? RISK_BADGE[doc.risk] : null

    const isBool  = doc?.type === 'bool'  || (val === 'true' || val === 'false')
    const isEnum  = doc?.type === 'enum'  && doc.options?.length
    const isPath  = doc?.type === 'path'
    const isNum   = !isBool && !isEnum && (doc?.type === 'number' || /^\d+$/.test(val))

    return (
      <div style={{
        marginBottom: 8, background: 'var(--bg-soft)',
        border: '1px solid #21262d', borderRadius: 7, overflow: 'hidden',
      }}>
        {/* ── Var header row ── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 10px', background: 'var(--surface)',
          borderBottom: '1px solid #21262d',
          cursor: doc?.detail ? 'pointer' : 'default',
        }} onClick={() => doc?.detail && setExpanded(p => !p)}>
          <span style={{ fontSize: 9, color: '#f0b429', fontFamily: 'monospace',
            fontWeight: 700, flex: 1 }}>{`{vars.${varKey}}`}</span>
          {risk && (
            <span style={{
              fontSize: 8, fontWeight: 700, letterSpacing: '.04em',
              color: risk.color, background: risk.bg,
              border: `1px solid ${risk.border}`,
              borderRadius: 3, padding: '1px 6px',
            }}>{risk.label}</span>
          )}
          {doc?.unit && (
            <span style={{ fontSize: 8.5, color: 'var(--text-3)' }}>{doc.unit}</span>
          )}
          {doc?.detail && (
            <span style={{ fontSize: 9, color: 'var(--text-3)' }}>{expanded ? '▲' : '▼'}</span>
          )}
        </div>

        <div style={{ padding: '7px 10px' }}>
          {/* ── Description ── */}
          {doc?.desc && (
            <div style={{ fontSize: 9.5, color: 'var(--text-2)', marginBottom: 6, lineHeight: 1.5 }}>
              {doc.desc}
            </div>
          )}

          {/* ── Input based on type ── */}
          {isBool ? (
            <label style={{ display:'flex', alignItems:'center', gap:8, cursor:'pointer', userSelect:'none' }}>
              <input type="checkbox" checked={val === 'true'}
                onChange={e => onVarChange?.(varKey, e.target.checked ? 'true' : 'false')}
                style={{ accentColor: ph.color, width:14, height:14 }} />
              <span style={{
                fontSize: 11, fontWeight: 700,
                color: val === 'true' ? '#3fb950' : 'var(--text-3)',
              }}>
                {val === 'true' ? '✓ enabled' : '○ disabled'}
              </span>
            </label>
          ) : isEnum ? (
            <select className="input" value={val}
              onChange={e => onVarChange?.(varKey, e.target.value)}
              style={{ fontFamily:'monospace', fontSize:10 }}>
              {doc.options.map(o => (
                <option key={o.value} value={o.value} title={o.desc}>{o.label} — {o.desc}</option>
              ))}
            </select>
          ) : (
            <input className="input"
              type={isNum ? 'number' : 'text'}
              value={val}
              onChange={e => onVarChange?.(varKey, e.target.value)}
              style={{ fontFamily:'monospace', fontSize:10, width:'100%', boxSizing:'border-box',
                padding:'4px 8px' }} />
          )}

          {/* ── Presets ── */}
          {!isBool && !isEnum && doc?.presets?.length > 0 && (
            <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginTop:5 }}>
              {doc.presets.map(p => (
                <button key={p.value} onClick={() => onVarChange?.(varKey, p.value)}
                  style={{
                    fontSize: 8.5, fontFamily:'monospace', cursor:'pointer',
                    background: val === p.value ? '#0a1929' : 'none',
                    border: `1px solid ${val === p.value ? '#58a6ff55' : 'var(--surface-2)'}`,
                    color: val === p.value ? '#58a6ff' : 'var(--text-3)',
                    borderRadius: 4, padding: '2px 7px',
                    transition: 'all .1s',
                  }}>
                  {p.label}
                </button>
              ))}
            </div>
          )}

          {/* ── Risk note ── */}
          {risk && doc.riskNote && (
            <div style={{ fontSize: 9, color: risk.color, marginTop: 5, lineHeight: 1.5,
              display: 'flex', gap: 4, alignItems: 'flex-start' }}>
              <span>⚠</span>
              <span>{doc.riskNote}</span>
            </div>
          )}

          {/* ── Expanded detail ── */}
          {expanded && doc?.detail && (
            <div style={{
              marginTop: 7, padding: '7px 10px',
              background: '#0a1929', border: '1px solid #0d2d4a',
              borderRadius: 5, fontSize: 9.5, color: 'var(--text-2)', lineHeight: 1.65,
            }}>
              {doc.detail}
            </div>
          )}
        </div>
      </div>
    )
}

// ── Section divider ───────────────────────────────────────────────────────────
function Section({ label, children, action }) {
  return (
    <div style={{ borderTop: '1px solid #21262d', paddingTop: 11 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
        marginBottom: 8 }}>
        <span style={{ fontSize: 8.5, color: 'var(--text-3)', fontWeight: 700,
          letterSpacing: '.08em', textTransform: 'uppercase' }}>{label}</span>
        {action}
      </div>
      {children}
    </div>
  )
}

// ─── Config Panel ─────────────────────────────────────────────────────────────
function ConfigPanel({ step, vars, onChange, onVarChange, onClose }) {
  const [showPreview, setShowPreview]   = useState(false)
  const [showRawCmd,  setShowRawCmd]    = useState(false)
  const [showBuilder, setShowBuilder]   = useState(false)
  const [copiedCmd,   setCopiedCmd]     = useState(false)

  if (!step) return null

  const phase = resolvePhase(step)
  const ph    = PH[phase]
  const run   = step.run || ''

  function set(key, val) { onChange({ ...step, [key]: val }) }

  // ── Smart param detection ────────────────────────────────────────────────────
  const usedVarKeys = [...new Set([...run.matchAll(/\{vars\.(\w+)\}/g)].map(m => m[1]))]
  const hasTarget   = run.includes('{target}')
  const hasWs       = run.includes('{workspace}')
  const stepRefs    = [...new Set([...run.matchAll(/\{steps\.(\w+)\.(\w+)\}/g)].map(m => `${m[1]}.${m[2]}`))]

  // ── Preview resolver ─────────────────────────────────────────────────────────
  function resolvePreview(cmd) {
    return cmd
      .replace(/\{vars\.(\w+)\}/g,          (_, k) => vars?.[k]  ?? `‹${k}›`)
      .replace(/\{steps\.(\w+)\.(\w+)\}/g,  (_, s, k) => `‹${s}.${k}›`)
      .replace(/\{target\}/g,                '‹target›')
      .replace(/\{workspace\}/g,             '/runs/…')
  }

  // ── Syntax-highlight run command ─────────────────────────────────────────────
  function highlightCmd(cmd) {
    const parts = cmd.split(/(\{[^}]+\})/g)
    return parts.map((p, i) => {
      if (/^\{vars\.\w+\}$/.test(p)) return <span key={i} style={{ color: '#f0b429' }}>{p}</span>
      if (p === '{target}')           return <span key={i} style={{ color: '#3fb950' }}>{p}</span>
      if (p === '{workspace}')        return <span key={i} style={{ color: '#a371f7' }}>{p}</span>
      if (/^\{steps\.\w+\.\w+\}$/.test(p)) return <span key={i} style={{ color: '#79c0ff' }}>{p}</span>
      return <span key={i} style={{ color: 'var(--text)' }}>{p}</span>
    })
  }

  function copyCmd() {
    navigator.clipboard.writeText(run)
    setCopiedCmd(true)
    setTimeout(() => setCopiedCmd(false), 1800)
  }

  return (
    <div style={{
      width: 320, borderLeft: '1px solid #30363d', background: 'var(--bg-soft)',
      display: 'flex', flexDirection: 'column', flexShrink: 0, overflowY: 'auto',
    }}>
      {/* ── Header ── */}
      <div style={{ padding: '12px 14px', borderBottom: '1px solid #21262d',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: `${ph.bg}`, flexShrink: 0,
      }}>
        <div>
          <div style={{ fontSize: 9, color: ph.color, fontWeight: 700,
            letterSpacing: '.07em', textTransform: 'uppercase', marginBottom: 3 }}>
            {ph.icon} {ph.label}
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', fontFamily: 'monospace', lineHeight: 1 }}>
            {step.id}
          </div>
          {step.name && step.name !== step.id && (
            <div style={{ fontSize: 10, color: 'var(--text-2)', marginTop: 3 }}>{step.name}</div>
          )}
        </div>
        <button onClick={onClose} style={{
          background: 'none', border: 'none', color: 'var(--text-2)',
          cursor: 'pointer', fontSize: 20, lineHeight: 1, padding: '0 2px',
        }}>×</button>
      </div>

      <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 0 }}>

        {/* ── Identity ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 11 }}>
          <Field label="Step ID">
            <input className="input" value={step.id || ''}
              onChange={e => set('id', e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: 10 }} />
          </Field>
          <Field label="Phase">
            <select className="input" value={step._phase || STEP_PH[step.id] || 'scan'}
              onChange={e => set('_phase', e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: 10 }}>
              {Object.entries(PH).map(([k, p]) => (
                <option key={k} value={k}>{p.icon} {p.label}</option>
              ))}
            </select>
          </Field>
        </div>
        <div style={{ marginBottom: 11 }}>
          <Field label="Display name">
            <input className="input" value={step.name || ''}
              onChange={e => set('name', e.target.value)} />
          </Field>
        </div>

        {/* ── Smart Parameters ── */}
        <Section label={`Parameters${usedVarKeys.length ? ` · ${usedVarKeys.length} vars` : ''}`}>
          {/* Special context vars: read-only info */}
          {(hasTarget || hasWs || stepRefs.length > 0) && (
            <div style={{ display:'flex', flexWrap:'wrap', gap:4, marginBottom: usedVarKeys.length ? 8 : 0 }}>
              {hasTarget && (
                <span title="Set when you click Run — pass a domain like example.com" style={{
                  fontSize: 9, fontFamily:'monospace', color:'#3fb950',
                  border:'1px solid #3fb95033', background:'#0a1f0e',
                  borderRadius:4, padding:'2px 7px', cursor:'help',
                }}>{'{target}'} <span style={{ color:'var(--text-3)' }}>run-time</span></span>
              )}
              {hasWs && (
                <span title="Auto-created output directory per run" style={{
                  fontSize: 9, fontFamily:'monospace', color:'#a371f7',
                  border:'1px solid #a371f733', background:'#150d26',
                  borderRadius:4, padding:'2px 7px', cursor:'help',
                }}>{'{workspace}'} <span style={{ color:'var(--text-3)' }}>auto</span></span>
              )}
              {stepRefs.map(ref => (
                <span key={ref} title={`Output from step: ${ref.split('.')[0]}`} style={{
                  fontSize: 9, fontFamily:'monospace', color:'#79c0ff',
                  border:'1px solid #79c0ff33', background:'#0a1929',
                  borderRadius:4, padding:'2px 7px', cursor:'help',
                }}>{'{' + ref + '}'} <span style={{ color:'var(--text-3)' }}>step</span></span>
              ))}
            </div>
          )}

          {/* Editable {vars.X} fields */}
          {usedVarKeys.length > 0 ? (
            <div style={{ background:'var(--surface)', borderRadius:6, padding:'8px 10px',
              border:'1px solid #21262d' }}>
              {usedVarKeys.map(k => <VarRow key={k} varKey={k} vars={vars} onVarChange={onVarChange} ph={ph} />)}
              <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 4, lineHeight: 1.5 }}>
                Changes apply globally to this workflow's vars.
                See all vars in the <strong style={{ color:'var(--text-2)' }}>Vars</strong> tab.
              </div>
            </div>
          ) : (
            <div style={{ fontSize: 10, color: 'var(--text-3)', fontStyle: 'italic' }}>
              No <code style={{ color:'#f0b429', fontSize:9 }}>{'{vars.X}'}</code> in this command
            </div>
          )}
        </Section>

        {/* ── Condition & Toggles ── */}
        <Section label="Behavior">
          <div style={{ marginBottom: 8 }}>
            <Field label="When condition" hint="{vars.run_nuclei}">
              <input className="input" value={step.when ?? ''}
                placeholder="true  (always run)"
                onChange={e => set('when', e.target.value || undefined)} />
            </Field>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:6, marginBottom:8 }}>
            {[
              ['optional',          '⊘ Optional — continue if this step fails'],
              ['skip_if_exists',    '⏭ Skip if output file already exists (resume)'],
              ['run_on_failed_deps','⚡ Run even if dependencies failed'],
            ].map(([k, label]) => (
              <label key={k} style={{ display:'flex', alignItems:'center', gap:7,
                cursor:'pointer', fontSize:10.5, color:'var(--text-2)', userSelect:'none' }}>
                <input type="checkbox" checked={!!step[k]}
                  onChange={e => set(k, e.target.checked || undefined)}
                  style={{ accentColor: ph.color, width:12, height:12, flexShrink:0 }} />
                {label}
              </label>
            ))}
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
            <Field label="Timeout">
              <input className="input" value={step.timeout || ''}
                placeholder="e.g. 30m"
                style={{ fontSize:10 }}
                onChange={e => set('timeout', e.target.value || undefined)} />
            </Field>
            <Field label="Retries">
              <input className="input" type="number" min={0} max={5}
                value={step.retries ?? 0}
                style={{ fontSize:10 }}
                onChange={e => set('retries', parseInt(e.target.value) || undefined)} />
            </Field>
          </div>
        </Section>

        {/* ── Run Command ── */}
        <Section label="Run Command"
          action={
            <div style={{ display:'flex', gap:4 }}>
              <button onClick={() => setShowPreview(p => !p)} style={{
                background: showPreview ? 'var(--surface-2)' : 'none',
                border: `1px solid ${showPreview ? '#58a6ff44' : 'var(--border)'}`,
                borderRadius:4, color: showPreview ? '#58a6ff' : 'var(--text-2)',
                fontSize:9, padding:'2px 7px', cursor:'pointer', fontWeight:700,
              }}>◉ Preview</button>
              <button onClick={() => { setShowRawCmd(p => !p); setShowBuilder(false) }} style={{
                background: showRawCmd ? 'var(--surface-2)' : 'none',
                border: `1px solid ${showRawCmd ? '#a371f744' : 'var(--border)'}`,
                borderRadius:4, color: showRawCmd ? '#a371f7' : 'var(--text-2)',
                fontSize:9, padding:'2px 7px', cursor:'pointer', fontWeight:700,
              }}>⌨ Edit</button>
              {TOOL_FLAGS[step.id] && (
                <button onClick={() => { setShowBuilder(p => !p); setShowRawCmd(false) }} style={{
                  background: showBuilder ? 'var(--surface-2)' : 'none',
                  border: `1px solid ${showBuilder ? '#3fb95044' : 'var(--border)'}`,
                  borderRadius:4, color: showBuilder ? '#3fb950' : 'var(--text-2)',
                  fontSize:9, padding:'2px 7px', cursor:'pointer', fontWeight:700,
                }}>⚙ Flags</button>
              )}
              <button onClick={copyCmd} style={{
                background:'none', border:'1px solid #30363d',
                borderRadius:4, color: copiedCmd ? '#3fb950' : 'var(--text-2)',
                fontSize:9, padding:'2px 7px', cursor:'pointer',
              }}>{copiedCmd ? '✓' : '⎘'}</button>
            </div>
          }>

          {/* Syntax-highlighted display */}
          {!showRawCmd && (
            <div style={{
              background:'var(--surface)', border:'1px solid #21262d', borderRadius:6,
              padding:'8px 10px', fontFamily:'monospace', fontSize:9.5, lineHeight:1.65,
              wordBreak:'break-all', whiteSpace:'pre-wrap', color:'var(--text-2)',
              maxHeight:140, overflowY:'auto',
            }}>
              {run ? highlightCmd(run) : <span style={{ color:'var(--text-3)', fontStyle:'italic' }}>no command</span>}
            </div>
          )}

          {/* Raw edit textarea */}
          {showRawCmd && (
            <textarea className="input" rows={6}
              value={run}
              style={{ fontFamily:'monospace', fontSize:9.5, resize:'vertical', lineHeight:1.6 }}
              onChange={e => set('run', e.target.value)} />
          )}

          {/* Resolved preview */}
          {showPreview && (
            <div style={{ marginTop:6 }}>
              <div style={{ fontSize:8.5, color:'var(--text-3)', marginBottom:4, fontWeight:700,
                letterSpacing:'.06em', textTransform:'uppercase' }}>
                Resolved preview
              </div>
              <div style={{
                background:'#0a1929', border:'1px solid #0d2d4a', borderRadius:6,
                padding:'8px 10px', fontFamily:'monospace', fontSize:9, lineHeight:1.65,
                wordBreak:'break-all', whiteSpace:'pre-wrap', color:'#58a6ff99',
                maxHeight:120, overflowY:'auto',
              }}>
                {resolvePreview(run) || <span style={{ color:'var(--text-3)' }}>—</span>}
              </div>
            </div>
          )}

          {/* Flag builder */}
          {showBuilder && (
            <div style={{ marginTop:8 }}>
              <div style={{ fontSize:8.5, color:'#3fb950', marginBottom:6, fontWeight:700,
                letterSpacing:'.06em', textTransform:'uppercase' }}>
                Flag Builder — {step.id}
              </div>
              <CommandBuilder
                stepId={step.id}
                currentCmd={run}
                vars={vars}
                onApply={cmd => { set('run', cmd); setShowBuilder(false) }}
              />
            </div>
          )}
        </Section>

        {/* ── Fanout ── */}
        {step.fanout?.length > 0 && (
          <Section label={`Fanout — ${step.fanout.length}× parallel`}>
            {step.fanout.map((sub, i) => (
              <FanoutSubStep key={sub.id} sub={sub} ph={ph} vars={vars}
                onChange={newRun => {
                  const fanout = step.fanout.map((s, j) => j === i ? { ...s, run: newRun } : s)
                  set('fanout', fanout)
                }} />
            ))}
          </Section>
        )}

        {/* ── Depends on ── */}
        {step.depends_on?.length > 0 && (
          <Section label="Depends on">
            <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
              {step.depends_on.map(d => (
                <span key={d} style={{
                  fontSize:10, color:'#79c0ff', background:'#0a1929',
                  border:'1px solid #0d2d4a', borderRadius:4,
                  padding:'1px 7px', fontFamily:'monospace',
                }}>{d}</span>
              ))}
            </div>
          </Section>
        )}

        <div style={{ height: 20 }} />
      </div>
    </div>
  )
}

function Field({ label, hint, children }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: 'var(--text-2)', fontWeight: 700,
        letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 4,
        display: 'flex', gap: 6 }}>
        {label}
        {hint && <span style={{ fontWeight:400, textTransform:'none', color:'var(--text-3)',
          fontFamily:'monospace' }}>{hint}</span>}
      </div>
      {children}
    </div>
  )
}

// ─── Vars Panel ───────────────────────────────────────────────────────────────
function VarsPanel({ vars, onChange }) {
  const [newKey, setNewKey] = useState('')
  const [newVal, setNewVal] = useState('')
  if (!vars) return null

  // Groups cover vars from both workflow YAMLs.
  // Keys absent from the currently-loaded workflow are silently filtered out.
  const VAR_GROUPS = {
    // 01-full-recon-pipeline: run_passive, run_permutation, run_tlsx
    // 02-js-secrets-recon:    run_archive, run_linkfinder, run_jsubfinder, run_secretfinder, run_static_secrets, run_nuclei_js, run_gf, run_dirbrute
    // 03-param-discovery:     run_gau, run_paramspider, run_katana, run_arjun, run_x8, run_ffuf_params, run_nuclei_params
    // k1nzr3con:              run_discovery, run_deep_scan, run_vhost, run_params, run_dirbrute
    'Phase Toggles': [
      'run_passive','run_waymore','run_asn',
      'run_permutation','run_tlsx',
      'run_portscan','run_asn_portscan','run_deep_portscan',
      'run_screenshot','run_st_pivot_scan','run_cdncheck','run_crawl',
      'run_js_analysis','run_takeover','run_s3scan',
      'run_nuclei','run_afrog',
      'run_discovery','run_deep_scan','run_vhost','run_params','run_dirbrute',
      'run_archive','run_linkfinder','run_jsubfinder','run_secretfinder','run_static_secrets','run_nuclei_js','run_gf',
      'run_gau','run_paramspider','run_katana','run_arjun','run_x8','run_ffuf_params','run_nuclei_params',
    ],
    'Auth': [
      'session_cookie','auth_header','custom_header',
    ],
    'DNS & Discovery': [
      'dns_resolvers','doh_resolvers','dnsx_threads','doh_threads','dnsx_retry',
      'chaos_key','subdomains_list',
    ],
    'Port Scan': [
      'naabu_rate','naabu_top_ports',
      'rustscan_batch','rustscan_timeout_ms','rustscan_tries',
      'nmap_flags','nmap_tcp_flags','nmap_udp_flags',
    ],
    'HTTP & Crawl': [
      'httpx_threads','httpx_timeout','httpx_bin',
      'screenshot_threads','scheme',
      'katana_depth','katana_concurrency','katana_crawl_timeout','katana_timeout',
      'ffuf_filter_size','ffuf_threads',
    ],
    'Vuln Scan': [
      'nuclei_rl','nuclei_concurrency','nuclei_timeout',
    ],
    'Wordlists & Params': [
      'vhost_wordlist','dir_wordlist',
      'param_wordlist','param_wordlist_large','kr_wordlist',
      'wordlists','gobuster_threads','gobuster_timeout',
      'arjun_rate','arjun_threads','method',
      'dirsearch_threads','ferox_threads','x8_threads',
    ],
    'Paths & Misc': [
      'org_name','scripts_dir','oneforall_cmd','subzy_bin',
      'tools_root',
    ],
    'Other': null,
  }

  const grouped = {}
  const assigned = new Set()
  Object.entries(VAR_GROUPS).forEach(([group, keys]) => {
    if (keys) {
      grouped[group] = keys.filter(k => k in vars)
      keys.forEach(k => assigned.add(k))
    }
  })
  const others = Object.keys(vars).filter(k => !assigned.has(k))
  if (others.length) grouped['Other'] = others

  const addVar = () => {
    const k = newKey.trim()
    if (!k || k in vars) return
    onChange(k, newVal.trim() || 'true')
    setNewKey('')
    setNewVal('')
  }

  return (
    <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 18 }}>
      {Object.entries(grouped).map(([group, keys]) =>
        !keys || keys.length === 0 ? null : (
          <div key={group}>
            {/* Group header */}
            <div style={{ fontSize: 9, color: 'var(--text-3)', fontWeight: 700,
              letterSpacing: '.08em', textTransform: 'uppercase',
              borderBottom: '1px solid #21262d', paddingBottom: 5, marginBottom: 8 }}>
              {group}
            </div>

            {/* Toggle vars — compact 2-col grid */}
            {keys.some(k => ['true','false'].includes(String(vars[k]))) && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 8px', marginBottom: 4 }}>
                {keys.filter(k => ['true','false'].includes(String(vars[k]))).map(k => (
                  <label key={k} style={{ display:'flex', alignItems:'center', gap:6,
                    cursor:'pointer', userSelect:'none', padding: '3px 0' }}>
                    <input type="checkbox" checked={vars[k] === 'true'}
                      onChange={e => onChange(k, e.target.checked ? 'true' : 'false')}
                      style={{ accentColor: '#58a6ff', width:13, height:13, flexShrink:0 }} />
                    <span style={{ fontSize:10, color: vars[k]==='true' ? 'var(--text)' : 'var(--text-3)',
                      fontFamily:'monospace', lineHeight:1.3 }} title={k}>
                      {k.replace(/^run_/, '')}
                    </span>
                  </label>
                ))}
              </div>
            )}

            {/* Text vars — stacked (label top, full-width input below) */}
            {keys.filter(k => !['true','false'].includes(String(vars[k]))).map(k => (
              <div key={k} style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 9, color: 'var(--text-2)', fontFamily:'monospace',
                  marginBottom: 3, letterSpacing: '.02em' }}>
                  {k}
                </div>
                <input
                  className="input"
                  value={vars[k]}
                  title={vars[k]}
                  onChange={e => onChange(k, e.target.value)}
                  style={{ width: '100%', fontSize: 11, fontFamily:'monospace',
                    padding:'4px 8px', boxSizing:'border-box' }}
                />
              </div>
            ))}
          </div>
        )
      )}

      {/* Add new var */}
      <div style={{ borderTop: '1px solid #21262d', paddingTop: 12 }}>
        <div style={{ fontSize: 9, color: 'var(--text-3)', fontWeight: 700,
          letterSpacing: '.08em', textTransform: 'uppercase', marginBottom: 8 }}>
          Add Variable
        </div>
        <div style={{ display: 'flex', flexDirection:'column', gap: 5 }}>
          <input className="input" placeholder="var_name"
            value={newKey} onChange={e => setNewKey(e.target.value)}
            style={{ fontFamily: 'monospace', fontSize: 11, width:'100%', boxSizing:'border-box' }}
            onKeyDown={e => { if (e.key === 'Enter') document.getElementById('vars-add-val')?.focus() }}
          />
          <div style={{ display:'flex', gap:5 }}>
            <input id="vars-add-val" className="input" placeholder="value (default: true)"
              value={newVal} onChange={e => setNewVal(e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: 11, flex:1 }}
              onKeyDown={e => { if (e.key === 'Enter') addVar() }}
            />
            <button className="btn" style={{ fontSize: 11, padding: '0 10px', flexShrink: 0 }}
              disabled={!newKey.trim() || newKey.trim() in vars}
              onClick={addVar}>
              +
            </button>
          </div>
          {newKey.trim() && newKey.trim() in vars && (
            <span style={{ fontSize:9, color:'#f85149' }}>Key already exists</span>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Run Modal ────────────────────────────────────────────────────────────────
function RunModal({ workflowName, onClose }) {
  const [raw, setRaw]           = useState('')
  const [extraVars, setExtraVars] = useState('')
  const [loading, setLoading]   = useState(false)
  const [progress, setProgress] = useState(null)
  const navigate = useNavigate()

  const targets  = useMemo(() => parseTargetList(raw), [raw])
  const isBatch  = targets.length > 1
  const overLimit = targets.length > MAX_BATCH
  const isMulti  = raw.includes('\n') || raw.includes(',') || /\/\d+/.test(raw)

  async function submit() {
    if (!targets.length || overLimit) return
    const varsList = extraVars.trim() ? extraVars.trim().split(/\s+/).filter(Boolean) : []
    setLoading(true)

    if (!isBatch) {
      try {
        const run = await api.createRun({ workflow: workflowName, target: targets[0], vars: varsList })
        onClose()
        navigate(`/runs/${run.id}`)
      } catch {
        setLoading(false)
      }
      return
    }

    // Batch: create one run per target, show progress, navigate to runs list
    setProgress({ done: 0, total: targets.length, errors: 0 })
    let errors = 0
    for (let i = 0; i < targets.length; i++) {
      try {
        await api.createRun({ workflow: workflowName, target: targets[i], vars: varsList })
      } catch {
        errors++
      }
      setProgress({ done: i + 1, total: targets.length, errors })
    }
    onClose()
    navigate('/runs')
  }

  const badgeColor = overLimit ? '#f85149' : isBatch ? '#f0b429' : '#3fb950'

  return (
    <div style={{
      position:'fixed', inset:0, zIndex:1000,
      background:'rgba(0,0,0,.7)', backdropFilter:'blur(4px)',
      display:'flex', alignItems:'center', justifyContent:'center',
    }}>
      <div style={{
        background:'var(--surface)', border:'1px solid #30363d', borderRadius:10,
        padding:24, width:460, display:'flex', flexDirection:'column', gap:16,
        boxShadow:'0 20px 60px rgba(0,0,0,.6)',
      }}>
        {/* Header */}
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div>
            <div style={{ fontSize:11, color:'#58a6ff', fontWeight:700,
              letterSpacing:'.06em', textTransform:'uppercase', marginBottom:2 }}>▶ Launch Run</div>
            <div style={{ fontSize:13, color:'var(--text)', fontFamily:'monospace' }}>{workflowName}</div>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none',
            color:'var(--text-2)', cursor:'pointer', fontSize:18 }}>×</button>
        </div>

        {/* Target input */}
        <div>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
            <label className="label" style={{ margin:0 }}>Target</label>
            {targets.length > 0 && (
              <span style={{ fontSize:9, color: badgeColor, fontWeight:700, fontFamily:'monospace' }}>
                {overLimit
                  ? `⚠ ${targets.length} — max ${MAX_BATCH}`
                  : isBatch ? `${targets.length} targets → batch`
                  : '1 target'}
              </span>
            )}
          </div>
          <textarea className="input"
            rows={isMulti ? 5 : 2}
            placeholder={'example.com\n192.168.1.0/24\ntest.org  — one per line, CIDR ok'}
            value={raw}
            onChange={e => setRaw(e.target.value)}
            style={{ fontFamily:'monospace', fontSize:10, resize:'vertical', lineHeight:1.6 }}
            autoFocus />
          {/* Target preview chips */}
          {isBatch && !overLimit && (
            <div style={{ marginTop:5, lineHeight:1.8 }}>
              {targets.slice(0, 8).map(t => (
                <span key={t} style={{
                  display:'inline-block', marginRight:4, marginBottom:2,
                  fontFamily:'monospace', fontSize:9, color:'#58a6ff',
                  background:'#0a1929', border:'1px solid #0d2d4a',
                  borderRadius:3, padding:'1px 6px',
                }}>{t}</span>
              ))}
              {targets.length > 8 && (
                <span style={{ fontSize:9, color:'var(--text-3)' }}>+{targets.length - 8} more</span>
              )}
            </div>
          )}
          {overLimit && (
            <div style={{ marginTop:5, fontSize:9, color:'#f85149' }}>
              Too many targets. Split into smaller batches (max {MAX_BATCH} per run).
            </div>
          )}
        </div>

        {/* Override vars */}
        <div>
          <label className="label">Override vars <span style={{ fontWeight:400, color:'var(--text-3)' }}>key=value …</span></label>
          <input className="input" placeholder="run_afrog=true naabu_top_ports=full"
            value={extraVars} onChange={e => setExtraVars(e.target.value)} />
        </div>

        {/* Batch progress bar */}
        {progress && (
          <div>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
              <span style={{ fontSize:9, color:'var(--text-2)', fontFamily:'monospace' }}>
                Creating runs… {progress.done}/{progress.total}
              </span>
              {progress.errors > 0 && (
                <span style={{ fontSize:9, color:'#f85149', fontFamily:'monospace' }}>
                  {progress.errors} failed
                </span>
              )}
            </div>
            <div style={{ background:'var(--surface-2)', borderRadius:4, height:5, overflow:'hidden' }}>
              <div style={{
                height:'100%', borderRadius:4,
                background: progress.errors > 0 ? '#f85149' : '#3fb950',
                width:`${(progress.done / progress.total) * 100}%`,
                transition:'width .15s',
              }} />
            </div>
          </div>
        )}

        {/* Buttons */}
        <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
          <button className="btn btn-ghost" onClick={onClose} disabled={loading}>Cancel</button>
          <button className="btn btn-primary" onClick={submit}
            disabled={loading || !targets.length || overLimit}>
            {loading && progress
              ? `Creating… ${progress.done}/${progress.total}`
              : loading ? 'Starting…'
              : isBatch ? `▶ Run ${targets.length} targets`
              : '▶ Run'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── YAML Viewer Modal ────────────────────────────────────────────────────────
function YamlModal({ wf, wfName, nodes, edges, onClose, onSave, saving }) {
  const [copied, setCopied] = useState(false)
  const [tab, setTab] = useState('live')
  const [fileYaml, setFileYaml] = useState(null)
  const [fileLoading, setFileLoading] = useState(false)
  const [fileError, setFileError] = useState('')

  const updatedSteps = graphToSteps(nodes, edges, wf?.steps || [])
  const payload = wf ? { ...wf, steps: updatedSteps } : {}
  const liveYaml = yaml.dump(payload, { indent: 2, lineWidth: -1, noRefs: true, sortKeys: false })

  const yamlText = tab === 'file' ? (fileYaml || '') : liveYaml

  useEffect(() => {
    if (tab !== 'file' || fileYaml !== null) return
    setFileLoading(true)
    setFileError('')
    api.getWorkflow(wfName)
      .then(data => {
        setFileYaml(yaml.dump(data, { indent: 2, lineWidth: -1, noRefs: true, sortKeys: false }))
      }).catch(e => {
        setFileError(e.message || 'Failed to load file')
      }).finally(() => setFileLoading(false))
  }, [tab, wfName, fileYaml])

  function handleCopy() {
    navigator.clipboard.writeText(yamlText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Minimal syntax highlight: color YAML keys, strings, booleans, template vars
  function highlight(text) {
    return text.split('\n').map((line, i) => {
      // Comment
      if (line.trim().startsWith('#')) {
        return <div key={i} style={{ color: 'var(--text-3)' }}>{line}</div>
      }
      // Key: value line
      const keyMatch = line.match(/^(\s*)([\w_-]+)(:)(.*)$/)
      if (keyMatch) {
        const [, indent, key, colon, rest] = keyMatch
        return (
          <div key={i}>
            <span style={{ color: 'var(--text-2)' }}>{indent}</span>
            <span style={{ color: '#79c0ff' }}>{key}</span>
            <span style={{ color: 'var(--border)' }}>{colon}</span>
            <span>{colorValue(rest)}</span>
          </div>
        )
      }
      // List item
      const listMatch = line.match(/^(\s*)(-)(\s+)(.*)$/)
      if (listMatch) {
        const [, indent, dash, sp, rest] = listMatch
        return (
          <div key={i}>
            <span style={{ color: 'var(--text-3)' }}>{indent}{dash}{sp}</span>
            <span>{colorValue(rest)}</span>
          </div>
        )
      }
      return <div key={i} style={{ color: 'var(--text)' }}>{line || ' '}</div>
    })
  }

  function colorValue(v) {
    const s = v.trim()
    if (s === 'true' || s === 'false') return <span style={{ color: '#f0b429' }}>{v}</span>
    if (/^\d+$/.test(s)) return <span style={{ color: '#79c0ff' }}>{v}</span>
    if (s === '|' || s === '|-' || s === '>' || s === '>-') return <span style={{ color: '#a371f7' }}>{v}</span>
    // Highlight {vars.x} patterns in the value
    const parts = v.split(/(\{vars\.\w+\}|\{target\}|\{workspace\}|\{[^}]+\})/g)
    if (parts.length > 1) {
      return parts.map((p, i) =>
        /^\{[^}]+\}$/.test(p)
          ? <span key={i} style={{ color: '#f0b429' }}>{p}</span>
          : <span key={i} style={{ color: '#3fb950' }}>{p}</span>
      )
    }
    return <span style={{ color: s ? '#3fb950' : 'var(--text)' }}>{v}</span>
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,.8)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: 'var(--bg-soft)', border: '1px solid #30363d', borderRadius: 10,
        width: '72vw', maxWidth: 900, height: '82vh',
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 24px 80px rgba(0,0,0,.7)',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 16px', borderBottom: '1px solid #30363d', flexShrink: 0,
        }}>
          <span style={{ fontSize: 14, color: '#a371f7', fontWeight: 700 }}>{ }</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text)', letterSpacing: '.04em' }}>
              Workflow YAML
            </div>
            <div style={{ fontSize: 9.5, color: 'var(--text-2)' }}>
              {tab === 'live' ? 'State hiện tại trên canvas (có thể chưa lưu)' : `File trên disk: ${wfName}`}
            </div>
          </div>
          {/* Tab switcher */}
          <div style={{ display: 'flex', gap: 0, marginLeft: 14, background: 'var(--surface)', border: '1px solid #30363d', borderRadius: 6, overflow: 'hidden' }}>
            {[['live', '⬡ Live'], ['file', '◈ File']].map(([t, label]) => (
              <button key={t} onClick={() => setTab(t)} style={{
                background: tab === t ? 'var(--surface-2)' : 'none',
                border: 'none', borderRight: t === 'live' ? '1px solid #30363d' : 'none',
                color: tab === t ? 'var(--text)' : 'var(--text-2)',
                fontSize: 10, fontWeight: tab === t ? 700 : 400,
                padding: '4px 12px', cursor: 'pointer',
              }}>{label}</button>
            ))}
          </div>
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ fontSize: 9.5, color: 'var(--text-3)' }}>
              {tab === 'live' ? `${updatedSteps.length} steps · ` : ''}{yamlText.split('\n').length} lines
            </span>
            <button className="btn" style={{ fontSize: 11 }} onClick={handleCopy}>
              {copied ? '✓ Copied!' : '⎘ Copy'}
            </button>
            <button className="btn btn-primary" style={{ fontSize: 11 }}
              onClick={() => { setFileYaml(null); onSave() }} disabled={saving}>
              {saving ? '⌛ Saving…' : '💾 Save'}
            </button>
            <button onClick={onClose} style={{
              background: 'none', border: 'none', color: 'var(--text-2)',
              cursor: 'pointer', fontSize: 20, lineHeight: 1, padding: '0 4px',
            }}>×</button>
          </div>
        </div>

        {/* YAML content */}
        <div style={{
          flex: 1, overflowY: 'auto', padding: '16px 20px',
          fontFamily: 'monospace', fontSize: 11.5, lineHeight: 1.7,
          color: 'var(--text)', letterSpacing: '.01em',
        }}>
          {tab === 'file' && fileLoading && (
            <div style={{ color: 'var(--text-2)', textAlign: 'center', paddingTop: 40 }}>
              Loading file from disk…
            </div>
          )}
          {tab === 'file' && fileError && (
            <div style={{ color: '#f85149', padding: '8px 12px', background: '#1f0909', borderRadius: 6 }}>
              ✕ {fileError}
            </div>
          )}
          {(!fileLoading && !fileError && yamlText) && highlight(yamlText)}
        </div>
      </div>
    </div>
  )
}

// ─── Help / Usage Guide Modal ─────────────────────────────────────────────────
function HelpModal({ onClose }) {
  const [tab, setTab] = useState('guide')

  const SHORTCUTS = [
    { key: 'Ctrl+S',         desc: 'Save workflow to disk' },
    { key: 'Delete / Backspace', desc: 'Delete selected node(s)' },
    { key: 'Ctrl+Z',         desc: 'Undo (React Flow native)' },
    { key: 'Ctrl+Scroll',    desc: 'Zoom in/out on canvas' },
    { key: 'Space + Drag',   desc: 'Pan the canvas' },
    { key: 'Click node',     desc: 'Open config panel on the right' },
    { key: 'Shift+Click',    desc: 'Multi-select nodes' },
  ]

  const VARS = [
    { v: '{target}',         desc: 'Target domain passed at run time (e.g. example.com)' },
    { v: '{workspace}',      desc: 'Per-run output directory — all tool output goes here' },
    { v: '{vars.KEY}',       desc: 'Any variable defined in the vars section' },
    { v: '{vars.dns_resolvers}', desc: 'Path to resolvers file (built-in default)' },
    { v: '{vars.dir_wordlist}',  desc: 'Directory brute-force wordlist path' },
    { v: '{vars.kr_wordlist}',   desc: 'Kiterunner API routes wordlist' },
  ]

  const TIPS = [
    { icon: '→', title: 'Connect steps', body: 'Drag from the right handle of one node to the left handle of another. This creates a dependency edge (step A must finish before step B runs).' },
    { icon: '⊘', title: 'Conditional steps', body: 'Set a "When condition" like {vars.run_nuclei} in the config panel. The node will appear dimmed when the condition evaluates to false.' },
    { icon: '↺', title: 'Auto Layout', body: 'Click "↺ Auto Layout" in the toolbar to snap all nodes back to a clean DAG layout based on their dependency order.' },
    { icon: '⚡', title: 'Templates / Presets', body: 'Use the Presets tab to quickly toggle entire phases (Quick Recon, Full Audit, Passive Only, API Focus). Variables are updated immediately and nodes re-evaluate.' },
    { icon: '📋', title: 'Save before Run', body: 'The Run button launches the workflow as saved on disk. Always save (Ctrl+S) before running so your canvas edits take effect.' },
    { icon: '◈', title: 'Custom IDs', body: 'If you drop the same tool twice, it gets a unique suffix (_2, _3…). You can rename it in the config panel — just keep it unique.' },
  ]

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,.8)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: 'var(--bg-soft)', border: '1px solid #30363d', borderRadius: 10,
        width: '68vw', maxWidth: 820, maxHeight: '85vh',
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 24px 80px rgba(0,0,0,.7)',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 16px', borderBottom: '1px solid #30363d', flexShrink: 0,
        }}>
          <span style={{ fontSize: 16 }}>◈</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>
              Hướng dẫn sử dụng — Workflow Editor
            </div>
            <div style={{ fontSize: 9.5, color: 'var(--text-2)' }}>
              k1nzr3c0n · Visual Security Workflow Builder
            </div>
          </div>
          <div style={{ flex: 1 }} />
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: 'var(--text-2)',
            cursor: 'pointer', fontSize: 20, lineHeight: 1, padding: '0 4px',
          }}>×</button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', borderBottom: '1px solid #30363d', flexShrink: 0 }}>
          {[['guide', 'Hướng dẫn'], ['shortcuts', 'Shortcuts'], ['vars', 'Template Vars'], ['tips', 'Tips']].map(([t, label]) => (
            <button key={t} onClick={() => setTab(t)}
              style={{
                padding: '8px 18px', fontSize: 10.5, fontWeight: 700,
                letterSpacing: '.04em', textTransform: 'uppercase',
                background: 'none', border: 'none',
                borderBottom: `2px solid ${tab === t ? '#58a6ff' : 'transparent'}`,
                color: tab === t ? '#58a6ff' : 'var(--text-2)', cursor: 'pointer',
              }}>
              {label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>

          {/* ── Hướng dẫn ── */}
          {tab === 'guide' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <Step n={1} title="Tạo workflow mới"
                desc="Từ trang Workflows, nhấn '+ New Workflow', đặt tên file (vd: api_recon), rồi bấm 'Create & Open'. Một canvas trống sẽ mở ra." />
              <Step n={2} title="Kéo tool từ Library"
                desc="Mở tab 'Library' ở panel trái. Các công cụ được nhóm theo phase (Discovery, Scan, Vuln...). Kéo bất kỳ tool nào vào canvas để tạo node mới." />
              <Step n={3} title="Kết nối các bước"
                desc="Hover vào node — sẽ thấy handle hình tròn ở hai bên. Kéo từ handle phải (source) sang handle trái (target) của node tiếp theo để tạo dependency." />
              <Step n={4} title="Cấu hình từng bước"
                desc="Click vào node bất kỳ để mở Config Panel bên phải. Chỉnh sửa: tên, phase, lệnh run, when condition, timeout, retries, optional flag." />
              <Step n={5} title="Thiết lập biến (Variables)"
                desc="Tab 'Vars' hiển thị tất cả biến của workflow. Các biến boolean có toggle bật/tắt ngay. Thêm biến mới bằng ô 'Add Variable' ở cuối." />
              <Step n={6} title="Lưu và chạy"
                desc="Nhấn 💾 Save (hoặc Ctrl+S) để ghi YAML xuống disk. Sau đó nhấn ▶ Run, nhập target domain, và workflow sẽ được đẩy vào Celery queue." />
              <Step n={7} title="Theo dõi live"
                desc="Khi run đang chạy, WebSocket tự động overlay trạng thái (running ●, ok ✓, failed ✗) lên từng node trên canvas theo thời gian thực." />

              <div style={{
                background: '#0a1929', border: '1px solid #0d2d4a',
                borderRadius: 8, padding: '14px 16px',
              }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#58a6ff',
                  letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 8 }}>
                  Quy tắc thực thi
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {[
                    ['Edge A→B', 'B chỉ chạy sau khi A hoàn thành (ok hoặc skipped)'],
                    ['when: {vars.X}', 'Bước bị bỏ qua nếu var X = false'],
                    ['optional: true', 'Nếu bước fail, workflow vẫn tiếp tục'],
                    ['skip_if_exists', 'Bước bị skip nếu output file đã tồn tại (resume mode)'],
                    ['fanout', 'Danh sách sub-steps chạy song song bên trong một bước'],
                  ].map(([rule, desc]) => (
                    <div key={rule} style={{ display: 'flex', gap: 12, fontSize: 10.5 }}>
                      <span style={{ color: '#58a6ff', fontFamily: 'monospace',
                        minWidth: 160, flexShrink: 0 }}>{rule}</span>
                      <span style={{ color: 'var(--text-2)' }}>{desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Shortcuts ── */}
          {tab === 'shortcuts' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 10 }}>
                Keyboard shortcuts trong Workflow Editor:
              </div>
              {SHORTCUTS.map(({ key, desc }) => (
                <div key={key} style={{
                  display: 'flex', alignItems: 'center', gap: 16,
                  padding: '9px 14px', background: 'var(--surface)',
                  border: '1px solid #21262d', borderRadius: 6,
                }}>
                  <kbd style={{
                    background: 'var(--bg-soft)', border: '1px solid #30363d',
                    borderRadius: 5, padding: '3px 9px', fontSize: 10.5,
                    fontFamily: 'monospace', color: '#58a6ff',
                    whiteSpace: 'nowrap', flexShrink: 0,
                    boxShadow: '0 2px 0 #21262d',
                  }}>{key}</kbd>
                  <span style={{ fontSize: 11, color: 'var(--text-2)' }}>{desc}</span>
                </div>
              ))}
            </div>
          )}

          {/* ── Template Vars ── */}
          {tab === 'vars' && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 14 }}>
                Sử dụng các placeholder này trong trường "Run command" của mỗi step:
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {VARS.map(({ v, desc }) => (
                  <div key={v} style={{
                    display: 'flex', gap: 14, padding: '10px 14px',
                    background: 'var(--surface)', border: '1px solid #21262d', borderRadius: 6,
                  }}>
                    <code style={{
                      color: '#f0b429', fontFamily: 'monospace', fontSize: 11,
                      background: '#1f1800', border: '1px solid #f0b42933',
                      borderRadius: 4, padding: '2px 7px',
                      whiteSpace: 'nowrap', flexShrink: 0, alignSelf: 'flex-start',
                    }}>{v}</code>
                    <span style={{ fontSize: 11, color: 'var(--text-2)', lineHeight: 1.5 }}>{desc}</span>
                  </div>
                ))}
              </div>
              <div style={{
                marginTop: 20, padding: '12px 14px',
                background: '#150d26', border: '1px solid #a371f733',
                borderRadius: 8,
              }}>
                <div style={{ fontSize: 9.5, color: '#a371f7', fontWeight: 700,
                  letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 8 }}>
                  Ví dụ Run command
                </div>
                <pre style={{ margin: 0, fontSize: 10.5, color: 'var(--text-2)',
                  fontFamily: 'monospace', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
{`subfinder -d {target} \\
  -all -silent \\
  -o {workspace}/subdomains.txt 2>/dev/null; true`}
                </pre>
                <div style={{ marginTop: 8, fontSize: 9.5, color: 'var(--text-3)' }}>
                  Luôn thêm <code style={{ color: '#a371f7' }}>; true</code> ở cuối để tool không làm fail bước khi không tìm thấy kết quả.
                </div>
              </div>
            </div>
          )}

          {/* ── Tips ── */}
          {tab === 'tips' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {TIPS.map(({ icon, title, body }) => (
                <div key={title} style={{
                  display: 'flex', gap: 14, padding: '12px 14px',
                  background: 'var(--surface)', border: '1px solid #21262d', borderRadius: 7,
                }}>
                  <span style={{ fontSize: 16, color: '#58a6ff', flexShrink: 0,
                    marginTop: 1, width: 20, textAlign: 'center' }}>{icon}</span>
                  <div>
                    <div style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
                      {title}
                    </div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-2)', lineHeight: 1.6 }}>{body}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Step({ n, title, desc }) {
  return (
    <div style={{ display: 'flex', gap: 16 }}>
      <div style={{
        width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
        background: '#0a1929', border: '1.5px solid #58a6ff66',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 11, fontWeight: 700, color: '#58a6ff',
      }}>{n}</div>
      <div>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
          {title}
        </div>
        <div style={{ fontSize: 10.5, color: 'var(--text-2)', lineHeight: 1.6 }}>{desc}</div>
      </div>
    </div>
  )
}

// ─── Main WorkflowEditor ─────────────────────────────────────────────────────
export default function WorkflowEditor() {
  const { name } = useParams()
  const [wf, setWf] = useState(null)
  const [savedPositions, setSavedPositions] = useState({})
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [selectedStep, setSelectedStep] = useState(null)
  const [leftTab, setLeftTab] = useState('library')
  const [leftW, setLeftW] = useState(280)
  const leftDragRef = useRef(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [showRun, setShowRun] = useState(false)
  const [showYaml, setShowYaml] = useState(false)
  const [showHelp, setShowHelp] = useState(false)
  const [liveRunId, setLiveRunId] = useState(null)
  const wsRef = useRef(null)
  const rfInstanceRef = useRef(null)
  const deleteNodeRef = useRef(null)

  // ── Delete node (called from NodeToolbar X button + keyboard) ───────────────
  function handleDeleteNode(nodeId) {
    rfInstanceRef.current?.deleteElements({ nodes: [{ id: nodeId }] })
  }
  deleteNodeRef.current = handleDeleteNode

  // ── React Flow fires this after deleting nodes (Delete key or deleteElements) ─
  const onNodesDelete = useCallback((deleted) => {
    const ids = new Set(deleted.map(n => n.id))
    setEdges(prev => prev.filter(e => !ids.has(e.source) && !ids.has(e.target)))
    setWf(prev => prev ? ({
      ...prev,
      steps: (prev.steps || []).filter(s => !ids.has(s.id)),
    }) : prev)
    setSelectedStep(prev => (prev && ids.has(prev.id) ? null : prev))
  }, [])

  // ── Inject the delete callback into node data ───────────────────────────────
  function withDelete(ns) {
    return ns.map(n => ({
      ...n,
      data: { ...n.data, onDelete: (id) => deleteNodeRef.current(id) },
    }))
  }

  // ── Load workflow ───────────────────────────────────────────────────────────
  useEffect(() => {
    if (!name) return
    api.getWorkflow(name).then(data => {
      setWf(data)
      const { nodes: n, edges: e } = wfToGraph(data, {})
      setNodes(withDelete(n))
      setEdges(e)
    }).catch(console.error)
  }, [name])

  // ── Live WebSocket status overlay ───────────────────────────────────────────
  useEffect(() => {
    if (!liveRunId) return
    const ws = new WebSocket(wsUrl(liveRunId))
    wsRef.current = ws
    ws.onmessage = (ev) => {
      const data = JSON.parse(ev.data)
      if (data.type === 'step' && data.steps) {
        const statusMap = {}
        data.steps.forEach(s => { statusMap[s.id] = s.status })
        setNodes(prev => prev.map(n => ({
          ...n,
          data: { ...n.data, liveStatus: statusMap[n.id] },
        })))
      }
      if (data.type === 'done') { ws.close(); setLiveRunId(null) }
    }
    return () => ws.close()
  }, [liveRunId])

  // ── Ctrl+S to save ─────────────────────────────────────────────────────────
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault()
        handleSave()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [wf, nodes, edges])

  // ── Sync node positions to savedPositions on drag ──────────────────────────
  const onNodeDragStop = useCallback((_, node) => {
    setSavedPositions(prev => ({ ...prev, [node.id]: node.position }))
  }, [])

  // ── Connect edge ───────────────────────────────────────────────────────────
  const onConnect = useCallback((params) => {
    setEdges(eds => addEdge({
      ...params, type: 'smoothstep',
      style: { stroke: 'var(--border)', strokeWidth: 1.5 },
      markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--border)', width: 10, height: 10 },
    }, eds))
    setWf(prev => {
      if (!prev?.steps) return prev
      return {
        ...prev,
        steps: prev.steps.map(s => s.id !== params.target ? s : {
          ...s, depends_on: [...new Set([...(s.depends_on || []), params.source])],
        }),
      }
    })
    setSelectedStep(prev => {
      if (!prev || prev.id !== params.target) return prev
      return { ...prev, depends_on: [...new Set([...(prev.depends_on || []), params.source])] }
    })
  }, [])

  // ── Click node ─────────────────────────────────────────────────────────────
  const onNodeClick = useCallback((_, node) => {
    setSelectedStep(node.data.step)
  }, [])

  // ── Drop tool from library onto canvas ─────────────────────────────────────
  const onDragOver = useCallback((e) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = 'move'
  }, [])

  const onDrop = useCallback((e) => {
    e.preventDefault()
    const raw = e.dataTransfer.getData('application/x-tool')
    if (!raw || !rfInstanceRef.current) return
    const tool = JSON.parse(raw)
    const position = rfInstanceRef.current.screenToFlowPosition({ x: e.clientX, y: e.clientY })

    // Generate unique ID using current nodes from RF instance (avoids nested setState)
    const existingIds = new Set(rfInstanceRef.current.getNodes().map(n => n.id))
    let newId = tool.id, c = 2
    while (existingIds.has(newId)) newId = `${tool.id}_${c++}`

    const newStep = {
      id: newId, name: tool.name, run: tool.defaultRun, optional: true, _phase: tool.phase,
    }
    const ph = PH[tool.phase]
    const newNode = {
      id: newId, type: 'stepNode', position,
      data: { step: newStep, phase: tool.phase, ph, isOn: true, onDelete: (id) => deleteNodeRef.current(id) },
    }
    setNodes(prev => [...prev, newNode])
    setWf(prev => prev ? ({ ...prev, steps: [...(prev.steps || []), newStep] }) : prev)
    setSelectedStep(newStep)
  }, [])

  // ── Step config change ─────────────────────────────────────────────────────
  function handleStepChange(updated) {
    const oldId = selectedStep?.id
    const currentVars = wf?.vars
    setSelectedStep(updated)
    setWf(prev => ({
      ...prev,
      steps: prev.steps.map(s => s.id === oldId ? updated : s),
    }))
    const newPhase = resolvePhase(updated)
    setNodes(prev => prev.map(n => n.id === oldId
      ? { ...n, data: { ...n.data, step: updated, phase: newPhase, ph: PH[newPhase],
          isOn: evalWhen(updated.when, currentVars) } }
      : n
    ))
  }

  // ── Var change ─────────────────────────────────────────────────────────────
  function handleVarChange(key, val) {
    const newVars = { ...(wf?.vars || {}), [key]: val }
    setWf(prev => ({ ...prev, vars: newVars }))
    setNodes(nds => nds.map(n => ({
      ...n, data: { ...n.data, isOn: evalWhen(n.data.step.when, newVars) },
    })))
  }

  // ── Apply template ─────────────────────────────────────────────────────────
  function applyTemplate(tplVars) {
    const newVars = { ...(wf?.vars || {}), ...tplVars }
    setWf(prev => ({ ...prev, vars: newVars }))
    setNodes(nds => nds.map(n => ({
      ...n, data: { ...n.data, isOn: evalWhen(n.data.step.when, newVars) },
    })))
  }

  // ── Save workflow ──────────────────────────────────────────────────────────
  async function handleSave() {
    if (!wf || !name) return
    setSaving(true)
    try {
      const updatedSteps = graphToSteps(nodes, edges, wf.steps)
      const payload = { ...wf, steps: updatedSteps }
      await api.saveWorkflow(name, payload)
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (e) {
      console.error(e)
    }
    setSaving(false)
  }

  // ── Reset layout ───────────────────────────────────────────────────────────
  function handleResetLayout() {
    if (!wf) return
    setSavedPositions({})
    const { nodes: n, edges: e } = wfToGraph(wf, {})
    setNodes(withDelete(n))
    setEdges(e)
  }

  if (!wf) {
    return (
      <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
        height:'100%', color:'var(--text-2)', fontSize:13 }}>
        Loading workflow…
      </div>
    )
  }

  const enabledCount = nodes.filter(n => n.data.isOn !== false).length
  const disabledCount = nodes.length - enabledCount

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', background:'var(--bg-soft)' }}>
      {/* ── Toolbar ── */}
      <div style={{
        display:'flex', alignItems:'center', gap:10,
        padding:'8px 16px', borderBottom:'1px solid #30363d',
        background:'var(--bg-soft)', flexShrink:0,
      }}>
        <Link to="/workflows" style={{ color:'var(--text-2)', fontSize:11,
          textDecoration:'none', display:'flex', alignItems:'center', gap:4 }}>
          ◈ Workflows
        </Link>
        <span style={{ color:'var(--border)' }}>/</span>
        <span style={{ fontSize:12, fontWeight:700, color:'var(--text)', fontFamily:'monospace' }}>
          {name}
        </span>
        <span style={{ fontSize:10, color:'var(--text-2)', marginLeft:4 }}>
          {nodes.length} steps · <span style={{ color:'#3fb950' }}>{enabledCount} active</span>
          {disabledCount > 0 && <span style={{ color:'var(--text-3)' }}> · {disabledCount} disabled</span>}
        </span>

        <div style={{ flex:1 }} />

        {liveRunId && (
          <span style={{
            fontSize:10, color:'#3fb950', border:'1px solid #3fb95044',
            borderRadius:4, padding:'2px 8px', animation:'nodePulse 1.5s infinite',
          }}>
            ● Live
          </span>
        )}

        <button className="btn" style={{ fontSize:11 }} onClick={handleResetLayout}>
          ↺ Layout
        </button>
        <button className="btn" style={{ fontSize:11, color:'#a371f7' }}
          onClick={() => setShowYaml(true)}>
          {'{ }'} YAML
        </button>
        <button className="btn" style={{ fontSize:11 }}
          onClick={() => setShowHelp(true)}>
          ? Help
        </button>
        <button className="btn" style={{ fontSize:11, color: saved ? '#3fb950' : 'var(--text)',
          borderColor: saved ? '#3fb95066' : 'transparent' }}
          onClick={handleSave} disabled={saving}>
          {saving ? '⌛ Saving…' : saved ? '✓ Saved' : '💾 Save  Ctrl+S'}
        </button>
        <button className="btn btn-primary" style={{ fontSize:11 }}
          onClick={() => setShowRun(true)}>
          ▶ Run
        </button>
      </div>

      {/* ── Body ── */}
      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>

        {/* ── Left Panel ── */}
        <div style={{
          width: leftW, flexShrink:0, borderRight:'1px solid #30363d',
          display:'flex', flexDirection:'column', background:'var(--bg-soft)',
          position:'relative',
        }}>
          {/* resize handle */}
          <div
            ref={leftDragRef}
            onMouseDown={e => {
              e.preventDefault()
              const startX = e.clientX
              const startW = leftW
              const onMove = mv => setLeftW(Math.max(200, Math.min(500, startW + mv.clientX - startX)))
              const onUp   = () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp) }
              window.addEventListener('mousemove', onMove)
              window.addEventListener('mouseup', onUp)
            }}
            style={{
              position:'absolute', right:0, top:0, bottom:0, width:5,
              cursor:'col-resize', zIndex:10,
              background:'transparent',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = '#58a6ff44' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
          />
          {/* Tabs — 4 tabs */}
          <div style={{ display:'flex', borderBottom:'1px solid #30363d' }}>
            {[['library','Library'],['templates','Presets'],['vars','Vars'],['steps','Steps']].map(([tab, label]) => (
              <button key={tab} onClick={() => setLeftTab(tab)}
                style={{
                  flex:1, padding:'7px 2px', fontSize:9, fontWeight:700,
                  letterSpacing:'.03em', textTransform:'uppercase',
                  background:'none', border:'none', borderBottom:`2px solid ${leftTab===tab ? '#58a6ff' : 'transparent'}`,
                  color: leftTab===tab ? '#58a6ff' : 'var(--text-2)', cursor:'pointer',
                  transition:'color .15s',
                }}>
                {label}
              </button>
            ))}
          </div>

          <div style={{ flex:1, overflowY:'auto' }}>

            {/* ── Library tab ── */}
            {leftTab === 'library' && (
              <div style={{ padding: '10px 8px' }}>
                <p style={{ fontSize: 9.5, color: 'var(--text-3)', lineHeight: 1.5,
                  marginBottom: 10, padding: '0 4px' }}>
                  Drag any tool onto the canvas to add a step.
                  Select a node to connect handles.
                </p>
                {Object.entries(PH).map(([phKey, ph]) => {
                  const tools = TOOL_LIBRARY.filter(t => t.phase === phKey)
                  if (!tools.length) return null
                  return (
                    <div key={phKey} style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 8.5, color: ph.color, fontWeight: 700,
                        letterSpacing: '.07em', textTransform: 'uppercase',
                        marginBottom: 5, padding: '0 4px',
                        display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span>{ph.icon}</span>
                        <span>{ph.label}</span>
                      </div>
                      {tools.map(tool => (
                        <div
                          key={tool.id}
                          draggable
                          onDragStart={(e) => {
                            e.dataTransfer.setData('application/x-tool', JSON.stringify(tool))
                            e.dataTransfer.effectAllowed = 'move'
                          }}
                          style={{
                            padding: '6px 10px', marginBottom: 3,
                            background: 'var(--surface)', border: `1px solid #21262d`,
                            borderRadius: 6, cursor: 'grab', userSelect: 'none',
                            transition: 'border-color .15s, background .15s',
                          }}
                          onMouseEnter={e => {
                            e.currentTarget.style.borderColor = ph.color + '55'
                            e.currentTarget.style.background = ph.bg
                          }}
                          onMouseLeave={e => {
                            e.currentTarget.style.borderColor = 'var(--surface-2)'
                            e.currentTarget.style.background = 'var(--surface)'
                          }}>
                          <div style={{ fontSize: 10.5, fontWeight: 700,
                            color: 'var(--text)', fontFamily: 'monospace', marginBottom: 2 }}>
                            {tool.name}
                          </div>
                          <div style={{ fontSize: 9, color: 'var(--text-2)', lineHeight: 1.3 }}>
                            {tool.desc}
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                })}
              </div>
            )}

            {/* ── Presets tab ── */}
            {leftTab === 'templates' && (
              <div style={{ padding: 12, display:'flex', flexDirection:'column', gap: 8 }}>
                <p style={{ fontSize:10, color:'var(--text-3)', marginBottom:4, lineHeight:1.5 }}>
                  Apply a preset to quickly configure which phases run.
                </p>
                {Object.entries(TEMPLATES).map(([tplName, tpl]) => (
                  <button key={tplName} onClick={() => applyTemplate(tpl.vars)}
                    style={{
                      background:'var(--surface)', border:'1px solid #30363d', borderRadius:7,
                      padding:'10px 12px', textAlign:'left', cursor:'pointer',
                      transition:'border-color .15s, background .15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = '#58a6ff66'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                  >
                    <div style={{ fontSize:12, fontWeight:700, color:'var(--text)', marginBottom:3 }}>
                      {tpl.icon} {tplName}
                    </div>
                    <div style={{ fontSize:10, color:'var(--text-2)', lineHeight:1.4 }}>{tpl.desc}</div>
                  </button>
                ))}

                {/* Phase quick-toggles */}
                <div style={{ marginTop:8, padding:'10px 12px', background:'var(--surface)',
                  border:'1px solid #30363d', borderRadius:7 }}>
                  <div style={{ fontSize:9, color:'var(--text-3)', fontWeight:700,
                    letterSpacing:'.07em', textTransform:'uppercase', marginBottom:8 }}>
                    Quick toggles
                  </div>
                  {['run_discovery','run_portscan','run_crawl','run_screenshot',
                    'run_nuclei','run_afrog','run_params','run_dirbrute'].map(key => {
                    const exists = key in (wf.vars || {})
                    if (!exists) return null
                    return (
                      <label key={key} style={{
                        display:'flex', alignItems:'center', justifyContent:'space-between',
                        cursor:'pointer', userSelect:'none', padding:'3px 0',
                      }}>
                        <span style={{ fontSize:10, color:'var(--text-2)', fontFamily:'monospace' }}>
                          {key.replace('run_','')}
                        </span>
                        <input type="checkbox" checked={wf.vars?.[key] === 'true'}
                          onChange={e => handleVarChange(key, e.target.checked ? 'true' : 'false')}
                          style={{ accentColor:'#58a6ff', width:13, height:13 }} />
                      </label>
                    )
                  })}
                </div>
              </div>
            )}

            {/* ── Vars tab ── */}
            {leftTab === 'vars' && (
              <VarsPanel vars={wf.vars || {}} onChange={handleVarChange} />
            )}

            {/* ── Steps tab ── */}
            {leftTab === 'steps' && (
              <div style={{ padding:8 }}>
                {nodes.length === 0 && (
                  <div style={{ padding: '20px 8px', textAlign: 'center' }}>
                    <p style={{ fontSize: 10, color: 'var(--text-3)', lineHeight: 1.6 }}>
                      No steps yet. Drag tools from the Library tab onto the canvas.
                    </p>
                  </div>
                )}
                {nodes.map(n => {
                  const ph = PH[n.data.phase]
                  return (
                    <button key={n.id}
                      onClick={() => setSelectedStep(n.data.step)}
                      style={{
                        display:'flex', alignItems:'center', gap:7,
                        width:'100%', background: selectedStep?.id === n.id ? 'var(--surface-2)' : 'none',
                        border:'none', borderRadius:5, padding:'5px 8px',
                        cursor:'pointer', textAlign:'left', marginBottom:2,
                        transition:'background .1s',
                      }}
                      onMouseEnter={e => { if(selectedStep?.id !== n.id) e.currentTarget.style.background='var(--surface)' }}
                      onMouseLeave={e => { if(selectedStep?.id !== n.id) e.currentTarget.style.background='none' }}
                    >
                      <span style={{ width:6, height:6, borderRadius:'50%',
                        background: n.data.isOn === false ? 'var(--text-3)' : ph.color,
                        flexShrink:0 }} />
                      <span style={{ fontSize:10, color: n.data.isOn === false ? 'var(--text-3)' : 'var(--text)',
                        fontFamily:'monospace', flex:1, overflow:'hidden',
                        textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                        {n.id}
                      </span>
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* ── Canvas ── */}
        <div
          style={{ flex:1, position:'relative' }}
          onDragOver={onDragOver}
          onDrop={onDrop}>
          <style>{`
            @keyframes nodeGlow { 0%,100%{opacity:1} 50%{opacity:0.4} }
            .react-flow__node { border-radius:8px !important; }
            .react-flow__edge-path { stroke-width: 1.5 !important; }
            .react-flow__minimap { background: #161b22 !important; border: 1px solid #30363d !important; border-radius: 6px !important; }
            .react-flow__controls { background: #161b22 !important; border: 1px solid #30363d !important; border-radius: 6px !important; }
            .react-flow__controls-button { background: #161b22 !important; border-color: #30363d !important; color: #8b949e !important; }
            .react-flow__controls-button:hover { background: #1c2128 !important; color: #e6edf3 !important; }
            .react-flow__attribution { display: none !important; }
            .react-flow__nodesselection-rect { background: #58a6ff11 !important; border: 1px solid #58a6ff55 !important; }
          `}</style>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodesDelete={onNodesDelete}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onNodeDragStop={onNodeDragStop}
            onPaneClick={() => setSelectedStep(null)}
            onInit={inst => { rfInstanceRef.current = inst }}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.15}
            maxZoom={2}
            deleteKeyCode={['Delete', 'Backspace']}
            style={{ background: 'var(--bg-soft)' }}
            defaultEdgeOptions={{
              type: 'smoothstep',
              style: { stroke: 'var(--border)', strokeWidth: 1.5 },
              markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--border)', width:10, height:10 },
            }}
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={24} size={1} color="var(--border)" />
            <Controls position="bottom-right" />
            <MiniMap
              position="bottom-left"
              nodeColor={(n) => {
                const ph = PH[n.data?.phase] || PH.scan
                return n.data?.isOn === false ? 'var(--surface-2)' : ph.color + '88'
              }}
              maskColor="#0d111788"
              style={{ width: 160, height: 100 }}
            />
            {/* Legend + hint */}
            <Panel position="top-right">
              <div style={{
                background:'var(--surface)', border:'1px solid #30363d', borderRadius:7,
                padding:'8px 12px', display:'flex', flexDirection:'column', gap:4,
              }}>
                {Object.entries(PH).map(([k, ph]) => (
                  <div key={k} style={{ display:'flex', alignItems:'center', gap:6, fontSize:9.5 }}>
                    <span style={{ width:8, height:8, borderRadius:'50%',
                      background:ph.color, flexShrink:0 }} />
                    <span style={{ color:'var(--text-2)' }}>{ph.label}</span>
                  </div>
                ))}
                <div style={{ borderTop:'1px solid #21262d', marginTop:4, paddingTop:4,
                  display:'flex', flexDirection:'column', gap:3 }}>
                  {Object.entries(SC).map(([s, sc]) => (
                    <div key={s} style={{ display:'flex', alignItems:'center', gap:5, fontSize:9 }}>
                      <span style={{ color:sc.color }}>{sc.icon}</span>
                      <span style={{ color:'var(--text-3)' }}>{s}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
            {/* Empty state hint */}
            {nodes.length === 0 && (
              <Panel position="top-center">
                <div style={{
                  background:'var(--surface)', border:'1px dashed #30363d', borderRadius:8,
                  padding:'16px 24px', textAlign:'center', marginTop:60,
                }}>
                  <div style={{ fontSize:24, marginBottom:8 }}>◈</div>
                  <div style={{ fontSize:12, color:'var(--text-2)', marginBottom:4 }}>Empty workflow</div>
                  <div style={{ fontSize:10, color:'var(--text-3)' }}>
                    Drag tools from the Library panel on the left<br/>onto this canvas to build your workflow.
                  </div>
                </div>
              </Panel>
            )}
          </ReactFlow>
        </div>

        {/* ── Config Panel ── */}
        {selectedStep && (
          <ConfigPanel
            step={selectedStep}
            vars={wf.vars}
            onChange={handleStepChange}
            onVarChange={handleVarChange}
            onClose={() => setSelectedStep(null)}
          />
        )}
      </div>

      {showRun && (
        <RunModal
          workflowName={name}
          onClose={() => setShowRun(false)}
        />
      )}

      {showYaml && (
        <YamlModal
          wf={wf}
          wfName={name}
          nodes={nodes}
          edges={edges}
          onClose={() => setShowYaml(false)}
          onSave={async () => { await handleSave(); setShowYaml(false) }}
          saving={saving}
        />
      )}

      {showHelp && (
        <HelpModal onClose={() => setShowHelp(false)} />
      )}
    </div>
  )
}
