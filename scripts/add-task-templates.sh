#!/usr/bin/env bash
# Seed the "Red Team" Task template into the autonomous Task engine via
# POST /api/task-templates (ARTEX API — needs a login token).
#
# PHASE-BASED red-team / pentest playbook (MITRE ATT&CK). Terse bullet steps,
# divided into phases: MISSION + RULES + PHASE 1..6 (recon -> map/fan-out ->
# vuln -> exploit -> post-exploit -> objective/report). Vietnamese content;
# every tool / flag / workflow / var / skill / ATT&CK id kept verbatim. No secrets.
#
# Auth — provide ONE of:
#   ARTEX_TOKEN=...        # browser console: localStorage.getItem('artex_token')
#   ARTEX_PASSWORD=...     # script logs in (ARTEX_USER defaults to "ARTEX")
#
# Usage:
#   BASE_URL=http://127.0.0.1:8000 ARTEX_TOKEN=... ./scripts/add-task-templates.sh
#   BASE_URL=http://192.168.52.103:8000 ARTEX_PASSWORD='yourpass' ./scripts/add-task-templates.sh
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

# ── acquire a token ──────────────────────────────────────────────────────────
TOKEN="${ARTEX_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${ARTEX_PASSWORD:-}" ]; then
  TOKEN=$(U="${ARTEX_USER:-ARTEX}" P="$ARTEX_PASSWORD" python3 -c 'import json,os;print(json.dumps({"username":os.environ["U"],"password":os.environ["P"]}))' \
    | curl -sS -X POST "$BASE_URL/api/auth/login" -H 'Content-Type: application/json' --data @- 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)
fi
if [ -z "$TOKEN" ]; then
  echo "error: no token. Set ARTEX_TOKEN (browser: localStorage.getItem('artex_token'))" >&2
  echo "       or ARTEX_PASSWORD=... (ARTEX_USER defaults to ARTEX)." >&2
  exit 1
fi

create() { # upsert <name> <goal> <description> — updates a same-named template in place
  local payload code id
  payload=$(NAME="$1" GOAL="$2" DESC="$3" python3 -c 'import json,os; print(json.dumps({"name":os.environ["NAME"],"goal":os.environ["GOAL"],"description":os.environ["DESC"]}))')
  # find an existing template with the same name → PATCH it (so re-running IMPROVES
  # the template in place instead of 409-conflicting on the duplicate name).
  id=$(curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/task-templates" 2>/dev/null \
    | NAME="$1" python3 -c '
import json,os,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
n=os.environ["NAME"].strip().lower()
for t in (d.get("templates") or []):
    if (t.get("name") or "").strip().lower()==n:
        print(t.get("id")); break
' 2>/dev/null || echo "")
  if [ -n "$id" ]; then
    code=$(curl -sS -o /dev/null -w '%{http_code}' -X PATCH "$BASE_URL/api/task-templates/$id" \
      -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" --data "$payload" 2>/dev/null || echo 000)
    case "$code" in
      200|201) printf '  ok    %s (updated #%s)\n' "$1" "$id" ;;
      401|403) printf '  FAIL  %s (HTTP %s — token invalid/expired)\n' "$1" "$code" ;;
      *)       printf '  FAIL  %s update (HTTP %s)\n' "$1" "$code" ;;
    esac
  else
    code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/task-templates" \
      -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" --data "$payload" 2>/dev/null || echo 000)
    case "$code" in
      200|201) printf '  ok    %s (created)\n' "$1" ;;
      401|403) printf '  FAIL  %s (HTTP %s — token invalid/expired)\n' "$1" "$code" ;;
      *)       printf '  FAIL  %s (HTTP %s)\n' "$1" "$code" ;;
    esac
  fi
}

MISSION=$(cat <<'EOF'
# RED TEAM / PENTEST — PLAYBOOK THEO PHASE (MITRE ATT&CK)
MISSION: engagement được cấp phép, đầu-cuối. KHAI THÁC TỚI CÙNG tới crown jewels + CHỨNG MINH tác động thật
— không dừng ở "phát hiện". Tư duy attacker, OPSEC, chain điểm-yếu-nhỏ -> quyền cao nhất; vừa đánh vừa đo
khả năng phát hiện của blue team.
- Làm theo PHASE 1->6 dưới; giữ 1 LEDGER (TodoWrite) mọi asset/sub/IP đã·chưa test.
- Được dùng MỌI skill có trong hệ thống: gọi list_skills để xem TOÀN BỘ skill rồi load_skill <name> để nạp + theo hướng dẫn của nó. KHÔNG giới hạn ở map ROUTE ở PHASE 4 — chọn skill phù hợp nhất cho mỗi bước (recon/web/AD/cloud/k8s/mobile/cred/privesc/report/opsec...).
- Lưu kết quả NGAY (insert_assets / record_fact / report_finding) rồi BỎ output thô khỏi context — window có hạn, không giữ scan dump trong đầu.
- Người vận hành có thể chèn chỉ-dẫn vào việc đang chạy giữa chừng: ĐỌC và TUÂN ngay khi thấy.
EOF
)

RULES=$(cat <<'EOF'
## RULES (operator ĐÃ cấp phép — trong scope TOÀN QUYỀN khai thác)
- SCOPE: MỌI domain/subdomain trong sub_domain_all + MỌI IP liên quan (gồm pool/LB/F5/shared/ASN) = IN-SCOPE.
- ĐƯỢC đi tới cùng: privesc, lateral, cred-reuse, dump hash/secret, persistence, root/domain-admin, crown jewels. KHÔNG prove-and-stop.
- SÀN AN TOÀN (DỪNG + báo người): không DoS/sập production; thay đổi phải ĐẢO-NGƯỢC + log + cleanup; dừng khi chạm hệ thống tính-mạng (ICS/y tế/thanh toán lõi) / bên-thứ-ba thật / PII thật khối lượng lớn / dấu vết breach thật.
- Chỉ CDN/SaaS bên-thứ-ba thật (Cloudflare/Akamai/Fastly) mới host-only. Mask secret/PII trong report. Timestamp mọi hành động.
EOF
)

P1=$(cat <<'EOF'
## PHASE 1 — RECON & ĐIỀU PHỐI (quiet/passive trước; workflow CHÍNH, hand-recon lấp khe hở)
# VÒNG ĐIỀU PHỐI KHÉP KÍN (agent-task -> run_workflow -> graph, không bỏ sót): SEE -> CHECK -> RUN -> FOLLOW -> READ-DELTA -> RECONCILE -> LOOP.
- SEE/CHECK (đừng quét mù): recon_graph(target, summary=true) đo bề mặt (đếm node + finding theo severity) + recon_runs(target, status=...) xem đã/đang có run + list_workflows. ĐÃ có recon tươi -> TÁI DÙNG recon_findings/recon_assets, KHÔNG chạy lại.
- RUN (chỉ mảng còn thiếu, TÙY CƠ ỨNG BIẾN; non-blocking, trả run_id, chạy song song): run_workflow(target, <file>, vars={...}).
  · 02-full-recon-artex.yaml = MẶC ĐỊNH (nhanh, discovery -> trả tên để tự scan bằng 05).
  · 01-full-recon-pipeline.yaml = all-in-one (resolve+httpx+portscan+vuln, chậm) khi muốn tất cả 1 run.
  · 03-js-secrets-recon.yaml = khi nhiều JS/SPA (endpoint + secret trong JS).
  · 04-param-discovery.yaml = khi cần đào param ẩn.
  · 05-scan-hosts.yaml = scan CÓ-MỤC-TIÊU 1 tập host (target_hosts) + VHOST (PHASE 2).
- FOLLOW real-time: run_status(run_id) + run_log(run_id) (tail step). Run xong chỉ ở completed/failed (brief tự push về task). KHÔNG kết thúc khi còn run CHƯA đọc; kết quả tạm rỗng != "không có". Lạc run_id -> recon_runs(target, status=running); sai hướng -> stop_workflow(run_id).
- READ-DELTA: recon_graph(target, run_id, summary=true) xem run ĐÓ vừa thêm gì (rẻ hơn đọc lại cả map); recon_graph(target, q="admin"/node="h:host") khoan sâu; FULL map chỉ khi thật cần.
- RECONCILE + LƯU NGAY: GHIM lead -> graph_note(target, node, tag="priority"); record_fact cho version/CVE/exposure; report_finding CHỈ cho cái đã CHỨNG MINH; insert_assets cho host/param mới; rồi BỎ output thô khỏi context.
# NGUỒN RECON tay (gap-fill cái workflow KHÔNG tạo ra):
- Subdomain: subfinder -all + crt.sh + subdomain.center; permute gotator/dnsgen; AXFR dig @ns; records MX/NS/TXT/SPF/DMARC.
- IP/ASN: resolve subs -> IP A-record -> ASN (Team Cymru: dig +short TXT <reversed-ip>.origin.asn.cymru.com) -> prefix union RIPEstat + bgp.he.net + bgpview.io + bgpq4. (workflow asn_expand -> asn_ipv4_cidrs / asn_org_cidrs.)
- Leak/OSINT: GitHub/GitLab org dork + trufflehog, Postman, Docker, paste; breach data HIBP/dehashed.
- CONTENT/PATH FUZZ (baseline riêng + batch, -ac): ffuf/feroxbuster wordlist raft + ext .bak/.zip/.config/.env/.json/.sql; VCS /.git /.svn /.DS_Store; API /swagger /openapi.json /api-docs /graphql /actuator(/env,/heapdump); versioning /v1 /v2 /internal /mobile; method GET/POST/PUT/PATCH/DELETE/OPTIONS. Chi tiết: skill web-pentest (bug-bounty-web-playbook).
- Mobile (nếu có app): APK/IPA -> apktool/MobSF -> endpoint/key/host.
EOF
)

P2=$(cat <<'EOF'
## PHASE 2 — MAP BỀ MẶT + FAN-OUT (MỖI domain & MỖI IP = 1 worker RIÊNG; KHÔNG làm chung)
- FAN-OUT RIÊNG — duyệt TOÀN BỘ sub_domain_all + toàn bộ IP đã map:
  · MỖI domain/subdomain -> 1 worker RIÊNG: spawn_task(description="<domain>", goal="Red-team SÂU <domain> theo PHASE 2-6: vhost sống+chết x mọi IP, JS-endpoint recon, exploit web, privesc, objective, report").
  · MỖI IP (hoặc cụm pool/LB/F5) -> 1 worker RIÊNG: spawn_task(description="<ip|cidr>", goal="Pentest SÂU IP <ip>: full port-scan + service + CVE + vhost TOÀN BỘ tên vs IP này, exploit, report").
  · KHÔNG gộp nhiều domain/IP vào một worker. IP dùng chung giữa nhiều domain -> cross-reference giữa các worker.
  · GIÁM SÁT (orchestrator loop): list_tasks xem worker nào đã spawn; get_task_graph(task_id) đo coverage từng worker + list_task_findings(task_id) thu finding; get_task_worker_trace soi bước; worker lạc hướng/thiếu -> add_task_hint(task_id, ...) để lái, hoặc pause_task nếu cần. Không coi là xong khi còn worker chưa phủ hết ledger của nó.
- RESOLVE từng sub: public + DoH + NS auth (dig @ns). SERVFAIL/timeout = soft-recheck 8.8.8.8/1.1.1.1/9.9.9.9 trước khi coi là "chết"; tên không-resolve vẫn là SURFACE (tìm IP qua CNAME/cert-SAN/Shodan·Censys·FOFA/passive-DNS/PTR).
- VHOST MATRIX (BẮT BUỘC từng domain): MỌI tên CẢ SỐNG LẪN CHẾT x MỌI IP mở-web. CHẠY run_workflow 05-scan-hosts.yaml với vars={target_hosts:"<mọi tên domain>", target_ips:"<pool/LB/F5 IP không-tên-nào-resolve-tới, dạng IP/CIDR>", vhost_all_names:"true"} — 05 tự port-scan IP + sweep mọi tên như Host vs mọi IP mở-web, GATE baseline random-host (loại catch-all), phản hồi KHÁC baseline = vhost sống -> asset mới. Theo delta qua recon_graph(target, run_id). (Thủ công nếu cần: curl --resolve name:443:IP https+http.)
- PORT SCAN mọi IP của target (naabu -> nmap -sV -sC). Flag unauth: redis6379/mongo27017/elastic9200/DB, SMB445/LDAP389,636/Kerberos88/RDP3389/SSH22/FTP21/SMTP25/SNMP161, docker2375/k8s6443,10250. (IP pool/LB/shared của target = quét đầy đủ; chỉ CDN bên-thứ-ba mới host-only.)
- Mỗi sub + mỗi IP = LEDGER item; chưa "xong" tới khi: MỖI domain có worker riêng, MỖI IP có worker riêng, và mỗi item đủ resolve + httpx-probe + port-scan + vhost.
- Surface mới (sub/host/param) -> insert_assets + LOOP: 05-scan-hosts với target_hosts="<host mới>" rồi theo delta.
EOF
)

P3=$(cat <<'EOF'
## PHASE 3 — PHÂN TÍCH & NGHIÊN CỨU KHAI THÁC LỖ HỔNG (mục tiêu: KHAI THÁC ALL lỗ hổng; mọi finding = LEAD, phải VERIFY)
- FINGERPRINT NGHIÊM TÚC mọi tech stack: framework + thư viện + PHIÊN BẢN chính xác (httpx -td, wappalyzer, favicon-hash, headers/cookie, error-page, /VERSION, package.json/composer.json/pom.xml, retire.js cho JS lib). Lập 1 SBOM mỗi host — liệt kê HẾT, không bỏ component nào.
- MAP CVE từng thành phần: mỗi product+version -> CISA KEV + NVD + GitHub Security Advisory + exploit-db/searchsploit + nuclei + PoC công khai. Ưu tiên RCE / auth-bypass / deserialization / SSRF. Dependency cũ (retire.js/osv-scanner) -> known-CVE, xác minh REACHABLE.
- NGHIÊN CỨU + KHAI THÁC TẤT CẢ (đừng dừng ở signature): nuclei -ut -> nuclei full template mọi host/panel; rồi với MỖI tech/CVE tiềm năng -> đọc advisory + PoC, DỰNG LẠI exploit, thử trên target (safe PoC). Edge/app server (Citrix/Fortinet/Ivanti/GlobalProtect/F5/Exchange/Zimbra/Confluence/WebLogic/Struts/Spring) = ưu tiên hàng đầu.
- SERVICE: trên port đã mở -> default/weak cred + CVE-version mọi panel/service. CLOUD: bucket cloud_enum/s3scanner; SSRF -> metadata -> IAM.
- VERIFY trước report_finding: tự tái lập độc lập (curl / 1 nuclei template / exploit PoC / skill khớp) 2 lần, không phá hoại. graph_note(verified | false-positive); record_fact cho version/CVE; report_finding chỉ cho cái đã CHỨNG MINH.
EOF
)

P4=$(cat <<'EOF'
## PHASE 4 — KHAI THÁC / RED TEAM WEB SÂU (TA0001) — kiểm thử MỌI endpoint, nghiên cứu BYPASS mọi thứ
- JS RECON SÂU: tải MỌI file JS + *.js.map; dựng lại source (sourcemapper); TRÍCH XUẤT MỌI endpoint/route/API-path/param/secret/khóa (linkfinder/jsluice/katana -jc + grep fetch|axios|XHR|url). Gộp thành 1 danh sách endpoint ĐẦY ĐỦ.
- TEST MỌI ENDPOINT tìm được (JS + crawl + swagger/openapi/GraphQL/.well-known): cả AUTH lẫn UNAUTH, mỗi method (GET/POST/PUT/DELETE/PATCH), mỗi param (arjun/x8 fuzz). KHÔNG endpoint nào bỏ chưa test.
- Injection: SQLi/NoSQLi, OS-cmd, SSTI, XXE, LDAP, XSS. SSRF (mọi param url/fetch/webhook/import) -> internal/metadata/app-port-scan.
- Access control: IDOR/BOLA (đổi id giữa 2 account), BFLA (role/verb), mass-assignment, multi-tenant, forced-browse.
- Auth: default+weak cred; JWT (alg/none/secret-yếu/kid/jku), OAuth/SAML, reset password, 2FA bypass, session fixation, SSO.
- Files: upload -> webshell/RCE, LFI/RFI, path traversal, deserialization.
- NGHIÊN CỨU BYPASS MỌI THỨ: WAF bypass (encoding/case/comment/chunked/HTTP-request-smuggling); 401/403 bypass (path-case, %2e, ..;/, /.;/, header X-Original-URL/X-Rewrite-URL/X-Forwarded-For, verb-tamper); auth/login bypass; filter/validation bypass; rate-limit bypass (chứng minh bằng SỐ HỌC + keying matrix host/header/session, KHÔNG brute thật); CORS/CSP/SOP; upload-filter bypass. CHAIN nhiều bug nhỏ -> RCE / account-takeover / full read.
- TRADECRAFT SÂU -> skill web-pentest (reference bug-bounty-web-playbook): IDOR matrix, mass-assignment, business-logic & payment tamper, single-packet race, rate-limit-by-math, ATO reset/host-poison, open-redirect ladder (chỉ leo chuỗi/token-leak).
- ACCOUNT SAFETY (ràng buộc khi test auth web): tự đăng ký 1 account test; login sai <=2 lần thì DỪNG loại test đó, OTP sai <=3; KHÔNG brute/password-spray, KHÔNG để account bị khóa, KHÔNG đổi cred/MFA/session account khác; chỉ ghi/sửa bản ghi do account test tạo; KHÔNG thanh toán thật (dừng ở preview/intent); default/leaked cred login được -> STOP + report ngay.
- ROUTE skill (dùng ĐƯỢC mọi skill trong hệ thống, đây chỉ là map gợi ý): web->web-pentest; SMB/LDAP/Kerberos/RDP->network-attack + active-directory-attack; cloud->cloud-security; docker/k8s->container-k8s-escape; secret->red-team-ops; code/SAST->semgrep-sast + appsec-code-audit; bug-bounty->bug-bounty-methodology; shell->privesc-linux/privesc-windows + living-off-the-land + edr-evasion; hash->password-cracking; mobile/CI-CD/AI-MCP + bất kỳ skill khớp nào khác.
- Confirm bằng PoC marker AN TOÀN (không payload phá hoại).
EOF
)

P5=$(cat <<'EOF'
## PHASE 5 — HẬU KHAI THÁC (leo quyền TỚI CÙNG — cần foothold THẬT; đừng bịa bước chưa thực thi)
- Loot: SSH key, .env/config/DB cred, token/secret, cloud metadata trong host.
- Cred matrix: tái dùng mọi cred/hash qua mọi service + auth surface.
- PrivEsc TA0004: linpeas/winpeas; sudo/SUID/misconfig. AD: LSASS/DPAPI/DCSync (scoped), BloodHound (offline), ADCS ESC, Kerberos delegation/RBCD, NTLM relay+coercion, PtH/PtT, trust abuse.
- Lateral TA0008: cred tái dùng, SSH -> enum nội bộ/RFC1918 + token SA container/k8s -> container escape.
- Persistence TA0003 (ĐẢO-NGƯỢC + log) · C2 TA0011 (test egress/DLP bằng callback DNS/HTTPS, KHÔNG implant). OPSEC: né AMSI/ETW/EDR chỉ-ghi-tài-liệu, không làm hỏng host.
EOF
)

P6=$(cat <<'EOF'
## PHASE 6 — MỤC TIÊU + BÁO CÁO
- Objective TA0009: đạt crown jewels; CHỨNG MINH tác động thật — MÔ PHỎNG bước phá hoại cuối (wipe/ransom/mass-delete), KHÔNG thực thi.
- CONVERGENCE "xong" = objective đạt, HOẶC mọi ledger item terminal (tested / reasoned-negative / out-of-scope / deferred-có-lý-do). BẮT BUỘC: MỖI domain có worker riêng + plan, MỖI IP có worker riêng, đã qua VHOST MATRIX sống+chết, mọi IP phủ port-scan + vhost, mọi endpoint JS đã test, đã khai thác sâu tới hạn. Baseline (resolve+probe+port-scan+vhost) KHÔNG BAO GIỜ defer.
- REPORT (skill report-writing): executive summary + attack-path narrative (bước->technique->kết quả) + ATT&CK heatmap + detection gaps (fired/miss) + IOC cho blue (hash/C2/timestamp) + fix blue-team ưu-tiên + deconfliction + cleanup log. report_finding kèm PoC tái-lập-được trước, rồi lắp report từ các finding.
EOF
)

NL=$'\n\n'
DESC="${MISSION}${NL}${RULES}${NL}${P1}${NL}${P2}${NL}${P3}${NL}${P4}${NL}${P5}${NL}${P6}"

GOAL="RED TEAM / PENTEST được cấp phép (MITRE ATT&CK), theo 6 PHASE: recon -> map+fan-out (mỗi domain 1 plan + 1 worker, VHOST MATRIX cả sống lẫn chết x mọi IP) -> phân tích lỗ hổng -> khai thác -> hậu khai thác (leo quyền/lateral/persistence tới cùng) -> đạt crown jewels + chứng minh tác động + báo cáo. Có kỷ luật: không DoS/phá hoại production."

echo "Creating the Red Team task template on $BASE_URL ..."
create "Red Team" "$GOAL" "$DESC"

# The former standalone "Recon-Driven Pentest" template is now FOLDED INTO "Red Team".
# Delete the old separate template if an earlier seed created it, so there is ONE template.
remove_template() { # remove <name>
  local id code
  id=$(curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/task-templates" 2>/dev/null \
    | NAME="$1" python3 -c '
import json,os,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
n=os.environ["NAME"].strip().lower()
for t in (d.get("templates") or []):
    if (t.get("name") or "").strip().lower()==n:
        print(t.get("id")); break
' 2>/dev/null || echo "")
  [ -n "$id" ] || return 0
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE_URL/api/task-templates/$id" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo 000)
  case "$code" in
    200|204) printf '  removed  %s (#%s) — folded into Red Team\n' "$1" "$id" ;;
    *)       printf '  note     %s left in place (HTTP %s) — remove it in the UI if present\n' "$1" "$code" ;;
  esac
}
remove_template "Recon-Driven Pentest"

echo "Done. Open New task -> Task template dropdown, or Manage templates."
