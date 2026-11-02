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
khả năng phát hiện của blue team. Làm theo PHASE 1->6; INVARIANTS dưới ƯU TIÊN hơn mọi chi tiết.

## INVARIANTS (BẤT BIẾN — đúng ở MỌI phase)
1. SCOPE: mọi domain/subdomain (subdomains_all.txt) + mọi IP liên quan (asn_ipv4_cidrs.txt + resolved; gồm pool/LB/F5/shared/ASN) = IN-SCOPE (operator bảo chứng). Chỉ CDN/SaaS bên-thứ-ba thật (Cloudflare/Akamai) mới host-only.
2. TUẦN TỰ 1 WORKER: mỗi domain/IP = 1 worker trong task HIỆN TẠI qua add_intent, chạy LẦN LƯỢT (mở mục kế CHỈ khi worker trước xong). TUYỆT ĐỐI KHÔNG spawn_task, KHÔNG đồng thời. Tên intent bắt đầu "[#i/tổng] <domain|ip>".
3. QUEUE BỀN: record_fact 1 fact "QUEUE" liệt kê TOÀN BỘ domain/IP + trạng thái [chờ/đang/xong] NGAY từ đầu; cập nhật khi mỗi mục xong. Không để phần chờ chỉ nằm trong đầu.
4. HIỆN MỌI THỨ (operator theo dõi real-time): trước mỗi worker/bước lớn record_fact 1 dòng "đang làm X trên mục Y"; ghi NGAY mọi finding/fact/asset khi vừa có (không gom); KHÔNG chạy ẩn/im lặng; luôn đúng 1 worker đang chạy nhìn thấy được.
5. CỘNG DỒN: lộ domain/IP MỚI bất cứ lúc nào (recon HAY khai thác: loot/config/SSRF/pivot/cert/vhost) -> create_target (domain) / nạp 05 target_ips (IP) + NỐI CUỐI QUEUE + xử lý khi tới lượt (KHÔNG spawn_task).
6. FINDING client-grade: report_finding CHỈ cho cái đã VERIFY 2x + đủ severity/CWE/CVSS/evidence/PoC/traffic/remediation (chuẩn ở PHASE 3). Thiếu PoC = KHÔNG report.
7. SKILL: được dùng MỌI skill — list_skills để xem, load_skill <name> để nạp; không giới hạn map ROUTE. Operator chèn chỉ-dẫn giữa chừng -> ĐỌC + TUÂN ngay. Lưu NGAY rồi BỎ output thô khỏi context.
KHÔNG: spawn_task · chạy đồng thời/ẩn · report thiếu PoC · re-scan cái đã map · tự nới scope · DoS/phá hoại production.
TOOL MAP: recon->run_workflow · theo run->run_status+run_log · bản đồ->recon_graph · tái dùng->recon_findings/recon_assets · run cũ->recon_runs · worker/domain->add_intent · giám sát->get_task_graph+get_task_worker_trace · ghi->record_fact/insert_assets · finding->report_finding · scope mới->create_target · ghim lead->graph_note · skill->list_skills/load_skill.
EOF
)

RULES=$(cat <<'EOF'
## RULES (chi tiết phạm vi & an toàn — bổ trợ INVARIANT #1)
- KHAI THÁC SÂU tới cùng: privesc Linux/Windows, lateral, cred-reuse, dump hash/secret, persistence, root/domain-admin, crown jewels, CHỨNG MINH tác động. KHÔNG prove-and-stop; chỉ MÔ PHỎNG bước phá hoại cuối (wipe/ransom/mass-delete).
- GIỮ LÀ RED TEAM: không DoS/sập production; mọi thay đổi/persistence phải ĐẢO-NGƯỢC + log + cleanup; không xóa/mã hóa dữ liệu thật.
- SÀN AN TOÀN (DỪNG + báo người): chạm hệ thống tính-mạng (ICS/SCADA/y tế/thanh toán lõi) / bên-thứ-ba thật / PII thật khối lượng lớn (lấy mẫu che, KHÔNG kéo hàng loạt) / dấu vết breach thật.
- ACCOUNT AUTH web (CHỈ khi test đăng nhập): KHÔNG brute/spray, login sai <=2 lần thì dừng loại test đó, OTP <=3, không khoá account, không đụng cred/MFA account khác, không thanh toán thật. (privesc hạ tầng KHÔNG thuộc giới hạn này — đi tới cùng.)
- Che/mask PII/secret trong report; timestamp mọi hành động.
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
- Subdomain: subfinder -all + crt.sh + subdomain.center; permute gotator/dnsgen; AXFR dig @ns; records MX/NS/TXT/SPF/DMARC. Union đầy đủ -> subdomains_all.txt (01/02 merge_all_subdomains) = DANH SÁCH TÊN ĐẦY ĐỦ (sống+chết); dùng làm target_hosts cho 05.
- IP/ASN: resolve subs -> IP A-record -> ASN (Team Cymru: dig +short TXT <reversed-ip>.origin.asn.cymru.com) -> prefix union RIPEstat + bgp.he.net + bgpview.io + bgpq4. (workflow 01/02 step asn_expand -> asn_ipv4_cidrs.txt = DẢI IP ĐẦY ĐỦ của tổ chức.) naabu của 01 chỉ port-scan host đã resolve (scope-safety), KHÔNG quét trọn dải ASN -> muốn phủ CẢ footprint thì nạp asn_ipv4_cidrs.txt vào 05 qua target_ips.
- Leak/OSINT: GitHub/GitLab org dork + trufflehog, Postman, Docker, paste; breach data HIBP/dehashed.
- CONTENT/PATH FUZZ (baseline riêng + batch, -ac): ffuf/feroxbuster wordlist raft + ext .bak/.zip/.config/.env/.json/.sql; VCS /.git /.svn /.DS_Store; API /swagger /openapi.json /api-docs /graphql /actuator(/env,/heapdump); versioning /v1 /v2 /internal /mobile; method GET/POST/PUT/PATCH/DELETE/OPTIONS. Chi tiết: skill web-pentest (bug-bounty-web-playbook).
- Mobile (nếu có app): APK/IPA -> apktool/MobSF -> endpoint/key/host.
- DONE PHASE 1 khi: subdomains_all.txt + asn_ipv4_cidrs.txt có; bề mặt đã vào graph (recon_graph thấy); QUEUE (INV #3) đã lập đủ.
EOF
)

P2=$(cat <<'EOF'
## PHASE 2 — MAP BỀ MẶT + CHẠY QUEUE (theo INVARIANT #2/#3: mỗi domain/IP = 1 worker add_intent, tuần tự)
- QUEUE: lập fact QUEUE (INV #3) từ subdomains_all.txt + asn_ipv4_cidrs.txt + resolved. Tái dùng recon có sẵn (recon_findings/recon_assets) nếu run/task trước đã tạo — KHÔNG recon lại; nhưng QUEUE vẫn phải liệt kê ĐỦ mọi mục.
- WORKER (mục kế trong QUEUE): add_intent(summary="[#<i>/<tổng>] <domain|ip> — PHASE 2-4: vhost sống+chết x mọi IP, JS-endpoint, exploit web, privesc, report", asset_ids=[...]). Worker xong -> đánh dấu mục "xong" trong QUEUE -> add_intent mục kế. Giám sát: get_task_graph + get_task_worker_trace + steer.
- RESOLVE từng sub: public + DoH + NS auth (dig @ns). SERVFAIL/timeout = soft-recheck 8.8.8.8/1.1.1.1/9.9.9.9 trước khi coi là "chết"; tên không-resolve vẫn là SURFACE (tìm IP qua CNAME/cert-SAN/Shodan·Censys·FOFA/passive-DNS/PTR).
- VHOST MATRIX (BẮT BUỘC từng domain): MỌI tên CẢ SỐNG LẪN CHẾT x MỌI IP mở-web. CHẠY run_workflow 05-scan-hosts.yaml với vars={target_hosts:"<MỌI tên = subdomains_all.txt từ 01/02, cả sống lẫn chết>", target_ips:"<DẢI IP ĐẦY ĐỦ = asn_ipv4_cidrs.txt từ 01/02 + pool/LB/F5 IP không-tên-nào-resolve-tới, dạng IP/CIDR>", vhost_all_names:"true"} — 05 tự port-scan IP + sweep mọi tên như Host vs mọi IP mở-web, GATE baseline random-host (loại catch-all), phản hồi KHÁC baseline = vhost sống -> asset mới. Theo delta qua recon_graph(target, run_id). (Thủ công nếu cần: curl --resolve name:443:IP https+http.)
- PORT SCAN mọi IP của target (naabu -> nmap -sV -sC). Flag unauth: redis6379/mongo27017/elastic9200/DB, SMB445/LDAP389,636/Kerberos88/RDP3389/SSH22/FTP21/SMTP25/SNMP161, docker2375/k8s6443,10250. (IP pool/LB/shared của target = quét đầy đủ; chỉ CDN bên-thứ-ba mới host-only.)
- DONE PHASE 2 (mỗi mục QUEUE): resolve + httpx-probe + port-scan origin + VHOST MATRIX sống+chết xong; QUEUE không còn [chờ]; không bỏ mục nào.
- Surface mới BẤT CỨ LÚC NÀO (sub/host/param/IP, kể cả lúc khai thác) -> insert_assets + ĐƯA VÀO SCOPE + add_intent 1 worker MỚI trong task này (release LẦN LƯỢT khi worker trước xong): 05-scan-hosts target_hosts="<host mới>" / target_ips="<IP mới>" rồi theo delta. KHÔNG spawn_task.
EOF
)

P3=$(cat <<'EOF'
## PHASE 3 — PHÂN TÍCH & NGHIÊN CỨU KHAI THÁC LỖ HỔNG (mục tiêu: KHAI THÁC ALL lỗ hổng; mọi finding = LEAD, phải VERIFY)
- FINGERPRINT NGHIÊM TÚC mọi tech stack: framework + thư viện + PHIÊN BẢN chính xác (httpx -td, wappalyzer, favicon-hash, headers/cookie, error-page, /VERSION, package.json/composer.json/pom.xml, retire.js cho JS lib). Lập 1 SBOM mỗi host — liệt kê HẾT, không bỏ component nào.
- MAP CVE từng thành phần: mỗi product+version -> CISA KEV + NVD + GitHub Security Advisory + exploit-db/searchsploit + nuclei + PoC công khai. Ưu tiên RCE / auth-bypass / deserialization / SSRF. Dependency cũ (retire.js/osv-scanner) -> known-CVE, xác minh REACHABLE.
- NGHIÊN CỨU + KHAI THÁC TẤT CẢ (đừng dừng ở signature): nuclei -ut -> nuclei full template mọi host/panel; rồi với MỖI tech/CVE tiềm năng -> đọc advisory + PoC, DỰNG LẠI exploit, thử trên target (safe PoC). Edge/app server (Citrix/Fortinet/Ivanti/GlobalProtect/F5/Exchange/Zimbra/Confluence/WebLogic/Struts/Spring) = ưu tiên hàng đầu.
- SERVICE: trên port đã mở -> default/weak cred + CVE-version mọi panel/service. CLOUD: bucket cloud_enum/s3scanner; SSRF -> metadata -> IAM.
- VERIFY trước report_finding: tự tái lập độc lập (curl / 1 nuclei template / exploit PoC / skill khớp) 2 lần, không phá hoại. graph_note(verified | false-positive); record_fact cho version/CVE; report_finding chỉ cho cái đã CHỨNG MINH.
- CHUẨN FINDING client-grade (BẮT BUỘC mỗi report_finding — đây là chất lượng bàn giao, xem skill finding-discipline + report-writing): severity ĐÚNG (critical|high|medium|low) · vulnclass (kèm CWE-ID) · name rõ · summary nêu ASSET bị ảnh hưởng + BUSINESS IMPACT · asset_ids link asset · evidence = PoC TÁI LẬP từng bước + CVSS v3.1 vector + CWE + REMEDIATION cụ thể · traffic_refs = request/response THẬT (baseline control + proof + verification, đúng thứ tự tái lập). DEDUP (không báo trùng, 1 bug class gộp 1 finding + list biến thể) + đã FP-check. THIẾU PoC/evidence/traffic = CHƯA đủ, không report.
- DONE PHASE 3 khi: mọi tech/version đã map CVE; mọi lead đã VERIFY (xác nhận | FP); mọi cái CONFIRMED đã report_finding chuẩn.
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
- ACCOUNT AUTH: tự đăng ký 1 account test; tuân giới hạn ở RULES (không brute/spray/khoá account/thanh toán thật). default/leaked cred login được -> STOP + report ngay.
- ROUTE skill (dùng ĐƯỢC mọi skill trong hệ thống, đây chỉ là map gợi ý): web->web-pentest; SMB/LDAP/Kerberos/RDP->network-attack + active-directory-attack; cloud->cloud-security; docker/k8s->container-k8s-escape; secret->red-team-ops; code/SAST->semgrep-sast + appsec-code-audit; bug-bounty->bug-bounty-methodology; shell->privesc-linux/privesc-windows + living-off-the-land + edr-evasion; hash->password-cracking; mobile/CI-CD/AI-MCP + bất kỳ skill khớp nào khác.
- Confirm bằng PoC marker AN TOÀN (không payload phá hoại).
- DONE PHASE 4 (mỗi domain): mọi endpoint (JS+crawl+API) đã test auth+unauth; đã thử bypass; mọi lỗ xác nhận -> report_finding chuẩn. Có foothold -> sang PHASE 5.
EOF
)

P5=$(cat <<'EOF'
## PHASE 5 — HẬU KHAI THÁC (leo quyền TỚI CÙNG — cần foothold THẬT; đừng bịa bước chưa thực thi)
- Loot: SSH key, .env/config/DB cred, token/secret, cloud metadata trong host.
- Cred matrix: tái dùng mọi cred/hash qua mọi service + auth surface.
- PrivEsc TA0004: linpeas/winpeas; sudo/SUID/misconfig. AD: LSASS/DPAPI/DCSync (scoped), BloodHound (offline), ADCS ESC, Kerberos delegation/RBCD, NTLM relay+coercion, PtH/PtT, trust abuse.
- Lateral TA0008: cred tái dùng, SSH -> enum nội bộ/RFC1918 + token SA container/k8s -> container escape.
- Persistence TA0003 (ĐẢO-NGƯỢC + log) · C2 TA0011 (test egress/DLP bằng callback DNS/HTTPS, KHÔNG implant). OPSEC: né AMSI/ETW/EDR chỉ-ghi-tài-liệu, không làm hỏng host.
- SURFACE MỚI (host/domain/IP nội bộ từ loot/.env/SSRF/pivot/cert/RFC1918) -> theo CỘNG DỒN (INV #5): nối cuối QUEUE + xử lý khi tới lượt.
- DONE PHASE 5 (mỗi foothold): đã loot + cred-matrix + thử privesc/lateral tới hạn; mọi quyền/pivot đạt được -> report_finding; surface nội bộ mới -> QUEUE.
EOF
)

P6=$(cat <<'EOF'
## PHASE 6 — MỤC TIÊU + BÁO CÁO
- Objective TA0009: đạt crown jewels; CHỨNG MINH tác động thật — MÔ PHỎNG bước phá hoại cuối (wipe/ransom/mass-delete), KHÔNG thực thi.
- CONVERGENCE "xong" = objective đạt, HOẶC mọi ledger item terminal (tested / reasoned-negative / out-of-scope / deferred-có-lý-do). BẮT BUỘC: MỖI domain + MỖI IP đã được XỬ LÝ TUẦN TỰ xong (một task duy nhất, không bỏ mục nào), đã qua VHOST MATRIX sống+chết, mọi IP phủ port-scan + vhost, mọi endpoint JS đã test, đã khai thác sâu tới hạn, và KHÔNG còn domain/IP mới phát hiện mà chưa đưa vào scope + xử lý. Baseline (resolve+probe+port-scan+vhost) KHÔNG BAO GIỜ defer.
- REPORT (skill report-writing): executive summary + attack-path narrative (bước->technique->kết quả) + ATT&CK heatmap + detection gaps (fired/miss) + IOC cho blue (hash/C2/timestamp) + fix blue-team ưu-tiên + deconfliction + cleanup log. report_finding theo CHUẨN FINDING client-grade (severity/CVSS/CWE/evidence/traffic/remediation — xem PHASE 3) trước, rồi lắp report từ các finding đó; mỗi finding 1 mục có tái-lập + impact + fix.
EOF
)

NL=$'\n\n'
DESC="${MISSION}${NL}${RULES}${NL}${P1}${NL}${P2}${NL}${P3}${NL}${P4}${NL}${P5}${NL}${P6}"

GOAL="RED TEAM / PENTEST được cấp phép (MITRE ATT&CK), theo 6 PHASE: recon -> map + mỗi domain/IP = 1 worker (add_intent) trong 1 task, chạy LẦN LƯỢT (KHÔNG tạo task mới, không đồng thời; VHOST MATRIX cả sống lẫn chết x mọi IP) -> phân tích lỗ hổng -> khai thác -> hậu khai thác (leo quyền/lateral/persistence tới cùng) -> đạt crown jewels + chứng minh tác động + báo cáo. Có kỷ luật: không DoS/phá hoại production."

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
