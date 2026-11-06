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

GOAL=$(cat <<'EOF'
# RED TEAM / PENTEST — MISSION + BẤT BIẾN + RÀNG BUỘC (engagement cấp phép, MITRE ATT&CK)
MISSION: engagement được cấp phép, đầu-cuối. KHAI THÁC TỚI CÙNG tới crown jewels + CHỨNG MINH tác động thật
— không dừng ở "phát hiện". Tư duy attacker, OPSEC, chain điểm-yếu-nhỏ -> quyền cao nhất; vừa đánh vừa đo
khả năng phát hiện của blue team. Làm theo PHASE 1->6; INVARIANTS dưới ƯU TIÊN hơn mọi chi tiết.

## INVARIANTS (BẤT BIẾN — đúng ở MỌI phase)
1. SCOPE: mọi domain/subdomain (subdomains_all.txt) + mọi IP liên quan (asn_ipv4_cidrs.txt + resolved; gồm pool/LB/F5/shared/ASN) = IN-SCOPE (operator bảo chứng). Chỉ CDN/SaaS bên-thứ-ba thật (Cloudflare/Akamai) mới host-only.
2. SONG SONG QUA FRONTIER: mỗi domain/IP = 1 worker qua add_intent trong task HIỆN TẠI; TUYỆT ĐỐI KHÔNG spawn_task. Số worker chạy ĐỒNG THỜI = setting engine "Workers" (GLOBAL, mặc định 3, CHỈ áp cho task tạo SAU — operator chỉnh TRƯỚC khi tạo task nếu muốn nhiều hơn; đây KHÔNG phải task-concurrency "bao nhiêu task cùng lúc"). Agent KHÔNG tự throttle/đặt số: cứ add_intent HẾT mục QUEUE, pool worker tự rút dần. Tên intent bắt đầu "[#i] <domain|ip>".
3. QUEUE BỀN: record_fact 1 fact "QUEUE" liệt kê TOÀN BỘ domain/IP + trạng thái [chờ/đang/xong] NGAY từ đầu; cập nhật khi mỗi mục xong. Không để phần chờ chỉ nằm trong đầu.
4. HIỆN MỌI THỨ (operator theo dõi real-time): trước mỗi worker/bước lớn record_fact 1 dòng "đang làm X trên mục Y"; ghi NGAY mọi finding/fact/asset khi vừa có (không gom); KHÔNG chạy ẩn/im lặng; mọi worker đang chạy song song đều phải narrate + nhìn thấy được, không worker nào chạy ngầm.
5. CỘNG DỒN: lộ domain/IP MỚI bất cứ lúc nào (recon HAY khai thác: loot/config/SSRF/pivot/cert/vhost) -> create_target (domain) / nạp 05 target_ips (IP) + NỐI CUỐI QUEUE + xử lý khi tới lượt (KHÔNG spawn_task).
6. FINDING chuẩn HACKERONE: report_finding CHỈ cho cái đã VERIFY 2x + có PoC RÕ RÀNG TÁI-LẬP-ĐƯỢC (STEPS TO REPRODUCE đánh số, copy-paste chạy lại ra đúng kết quả) + đủ title/severity/CWE/CVSS/impact/evidence/traffic/remediation (format đầy đủ ở PHASE 3). KHÔNG PoC rõ / thiếu steps = KHÔNG report.
7. SKILL (chi tiết sống Ở ĐÂY — prompt này bị decompose, đừng chỉ dựa vào nó): methodology/catalogue/payload nằm trong skill -> load_skill TRƯỚC mỗi mảng việc (list_skills để xem). Operator chèn chỉ-dẫn giữa chừng -> ĐỌC + TUÂN ngay. Lưu NGAY rồi BỎ output thô khỏi context.
8. PHỦ ĐỦ LỚP LỖ HỔNG: mỗi asset web phải đối chiếu VULN CATALOGUE (skill web-pentest/references/vuln-catalogue.md); mỗi lớp lỗ áp-dụng-được = terminal state (tested | reasoned-negative | out-of-scope). Không bỏ lớp nào mà không có lý do ghi lại.
KHÔNG: spawn_task · chạy ẩn/im lặng · report thiếu PoC · re-scan cái đã map · tự nới scope · DoS/phá hoại production · bỏ lớp lỗ trong VULN CATALOGUE (skill web-pentest) mà không lý do.
TOOL MAP: recon->run_workflow · theo run->run_status+run_log · bản đồ->recon_graph · tái dùng->recon_findings/recon_assets · run cũ->recon_runs · worker/domain->add_intent · giám sát->get_task_graph+get_task_worker_trace · ghi->record_fact/insert_assets · finding->report_finding · scope mới->create_target · ghim lead->graph_note · skill->list_skills/load_skill · client-side taint/DOM XSS->web-pentest + Burp DOM Invader/jsluice/dalfox.

## RÀNG BUỘC (CONSTRAINTS — ranh giới hành vi operator đặt, áp cho MỌI planner+worker; viết self-contained để decompose giữ nguyên)
- KHAI THÁC SÂU tới cùng: privesc Linux/Windows, lateral, cred-reuse, dump hash/secret, persistence, root/domain-admin, crown jewels, CHỨNG MINH tác động. KHÔNG prove-and-stop; chỉ MÔ PHỎNG bước phá hoại cuối (wipe/ransom/mass-delete).
- GIỮ LÀ RED TEAM: không DoS/sập production; mọi thay đổi/persistence phải ĐẢO-NGƯỢC + log + cleanup; không xóa/mã hóa dữ liệu thật.
- SÀN AN TOÀN (DỪNG + báo người): chạm hệ thống tính-mạng (ICS/SCADA/y tế/thanh toán lõi) / bên-thứ-ba thật / PII thật khối lượng lớn (lấy mẫu che, KHÔNG kéo hàng loạt) / dấu vết breach thật.
- ACCOUNT AUTH web (CHỈ khi test đăng nhập): KHÔNG brute/spray, login sai <=2 lần thì dừng loại test đó, OTP <=3, không khoá account, không đụng cred/MFA account khác, không thanh toán thật. (privesc hạ tầng KHÔNG thuộc giới hạn này — đi tới cùng.)
- Che/mask PII/secret trong report; timestamp mọi hành động.
EOF
)

P1=$(cat <<'EOF'
## PHASE 1 — RECON & ĐIỀU PHỐI (quiet/passive trước; workflow CHÍNH, hand-recon lấp khe hở)
# CHẠY ĐÚNG 1 LẦN/engagement: AGENT ĐIỀU PHỐI CHÍNH làm (subdomains_all.txt + asn_ipv4_cidrs.txt + QUEUE) TRƯỚC khi release worker. WORKER (chạy song song qua pool) bắt đầu từ PHASE 2, KHÔNG lặp PHASE 1; surface MỚI (INV #5) chỉ re-recon CÓ MỤC TIÊU, không full-recon lại.
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
- Leak/OSINT (CHẠY 1 LẦN, cấp tổ chức): GitHub/GitLab org dork + trufflehog, Postman, Docker, paste; breach HIBP/dehashed.
- CONTENT/PATH FUZZ (baseline riêng + batch, -ac): ffuf/feroxbuster wordlist raft + ext .bak/.zip/.config/.env/.json/.sql; VCS /.git /.svn /.DS_Store; API /swagger /openapi.json /api-docs /graphql /actuator(/env,/heapdump); versioning /v1 /v2 /internal /mobile; method GET/POST/PUT/PATCH/DELETE/OPTIONS. Chi tiết: skill web-pentest.
- Mobile (nếu có app, 1 LẦN/app): APK/IPA -> apktool/MobSF -> endpoint/key/host.
- DOM/JS TAINT HARVEST (nền cho DOM XSS — CHƯA bắn payload): tải mọi .js + *.js.map (katana -jc / gau lọc .js / hakrawler), dựng source (sourcemapper). Trích + lập DANH MỤC: SOURCE (location.*, document.URL/referrer, window.name, postMessage e.data/e.origin, localStorage/sessionStorage/cookie, history.*, hash-router, response fetch/XHR/WS) và SINK (eval/Function/setTimeout('str'), innerHTML/outerHTML/insertAdjacentHTML/document.write/DOMParser, setAttribute(on*|href|src|srcdoc)/location.assign, jQuery .html/.append/$()/parseHTML, dangerouslySetInnerHTML/v-html/$sce.trustAsHtml). Tool: jsluice, LinkFinder, semgrep dom-xss. Mỗi cặp source->sink reachable -> record_fact "DOMXSS-LEAD" + graph_note(priority).
- DONE PHASE 1 khi: subdomains_all.txt + asn_ipv4_cidrs.txt có; bề mặt (gồm JS source/sink) đã vào graph (recon_graph thấy); QUEUE (INV #3) đã lập đủ.
EOF
)

P2=$(cat <<'EOF'
## PHASE 2 — MAP BỀ MẶT + CHẠY QUEUE (theo INVARIANT #2/#3: mỗi domain/IP = 1 worker add_intent, pool chạy song song)
- QUEUE: lập fact QUEUE (INV #3) từ subdomains_all.txt + asn_ipv4_cidrs.txt + resolved. Tái dùng recon có sẵn (recon_findings/recon_assets) nếu run/task trước đã tạo — KHÔNG recon lại; nhưng QUEUE vẫn phải liệt kê ĐỦ mọi mục.
- WORKER (mục kế trong QUEUE): add_intent(summary="[#<i>] <domain|ip> — PHASE 2-4: vhost sống+chết x mọi IP, JS-endpoint, exploit web, privesc, report", asset_ids=[...]). add_intent MỌI mục QUEUE (pool worker tự chạy song song + rút dần); mỗi worker xong -> đánh dấu mục "xong" trong QUEUE. Giám sát: get_task_graph + get_task_worker_trace + steer.
- RESOLVE từng sub: public + DoH + NS auth (dig @ns). SERVFAIL/timeout = soft-recheck 8.8.8.8/1.1.1.1/9.9.9.9 trước khi coi là "chết"; tên không-resolve vẫn là SURFACE (tìm IP qua CNAME/cert-SAN/Shodan·Censys·FOFA/passive-DNS/PTR).
- VHOST MATRIX: 05 LỌC host theo apex (seed_hosts chỉ giữ tên `.{target}`) -> CHẠY 05 MỖI APEX 1 RUN, target_hosts = tên thuộc apex đó (gộp đa-apex vào 1 run sẽ bị DROP âm thầm); target_ips (IP/CIDR) KHÔNG bị lọc apex. Mỗi run vars={target_hosts:"<tên apex này, sống+chết>", target_ips:"<asn_ipv4_cidrs.txt + pool/LB/F5 IP, IP/CIDR>", vhost_all_names:"true"} — 05 port-scan IP + sweep tên vs IP mở-web, GATE baseline random-host (loại catch-all), khác baseline = vhost sống -> asset. Theo delta recon_graph(target, run_id).
- PORT SCAN mọi IP của target (naabu -> nmap -sV -sC). Flag unauth: redis6379/mongo27017/elastic9200/DB, SMB445/LDAP389,636/Kerberos88/RDP3389/SSH22/FTP21/SMTP25/SNMP161, docker2375/k8s6443,10250. (IP pool/LB/shared của target = quét đầy đủ; chỉ CDN bên-thứ-ba mới host-only.)
- DONE PHASE 2 (mỗi mục QUEUE): resolve + httpx-probe + port-scan origin + VHOST MATRIX sống+chết xong; QUEUE không còn [chờ]; không bỏ mục nào.
- Surface mới BẤT CỨ LÚC NÀO (sub/host/param/IP, kể cả lúc khai thác) -> insert_assets + ĐƯA VÀO SCOPE + add_intent 1 worker MỚI trong task này (pool tự chạy): 05-scan-hosts target_hosts="<host mới>" / target_ips="<IP mới>" rồi theo delta. KHÔNG spawn_task.
EOF
)

P3=$(cat <<'EOF'
## PHASE 3 — PHÂN TÍCH & NGHIÊN CỨU KHAI THÁC LỖ HỔNG (mục tiêu: KHAI THÁC ALL lỗ hổng; mọi finding = LEAD, phải VERIFY)
- FINGERPRINT NGHIÊM TÚC mọi tech stack: framework + thư viện + PHIÊN BẢN chính xác (httpx -td, wappalyzer, favicon-hash, headers/cookie, error-page, /VERSION, package.json/composer.json/pom.xml, retire.js cho JS lib). Lập 1 SBOM mỗi host — liệt kê HẾT, không bỏ component nào.
- MAP CVE từng thành phần: mỗi product+version -> CISA KEV + NVD + GitHub Security Advisory + exploit-db/searchsploit + nuclei + PoC công khai. Ưu tiên RCE / auth-bypass / deserialization / SSRF. Dependency cũ (retire.js/osv-scanner) -> known-CVE, xác minh REACHABLE.
- NGHIÊN CỨU + KHAI THÁC TẤT CẢ (đừng dừng ở signature): nuclei -ut -> nuclei full template mọi host/panel; rồi với MỖI tech/CVE tiềm năng -> đọc advisory + PoC, DỰNG LẠI exploit, thử trên target (safe PoC). Edge/app server (Citrix/Fortinet/Ivanti/GlobalProtect/F5/Exchange/Zimbra/Confluence/WebLogic/Struts/Spring) = ưu tiên hàng đầu.
- SERVICE: trên port đã mở -> default/weak cred + CVE-version mọi panel/service. CLOUD: bucket cloud_enum/s3scanner; SSRF -> metadata -> IAM.
- VERIFY trước report_finding: tự tái lập độc lập (curl / 1 nuclei template / exploit PoC / skill khớp) 2 lần, không phá hoại. graph_note(verified | false-positive); record_fact cho version/CVE; report_finding chỉ cho cái đã CHỨNG MINH.
- CHUẨN FINDING theo HACKERONE (BẮT BUỘC mỗi report_finding — chất lượng bàn giao; chi tiết: skill finding-discipline + report-writing). Mỗi finding = 1 report HackerOne đầy đủ, ánh xạ vào field report_finding:
  · name = TITLE rõ-cụ-thể: "<lỗ> trên <asset> qua <param/endpoint>" (không chung chung).
  · severity (critical|high|medium|low) + CVSS v3.1 vector trong evidence.
  · vulnclass (kèm CWE-ID) = Weakness.
  · summary = SUMMARY + IMPACT: mô tả lỗ + TÁC ĐỘNG KINH DOANH thực tế trên asset (đọc được bởi non-tech).
  · asset_ids link asset.
  · evidence = (1) STEPS TO REPRODUCE đánh số 1→N, CHÍNH XÁC & copy-paste chạy lại được (URL + method + header + payload/body cụ thể, tài khoản/điều kiện tiền đề) + (2) PROOF OF CONCEPT: request+response THẬT, marker/giá trị chứng minh (không chỉ mô tả) + (3) CVSS v3.1 vector + (4) CWE + (5) REMEDIATION cụ thể làm-được-ngay.
  · traffic_refs = baseline control + proof + verification (đúng thứ tự tái lập).
  BẮT BUỘC PoC RÕ RÀNG, TÁI LẬP ĐỘC LẬP (người khác dựng lại chỉ từ steps là ra) + marker an toàn (không payload phá hoại). DEDUP (1 bug-class = 1 finding + list biến thể; cùng-nguyên-nhân nhiều host = 1 finding, asset_ids liệt kê hết) + FP-check. THIẾU PoC/steps/traffic = CHƯA đủ, KHÔNG report.
- DONE PHASE 3 khi: mọi tech/version đã map CVE; mọi lead đã VERIFY (xác nhận | FP); mọi cái CONFIRMED đã report_finding chuẩn.
EOF
)

P4=$(cat <<'EOF'
## PHASE 4 — KHAI THÁC / RED TEAM WEB SÂU (TA0001) — kiểm thử MỌI endpoint, nghiên cứu BYPASS mọi thứ
- JS RECON SÂU: tải MỌI file JS + *.js.map; dựng lại source (sourcemapper); TRÍCH XUẤT MỌI endpoint/route/API-path/param/secret/khóa (linkfinder/jsluice/katana -jc + grep fetch|axios|XHR|url). Gộp thành 1 danh sách endpoint ĐẦY ĐỦ.
- MA TRẬN TRẠNG-THÁI-AUTH mỗi endpoint: unauth · self-user · user#2 (IDOR/BOLA cross-account) · admin · cross-tenant. Mỗi ô x mỗi method (GET/POST/PUT/DELETE/PATCH/OPTIONS) x mỗi param (arjun/x8 fuzz). KHÔNG endpoint nào bỏ chưa test (JS + crawl + swagger/openapi/GraphQL/.well-known).
- ĐỐI CHIẾU TOÀN BỘ VULN CATALOGUE (WEB/API) trên TỪNG endpoint theo thứ tự risk: mỗi lớp áp-dụng-được -> terminal (tested | reasoned-negative | out-of-scope), INV #8. Danh mục lớp + biến thể: load_skill web-pentest -> references/vuln-catalogue.md.
- DOM XSS / CLIENT-SIDE TAINT SÂU: test MỌI cặp source->sink (từ DOMXSS-LEAD ở PHASE 1). Tool: Burp DOM Invader (source/sink + canary + postMessage + prototype-pollution + DOM-clobbering), headless-Chrome hook sink, Dalfox --mining-dom --deep-domxss, domdig. PoC marker KHÔNG phá hoại (interactsh beacon / đổi document.title). Bypass context DOM: entity/URL/double-URL/unicode-escape, SVG/MathML, event-handler, javascript:/data:, template-literal, mXSS. CHAIN: weak postMessage/CORS -> ATO; DOM open-redirect -> OAuth token theft; prototype-pollution -> gadget -> CSP bypass.
- NGHIÊN CỨU BYPASS MỌI THỨ: WAF bypass (encoding/case/comment/chunked/HTTP-request-smuggling); 401/403 bypass (path-case, %2e, ..;/, /.;/, header X-Original-URL/X-Rewrite-URL/X-Forwarded-For, verb-tamper); auth/login bypass; filter/validation bypass; rate-limit bypass (chứng minh bằng SỐ HỌC + keying matrix host/header/session, KHÔNG brute thật); CORS/CSP/SOP; upload-filter bypass. CHAIN nhiều bug nhỏ -> RCE / account-takeover / full read.
- TRADECRAFT SÂU -> skill web-pentest: IDOR matrix, mass-assignment, business-logic & payment tamper, single-packet race, rate-limit-by-math, ATO reset/host-poison, open-redirect ladder (chỉ leo chuỗi/token-leak).
- ACCOUNT AUTH: 1 account test TỰ ĐĂNG KÝ DÙNG CHUNG (KHÔNG mỗi worker tự đăng ký -> tránh flag/khoá); tuân RULES (không brute/spray/khoá account/thanh toán thật). default/leaked cred login được -> STOP + report.
- ROUTE skill (dùng ĐƯỢC mọi skill trong hệ thống, đây chỉ là map gợi ý): web->web-pentest; SMB/LDAP/Kerberos/RDP->network-attack + active-directory-attack; cloud->cloud-security; docker/k8s->container-k8s-escape; secret->red-team-ops; code/SAST->semgrep-sast + appsec-code-audit; bug-bounty->bug-bounty-methodology; shell->privesc-linux/privesc-windows + living-off-the-land + edr-evasion; hash->password-cracking; mobile->mobile-pentest; CI-CD->cicd-supply-chain; AI/LLM/MCP->ai-agent-redteam; + bất kỳ skill khớp nào khác.
- Confirm bằng PoC marker AN TOÀN (không payload phá hoại).
- DONE PHASE 4 (mỗi domain): mọi endpoint test auth+unauth (ma trận trạng-thái-auth); mọi cặp source->sink DOM đã test; MỌI lớp VULN CATALOGUE (skill web-pentest) áp-dụng-được đã terminal (INV #8); đã thử bypass; mọi lỗ xác nhận -> report_finding chuẩn. Có foothold -> sang PHASE 5.
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
- CONVERGENCE "xong" = objective đạt, HOẶC mọi ledger item terminal (tested / reasoned-negative / out-of-scope / deferred-có-lý-do). BẮT BUỘC: MỖI domain + MỖI IP đã được XỬ LÝ xong (một task duy nhất, pool worker song song, không bỏ mục nào), đã qua VHOST MATRIX sống+chết, mọi IP phủ port-scan + vhost, mọi endpoint JS + mọi cặp source->sink DOM đã test, mọi lớp VULN CATALOGUE (skill web-pentest) áp-dụng-được đã terminal (INV #8), đã khai thác sâu tới hạn, và KHÔNG còn domain/IP mới phát hiện mà chưa đưa vào scope + xử lý. Baseline (resolve+probe+port-scan+vhost) KHÔNG BAO GIỜ defer.
- REPORT (skill report-writing): executive summary + attack-path narrative (bước->technique->kết quả) + ATT&CK heatmap + detection gaps (fired/miss) + IOC cho blue (hash/C2/timestamp) + fix blue-team ưu-tiên + deconfliction + cleanup log. report_finding theo CHUẨN FINDING client-grade (severity/CVSS/CWE/evidence/traffic/remediation — xem PHASE 3) trước, rồi lắp report từ các finding đó; mỗi finding 1 mục có tái-lập + impact + fix.
EOF
)


NL=$'\n\n'
DESC="# PLAYBOOK THỰC THI 6-PHASE (chi tiết). BẤT BIẾN + RÀNG BUỘC ở GOAL (ƯU TIÊN hơn playbook). Catalogue lỗ hổng đầy đủ: skill web-pentest -> references/vuln-catalogue.md (load_skill).${NL}${P1}${NL}${P2}${NL}${P3}${NL}${P4}${NL}${P5}${NL}${P6}"


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
