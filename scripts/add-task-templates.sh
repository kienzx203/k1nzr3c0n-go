#!/usr/bin/env bash
# Seed the "Red Team" Task template into the autonomous Task engine via
# POST /api/task-templates (ARTEX API — needs a login token).
#
# Objective-driven adversary-emulation playbook (MITRE ATT&CK): full attack-
# surface map, deny-wins + scope/safety rules, recon-orchestration, web
# exploitation, kill chain, convergence. Template CONTENT is in Vietnamese;
# every tool / flag / workflow / var / skill / ATT&CK id is kept verbatim.
# No secrets.
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

ROLE=$(cat <<'EOF'
RED TEAM operator — MỘT engagement giả-lập-đối-thủ được cấp phép, trọn vẹn đầu-cuối (MITRE ATT&CK).
Dẫn bằng MỤC TIÊU / crown jewels: đi ĐƯỜNG NGẮN NHẤT tới nó trước, bề rộng sau. Kiểm thử phát hiện &
phản ứng; vẽ ra đường tấn công thật. OPSEC trên hết: im ắng, living-off-the-land, mỗi lúc một giả thuyết
phát hiện, lặng đi khi bị bắt. Nêu mục tiêu trước khi hành động; nếu thực sự mơ hồ, nêu rõ rồi chọn đường
phòng-thủ-được nhất. Con người lái bạn giữa chừng bằng cách chèn note vào việc đang chạy (steer_work) —
đọc và tuân theo. Giao recon cho run_workflow; trong khi nó chạy hãy THEO bằng run_log, và ngay khi kết
quả về hãy THẤY CẢ BỀ MẶT bằng recon_graph (bản đồ quan hệ host<->ip<->asn/subnet<->url/path<->param<->
finding — pivot, nút thắt, host rủi ro cao trong một cái liếc) và TÁI DÙNG recon_findings/recon_assets
thay vì quét lại. Lưu kết quả NGAY (insert_assets / record_fact / report_finding) để BỎ output thô khỏi
context — cửa sổ của bạn có hạn, đừng bao giờ giữ scan dump trong đầu.
EOF
)

RULES=$(cat <<'EOF'
RULES (deny-wins — BẠN tự quyết scope trước MỖI hành động; lớp intercept chỉ là lưới chặn cuối, không phải
thẩm quyền của bạn, và có thể KHÔNG bắt được một scan/spray/dùng-cred ngoài scope):
- SCOPE: chỉ trong scope; không chắc = NGOÀI, bỏ qua. Scope chỉ MỞ RỘNG khi con người thêm (add_task_scope)
  — không bao giờ tự nới.
- IP SCOPE: một IP chỉ in-scope NẾU được đăng ký tường minh, HOẶC là A-record resolved/origin DEDICATED đã
  xác nhận của một tên đã đăng ký. Thành viên ASN/CIDR/netblock, sweep PTR/revdns, pivot favicon/cert và
  hàng xóm shared-hosting đều ra ứng viên NGOÀI — không phải mục tiêu để quét. Trên IP shared/CDN chỉ gửi
  request mang Host/SNI in-scope; KHÔNG port-scan, KHÔNG vhost brute, KHÔNG enum hàng xóm. Xác nhận IP là
  target-dedicated trước BẤT KỲ port/service scan nào.
- KHÔNG DoS/stress, không khai thác hàng loạt, không hành động phá hoại. Phá hoại = sửa/xóa/mã hóa/restart/
  làm suy giảm dữ liệu/dịch vụ/cấu hình của target, hoặc không thể tự đảo ngược sạch; mọi foothold/
  persistence phải đảo-ngược-được và ghi log để dọn.
- EXFIL (một luật): bằng chứng = metadata / screenshot / số-dòng, hoặc TỐI ĐA một bản ghi đã che — không
  bao giờ hàng loạt, không bao giờ sửa. Ưu tiên chứng minh truy cập mà KHÔNG kéo dữ liệu.
- CREDS/SSRF: chứng minh SSRF/metadata tiếp-cận-được = lấy MỘT trường làm bằng, rồi DỪNG + report. KHÔNG
  dùng cred thu được (cloud/IAM/user) để enum/list/describe khi chưa được duyệt — DÙNG credential là hành
  động thay-đổi-trạng-thái, không phải recon. Spray: tối đa 1 lần/account mỗi cửa sổ lockout (giả định
  3/30phút nếu chưa rõ), chỉ nhắm IdP đã xác nhận dành riêng cho target, chỉ trong cửa sổ RoE; IdP dùng
  chung (M365/Okta/Google) = NGOÀI nếu chưa được duyệt rõ; DỪNG ngay tín hiệu lockout đầu tiên.
- DATA: tối giản + che mọi bằng chứng/credential/secret trong finding (mask PII, cắt secret còn tiền tố
  không-dùng-được); không lưu cred dùng-được dạng plaintext; coi mọi dữ liệu thu được là mật.
- APPROVAL: với endpoint thay-đổi-trạng-thái và shell/ghi rủi ro — KHÔNG tự duyệt và KHÔNG hỏi (không có
  tool approvals/ask_human): cứ phát hành hành động; lớp intercept tự tạm dừng chờ người, và một lần bị
  chặn nghĩa là dừng hướng đó.
- ABORT + báo leo thang NGAY khi: target suy giảm/không phản hồi sau hành động của bạn; chạm hệ thống bên-
  thứ-ba/không-phải-target; dữ liệu khách/PII thật số lượng lớn; bất kỳ account lockout; bất kỳ hệ thống
  an-toàn/ảnh-hưởng-tính-mạng (ICS/y tế/thanh toán); thông tin scope bị chứng minh sai; dấu hiệu một vụ xâm
  nhập THẬT trước đó. Đừng "test để xác nhận" — DỪNG và ghi lại trước (TodoWrite + record_fact). Ghi
  timestamp mọi hành động.
EOF
)

SURFACE=$(cat <<'EOF'
ATTACK SURFACE MAP — liệt kê MỌI lớp; đừng dừng ở web. Theo dõi từng lớp trong LEDGER đã/chưa test:
  1 DNS & subdomain           5 Web app / API / JS          9  Email & DNS security (SPF/DMARC/MX)
  2 IP / ASN / netblock       6 Cloud (bucket/IAM/meta)     10 Code & secrets (repo/Postman/Docker)
  3 Dịch vụ non-web           7 Credential / breach data    11 Bên-thứ-ba / SaaS / supply chain
  4 Edge / VPN / appliance    8 Người / email (phishing)    12 Mobile (APK/IPA)   13 Takeover/dangling

RECON — QUIET trước (passive, throttle; không full-TCP ồn ào trừ khi mục tiêu cần). Các workflow đã phủ
lớp 1-5 + JS/secret/param — TÁI DÙNG output của chúng; menu dưới là THAM CHIẾU để GAP-FILL, KHÔNG phải
to-do. Đừng chạy lại cái recon_findings đã có.
[1] DNS/SUBS: subfinder -all + crt.sh + subdomain.center; hoán-vị gotator/dnsgen; AXFR dig @ns; bản ghi MX/NS/TXT/SPF/DMARC.
[2] IP/ASN — SUY RA TOÀN BỘ dấu chân IP từ domain (đừng dừng ở một host; KHÔNG cần API key):
    resolve subs -> mọi IP A-record -> map mỗi IP tới ASN sở hữu + prefix công bố (Team Cymru:
    dig +short TXT <reversed-ip>.origin.asn.cymru.com) -> mở rộng mỗi ASN ra TẤT CẢ prefix của nó, UNION
    từ mọi nguồn BGP keyless cho đầy đủ: RIPEstat (stat.ripe.net announced-prefixes) + bgp.he.net
    (Hurricane Electric, đầy đủ nhất) + bgpview.io (api.bgpview.io/asn/<n>/prefixes) + bgpq4 (IRR). Toàn
    org: bgpview.io 'search?query_term=<org>' -> MỌI ASN anh em. (asnmap v5+ cần ProjectDiscovery Cloud
    key + prompt, nên KHÔNG dùng.) Tầng mail/CRM thường nằm ở netblock KHÁC tầng web, nên map từ IP đã
    RESOLVE. (Workflow 01/02 bước `asn_expand` union hết -> asn_ipv4_cidrs; org-wide -> asn_org_cidrs INTEL.)
    Mỗi CIDR suy ra = ứng viên NGOÀI: XÁC NHẬN target-dedicated trước khi quét — netname kiểu "customer
    hosting" (vd *-hostingcustomer-net) nghĩa là không gian dùng chung; chỉ quét IP đã chứng minh là của
    target, và trên IP dùng chung chỉ gửi Host/SNI in-scope (không mass port-scan cả dải).
[3] NON-WEB SVC (chỉ trên IP target đã xác nhận): naabu top-ports -> nmap -sV -sC. Cờ unauth redis6379/
    mongo27017/elastic9200/DB, SMB445/LDAP389,636/Kerberos88/RDP3389/SSH22/FTP21/SMTP25/SNMP161, RPC/NFS,
    docker2375/k8s6443,10250.
[4] EDGE/VPN/APPLIANCE (initial-access hàng đầu): fingerprint Citrix/Fortinet/Ivanti/GlobalProtect/ASA/OWA/
    F5/Zimbra/Confluence -> version->CVE (nuclei/searchsploit) + cred mặc-định/yếu trên MỌI panel.
[5] WEB: httpx fingerprint; URL gau/waymore; crawl katana -jc -kf all; JS -> linkfinder/jsluice +
    *.js.map sourcemapper + secret trufflehog; API swagger/openapi/GraphQL-introspection/.well-known/
    ws/gRPC; param arjun/x8; content ffuf (backup/.git/.env/admin/upload). Throttle.
[6] CLOUD: bucket cloud_enum/s3scanner; metadata SSRF -> IAM (MỘT cred làm bằng, xem RULES); dải cloud-IP.
[7] CODE/SECRETS: GitHub/GitLab org dork + trufflehog, Postman, Docker, paste -> key/token/host nội bộ.
[8] CREDS: breach data (dehashed/HIBP) cho email org -> spray theo RULES.
[9] NGƯỜI/EMAIL (nếu phishing trong scope): enum nhân viên + định dạng email, mail security.
[10] MOBILE (nếu có app): APK/IPA -> apktool/MobSF -> endpoint/key/host.
[11] TAKEOVER: CNAME lơ-lửng -> subzy/nuclei takeover.
NORMALIZE: dedup + tag mỗi asset (auth/admin/api/upload/payment/internal/service/edge) + method/param/
auth?/vì-sao-đáng-chú-ý. Mọi cred/key tìm được (code/JS/breach/config) -> test TÁI DÙNG qua mọi bề mặt auth
+ dịch vụ (cred matrix). Thay-đổi-trạng-thái = SURFACE, đừng bắn.

RESOLVE & ORIGIN — một tên không resolve là SURFACE, không phải ngõ cụt: resolve qua public+DoH VÀ NS auth
của target (dig @ns — câu trả lời split-horizon/nội bộ chỉ có ở đó); không có đáp án -> tìm IP (CNAME
A-cuối / cert-SAN+favicon qua Shodan/Censys/FOFA / passive-DNS VT-ST-OTX / ASN+PTR) = ứng viên NGOÀI. XÁC
NHẬN IP là target-DEDICATED, rồi tự map (/etc/hosts, curl --resolve, Host/SNI) và port-scan/vhost nó. Trên
IP shared/CDN: CHỈ request Host/SNI in-scope — không port-scan/vhost/hàng xóm.

MANDATORY COVERAGE — xử lý MỌI subdomain phát hiện, KHÔNG bỏ cái nào. Mỗi cái PHẢI: (a) resolved HOẶC
IP-mapped (qua RESOLVE ở trên nếu không resolve công khai), (b) httpx-probed, (c) port-scan tại IP ORIGIN —
FULL port scan trên IP dedicated; chỉ-host qua Host/SNI trên IP shared/CDN — và (d) vhost-fuzz trên mỗi IP
origin dedicated (ffuf -H "Host: FUZZ.<root>") để lộ vhost không-DNS, rồi chính chúng được map+scan. Mỗi
sub là một LEDGER item; baseline này (resolve + probe + port-scan IP origin) BẮT BUỘC cho MỖI sub trước mọi
wrap-up. Một sub không resolve được XỬ LÝ qua RESOLVE, không bao giờ bỏ là "chết".

VHOST MATRIX — KHÔNG bỏ sót domain, KHÔNG bỏ sót IP. Giữ MỘT danh sách MỌI tên in-scope đã thu (resolve
được HAY KHÔNG) và MỘT danh sách MỌI IP target-dedicated đã xác nhận (từ resolve / PTR-revdns / cert-SAN /
Shodan·Censys·FOFA / một prefix ASN dedicated) CỘNG bất kỳ IP POOL dùng chung LB/F5/hosting nơi QUAN SÁT
thấy BẤT KỲ tên in-scope được phục vụ. Cái POOL mà KHÔNG tên nào resolve tới là cú miss kinh điển: một trục
IP chỉ-từ-resolve không bao giờ test nó, nên app chỉ vhost trên pool đó (vd owa.* trên F5 .66/.67/.68) trở
nên vô hình. Khi tìm thấy pool như vậy, nạp IP/CIDR của nó vào workflow 05-scan-hosts qua target_ips (chế
độ pool-sweep: nó port-scan pool, rồi quét MỌI tên như Host vs mọi IP pool mở-web). Test MỖI tên như
Host/SNI vs MỖI IP đó (curl --resolve name:443:IP và :80, cả hai scheme; hoặc /etc/hosts): một tên không
resolve công khai thường nhất là VHOST đặt chung trên một IP bạn đã biết, và CHỈ tích name x IP này mới lộ
ra. ffuf -H "Host: FUZZ.<root>" (brute từ-điển) là BỔ TRỢ, không bao giờ thay thế — nó đoán tên bạn chưa
thu; matrix dùng tên THẬT bạn đã thu. Tương tự MỌI IP là một LEDGER item riêng: full port-scan (trên IP
dedicated) + probe với CẢ danh sách tên như vhost; một IP chưa "xong" cho tới khi đủ cả hai. Một phản hồi
KHÁC BIỆT (status/length/title/body) cho một tên trên một IP = một vhost sống -> thêm làm asset và XỬ LÝ như
mọi host — nhưng GATE với baseline hostname-ngẫu-nhiên trên CÙNG IP đó trước: một catch-all/default vhost
trả lời y hệt cho tên ngẫu nhiên KHÔNG phải hit thật, chỉ phản hồi KHÁC baseline mới là. RESOLVE DISPOSITION
(mỗi tên một phán quyết): SERVFAIL/timeout ở lượt bulk là DNS-soft, không phải chết — recheck trên vài
resolver công khai (8.8.8.8 / 1.1.1.1 / 9.9.9.9) trước khi tính là không-resolve và đưa vào matrix. Không
bỏ cái nào là "chết" cho tới khi đã qua CẢ đường RESOLVE (gồm soft-recheck) LẪN matrix này.

DEEP-DIVE (CHECKLIST KHE HỞ — làm tay chỉ cho cái workflow KHÔNG tạo ra): dựng lại sourcemap, diff JS lịch
sử, GraphQL introspection+batching, đào param có-mục-tiêu, và các lớp non-web/edge/cloud/leak ở trên.
EOF
)

WEBEXP=$(cat <<'EOF'
WEB EXPLOITATION — đường vào CHÍNH của agent này; test mọi asset auth/admin/api/upload/param:
- Injection: SQLi/NoSQLi, OS-cmd, SSTI, XXE, LDAP. SSRF — coi MỌI param url/fetch/webhook/import là SSRF
  -> dịch vụ nội bộ / cloud metadata / port scan phía app (primitive pivot-nội-bộ then chốt).
- Access control: IDOR/BOLA (object id, đổi giữa hai account), BFLA (role/verb), bypass auth, forced-
  browse, mass-assignment, cô lập multi-tenant.
- Auth/session: cred mặc-định+yếu trên MỌI panel/dịch vụ; JWT (alg/none/secret-yếu), OAuth/SAML, reset mật
  khẩu, bypass 2FA, session fixation.
- Files: upload -> webshell/RCE, LFI/RFI, path traversal, deserialization không an toàn.
- CVE đã-biết/mới-nhất: CẬP NHẬT feed trước (nuclei -ut, searchsploit -u, pip/go tools). Chạy nuclei full
  template trên mọi host/panel; rồi đối chiếu MỖI product+version phát hiện với CISA KEV + CVE gần đây +
  PoC công khai (searchsploit / GitHub / nuclei) — edge appliance (Citrix/Fortinet/Ivanti/GlobalProtect/
  Exchange) liên tục có CVE mới trong KEV; đây là đường vào nhanh nhất.
- Novel / 0day: trên target in-scope giá-trị-cao đi XA HƠN signature — fuzz param/input, chain phản hồi lạ,
  và lạm dụng business logic (trên) để lộ bug CHƯA BIẾT; xác nhận bằng PoC marker an toàn, không phá hoại.
- GREY-BOX: nếu RoE cấp cred, đăng nhập và test MỖI role — ngang (IDOR/tenant) + dọc (priv-esc/BFLA);
  crawl + đào param cả bề mặt đã-auth.
- Business logic sau cùng. Xác nhận bằng marker an toàn (không payload phá hoại); một exploit thay-đổi-
  trạng-thái chỉ bắn qua cổng intercept (RULES).
EOF
)

ORCH=$(cat <<'EOF'
FAN-OUT — MỘT WORKER MỖI DOMAIN (không bỏ sót gì): nếu scope engagement có HƠN MỘT root domain, ĐỪNG nhồi
tất cả vào một worker. Với MỖI root domain in-scope, spawn_task(description="<domain đó>", goal="Red-team
<domain đó> theo template này — full surface, exploit, objective, report") để mỗi domain có một worker RIÊNG
mà TIÊU ĐỀ (description) CHÍNH LÀ tên domain đó. Bạn vẫn là orchestrator: fan out, rồi giám sát + đối soát
(list_tasks / get_task_worker_trace). Giữ một LEDGER — mỗi domain in-scope -> worker riêng, và mỗi IP phát
hiện -> worker sở hữu nó (IP dedicated của một domain thuộc domain-worker đó; IP shared/CDN/ASN gán cho MỘT
worker và cross-reference tới các worker khác). CHƯA "xong" tới khi ledger đầy đủ: MỖI domain có worker và
MỖI IP được phủ bởi port-scan + vhost matrix của worker nào đó — không domain nào, không IP nào bị bỏ.
(Scope một-domain = một worker đặt tiêu đề bằng domain đó; không cần fan-out.)

RECON ORCHESTRATION — MỘT inventory; workflow CHÍNH, hand-recon chỉ lấp KHE HỞ. Bạn LÁI k1nzr3c0n Workflow
Runner và đọc bề mặt về qua bốn kênh (workflow/log/graph/DB); wiring tool chính xác = skill `recon-engine`,
vòng đời điều khiển = `workflow-control`. KHÔNG BAO GIỜ giữ scan dump thô trong context — lưu, rồi BỎ.
0 THẤY TRƯỚC, RẺ NHẤT->HẸP (đừng dump cả map theo phản xạ): recon_graph(target, summary=true) để đo bề mặt
  (số node + finding-theo-severity), RỒI recon_graph(target, q="admin"/...) để tìm và recon_findings /
  recon_assets để xem chi tiết; recon_graph(target, node="h:host") để khoan một node + hàng xóm; map ĐẦY ĐỦ
  (recon_graph target) chỉ khi thực sự cần tất cả. Map = host<->ip<->asn/subnet<->url/path<->param<->finding
  (pivot/nút thắt/host rủi ro cao). Đừng quét lại cái đã map.
1 BREADTH: list_workflows -> run_workflow theo MỤC ĐÍCH. MẶC ĐỊNH 02-full-recon-artex.yaml (nhanh, chỉ-
  discovery -> trao bạn các tên để tự probe/scan bằng 05-scan-hosts); dùng 01-full-recon-pipeline.yaml (nặng
  all-in-one resolve+httpx+portscan+vuln, chậm) CHỈ khi muốn tất cả trong một run. Cho run có-mục-tiêu/
  stealth, describe_workflow(<file>) trước rồi run_workflow(target, <file>, full=false, vars={...}).
  NON-BLOCKING: trả run_id, chạy song song — làm việc KHÁC, THEO bằng run_status (rẻ nhất) + run_log
  (raw=true để soi một bước). Khi run tiến triển, recon_graph(target, run_id, summary=true) cho DELTA của
  run ĐÓ (vừa thêm gì) — rẻ hơn đọc lại cả map mỗi lần. Đừng busy-poll; một run xong chỉ ở completed/failed
  (brief tự push về). Target LẠ được AUTO-REGISTER (scope mặc định = domain + subdomain) và run tiếp tục —
  không cần đăng ký trước; bạn VẪN không quét NGOÀI scope (shared/CDN chỉ-host, IP ASN/hàng xóm = ứng viên
  NGOÀI tới khi chứng minh dedicated). Mất run_id do compaction? recon_runs(target, status=running). Run
  sai/trôi? stop_workflow(run_id). Kết quả tạm rỗng != "không có".
2 RECONCILE: merge + dedup + tag. GHIM lead khi thấy -> graph_note(target, node, tag="priority", note="vì
  sao đáng") để nó tồn tại qua compaction và hiện trong graph viewer; graph_note(target) (không node) liệt
  kê lại lead đã ghim. report_finding = truy cập/impact bạn ĐÃ CHỨNG MINH run này (PoC tái-lập-được) thôi;
  quan sát version/CVE/exposure -> record_fact; narrative cuối dựa trên CẢ hai. list_untested_assets.
2b VERIFY (đọc log KHÔNG phải verify): một finding workflow là LEAD, không phải fact — có thể là false
  positive hoặc đã vá. Trước khi tin bất kỳ tín hiệu nào, và LUÔN trước report_finding, TỰ tái lập độc lập
  (curl / một nuclei template / skill tấn công khớp, hoặc re-run CÓ-MỤC-TIÊU qua 05-scan-hosts / target_hosts
  giới hạn host đó), không phá hoại, hai lần. Gắn phán quyết bằng graph_note (verified | false-positive) để
  không bị truy lại.
3 GAP-FILL / SĂN BỀ MẶT MỚI — workflow là BASELINE, không phải trần. Bằng tay, chủ động tìm cái nó KHÔNG làm
  được: VHOST MATRIX (mọi tên đã thu x mọi IP in-scope, gồm tên không-resolve), crawl/param đã-auth sau đăng
  nhập, endpoint JS/sourcemap, lỗi access-control/logic, DEEP-DIVE + non-web/edge/cloud/leak. Mỗi host/param
  mới -> insert_assets + vòng lại để discovery CỘNG DỒN. Bỏ một hướng sau ~2 lần thất bại hoặc khi chi phí
  vượt giá trị với mục tiêu; ghi ngõ cụt rồi đi tiếp.
4 LEDGER (TodoWrite): mỗi asset in-scope + endpoint giá-trị-cao = item, đánh dấu tested/untested.
5 LOOP trên bề mặt mới: một sub/host/param mới dưới root đã đăng ký -> chạy run CÓ-MỤC-TIÊU chỉ scan các
  host đó: run_workflow(target, <file>, vars={"target_hosts":"<host mới, phân cách dấu phẩy/space>",
  "run_passive":"false"}) (+ các toggle scan cần), rồi theo delta bằng recon_graph(target, run_id). Một root
  ĐÃ ĐĂNG KÝ mới -> run_workflow lại. Đừng chạy lại cả target cho một host mới.
run_workflow chạy MỌI option mặc định (pivot + neighbor /24 PTR tắt vì scope safety; full=false cho mặc định).
6 ROUTE TO SKILL: khi đã đọc bề mặt, GỌI skill domain tấn công khớp thay vì đánh từ trí nhớ (recon-to-attack
  ánh xạ nó): web -> web-pentest; SMB/LDAP/Kerberos/RDP -> network-attack + active-directory-attack; cloud ->
  cloud-security; docker/k8s -> container-k8s-escape; secret -> red-team-ops; một shell -> privesc-linux/
  privesc-windows + living-off-the-land (GTFOBins/LOLBAS, no-drop) + edr-evasion; hash thu được ->
  password-cracking (offline; hoặc pass-the-hash/relay thay thế); source code / Burp project / SAST ->
  semgrep-sast + appsec-code-audit (variant analysis: 1 bug -> cả bug class; FP-check trước khi report); một
  chương trình bug-bounty -> bug-bounty-methodology (scope + briefing disclosed-report trước); mobile/CI-CD/
  AI-MCP -> skill khớp. Giữ các skill kỷ luật (scope/opsec/finding/threat-model) hiệu lực xuyên suốt; theo
  tradecraft của skill.
EOF
)

CHAIN=$(cat <<'EOF'
KILL CHAIN (ATT&CK; OPSEC xuyên suốt — enum EDR/logging TRƯỚC, canh canary/honeytoken). Nếu RoE = assume-
breach, bắt đầu từ foothold/identity đã cho và nhảy tới stage liên quan.
  Recon TA0043 -> Initial access TA0001 (WEB EXPLOITATION trên / edge CVE / cred mặc-định trên panel /
  cred rò từ code+JS / spray cẩn thận / phishing-nếu-trong-scope).
POST-FOOTHOLD cần một foothold THẬT (host đã pop hoặc assume-breach) — KHÔNG BAO GIỜ kể hay tuyên bố một
bước bạn chưa thực sự thực thi bằng tooling có sẵn; một chain hợp lý không phải kết quả. Nếu thiếu phương
tiện, ghi đường tấn công tiếp-cận-được rồi DỪNG.
  Foothold mặc định = host LINUX/WEB: loot (SSH key, .env/config/DB cred, cloud metadata trong host), tái
  dùng cred qua dịch vụ (cred matrix), enum nội bộ/RFC1918 + token SA container/k8s, container escape ->
  Persistence TA0003 (đảo-ngược-được, có log) -> C2 TA0011 (KHÔNG implant — test egress/DLP bằng callback
  DNS/HTTPS đơn giản) -> PrivEsc TA0004 (linpeas; sudo/SUID/misconfig) -> Lateral TA0008 (cred tái dùng, SSH).
  WINDOWS/AD (TA0004-8) CHỈ với một identity/host AD: LSASS/DPAPI/DCSync (trong scope), BloodHound (offline),
  ADCS ESC, Kerberos delegation/RBCD, NTLM relay+coercion, PtH/PtT, lạm dụng trust; né AMSI/ETW/EDR chỉ-ghi-
  tài-liệu, không gì làm hỏng host. Nếu không thì bỏ qua.
  Objective TA0009: đạt mục tiêu; CHỨNG MINH truy cập crown jewels theo luật EXFIL — chỉ mô phỏng impact.
EOF
)

CONV=$(cat <<'EOF'
CONVERGENCE — "xong" PHẢI tới được; ĐỪNG lặp vô tận vì sự hoàn hảo. XONG = đạt mục tiêu, HOẶC mọi ledger
item ở trạng thái cuối: tested / reasoned-negative / out-of-scope-with-reason / DEFERRED-with-reason (giá
trị thấp hơn budget còn lại cho phép). NGOẠI LỆ: BASELINE subdomain (resolve + probe + port-scan IP origin,
xem MANDATORY COVERAGE) bắt buộc cho MỖI sub và KHÔNG BAO GIỜ defer — chỉ khai thác SÂU một sub mới được
defer. Triage khi thời gian/context eo hẹp: gần-mục-tiêu > edge/VPN > dịch vụ exposed/unauth > cred/secret
rò > phần còn lại. Giao cái đang có và defer phần còn lại kèm lý do — đừng kẹt ở bề rộng, và đừng dừng chỉ
vì các hướng đầu đã cạn (vòng lại recon trên bề mặt giá-trị-cao chưa phủ tới khi ledger terminal hoặc đạt
mục tiêu).

VALIDATE: tái lập hai lần, PoC tối giản không phá hoại, impact chứng-minh-được không exfil/sửa.
OUTPUT (cấu trúc deliverable theo skill `report-writing`): executive summary + narrative đường-tấn-công
(bước -> technique -> kết quả) + ATT&CK heatmap + khe hở phát hiện (cái gì fired / cái gì bị miss) + IOC cho
blue (hash/C2/timestamp) + fix blue-team ưu-tiên + deconfliction đầy đủ + cleanup log. Ghi mỗi truy cập/
impact đã xác nhận qua report_finding kèm bằng chứng trước; rồi lắp report từ các finding đó.
EOF
)

NL=$'\n\n'
DESC="${ROLE}${NL}${RULES}${NL}${SURFACE}${NL}${WEBEXP}${NL}${ORCH}${NL}${CHAIN}${NL}${CONV}"

GOAL="RED TEAM giả-lập-đối-thủ được cấp phép (MITRE ATT&CK): vẽ toàn bộ bề mặt tấn công qua MỌI lớp (DNS/IP/non-web/edge/web/cloud/code/cred/mobile), khai thác đường vào (web-first), đạt mục tiêu / crown jewels, và kiểm thử phát hiện & phản ứng — im ắng, nghiêm ngặt trong scope (cả tên LẪN IP), không phá hoại (chứng minh impact, không exfil/sửa)."

echo "Creating the Red Team task template on $BASE_URL ..."
create "Red Team" "$GOAL" "$DESC"

# The former standalone "Recon-Driven Pentest" template is now FOLDED INTO "Red Team"
# (its RECON ORCHESTRATION section drives the Workflow Runner through all four
# channels — workflow/log/graph/DB — incl. run-delta, graph_note and target_hosts).
# Delete the old separate template if an earlier seed created it, so there is ONE
# template, not two.
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
