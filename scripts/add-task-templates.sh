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
- Lưu kết quả NGAY (insert_assets / record_fact / report_finding) rồi BỎ output thô khỏi context.
- Steer giữa chừng: đọc + tuân note (steer_work).
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
## PHASE 1 — RECON (quiet/passive trước; workflow CHÍNH, hand-recon lấp khe hở)
- run_workflow: MẶC ĐỊNH 02-full-recon-artex.yaml (nhanh, discovery) | 01-full-recon-pipeline.yaml (all-in-one, chậm). Non-blocking -> theo run_status + run_log; delta qua recon_graph(target, run_id, summary=true).
- Subdomain: subfinder -all + crt.sh + subdomain.center; permute gotator/dnsgen; AXFR dig @ns; records MX/NS/TXT/SPF/DMARC.
- IP/ASN: resolve subs -> IP A-record -> ASN (Team Cymru: dig +short TXT <reversed-ip>.origin.asn.cymru.com) -> prefix union RIPEstat + bgp.he.net + bgpview.io + bgpq4. (workflow asn_expand -> asn_ipv4_cidrs / asn_org_cidrs.)
- Leak/OSINT: GitHub/GitLab org dork + trufflehog, Postman, Docker, paste; breach data HIBP/dehashed.
- Mobile (nếu có app): APK/IPA -> apktool/MobSF -> endpoint/key/host.
- Kết quả về -> recon_graph(summary) để thấy bề mặt; TÁI DÙNG recon_findings/recon_assets, đừng quét lại.
EOF
)

P2=$(cat <<'EOF'
## PHASE 2 — MAP BỀ MẶT + FAN-OUT (mỗi domain 1 plan + 1 worker; KHÔNG bỏ sót domain/IP)
- Duyệt TOÀN BỘ sub_domain_all. MỖI domain -> lên plan riêng + spawn_task(description="<domain>", goal="Red-team SÂU <domain>: vhost sống+chết x mọi IP, exploit, privesc, objective, report"). Bạn là orchestrator: giám sát + đối soát (list_tasks / get_task_worker_trace).
- RESOLVE từng sub: public + DoH + NS auth (dig @ns). SERVFAIL/timeout = soft-recheck 8.8.8.8/1.1.1.1/9.9.9.9 trước khi coi là "chết"; tên không-resolve vẫn là SURFACE (tìm IP qua CNAME/cert-SAN/Shodan·Censys·FOFA/passive-DNS/PTR).
- VHOST MATRIX (BẮT BUỘC từng domain): MỌI tên CẢ SỐNG LẪN CHẾT x MỌI IP mở-web. Dùng 05-scan-hosts; nạp pool/LB/F5 IP không-tên-nào-resolve-tới qua target_ips. curl --resolve name:443:IP (https+http); GATE baseline random-host (loại catch-all); phản hồi KHÁC baseline = vhost sống -> asset mới.
- PORT SCAN mọi IP của target (naabu -> nmap -sV -sC). Flag unauth: redis6379/mongo27017/elastic9200/DB, SMB445/LDAP389,636/Kerberos88/RDP3389/SSH22/FTP21/SMTP25/SNMP161, docker2375/k8s6443,10250. (IP pool/LB/shared của target = quét đầy đủ; chỉ CDN bên-thứ-ba mới host-only.)
- Mỗi sub + mỗi IP = LEDGER item; chưa "xong" tới khi đủ: resolve + httpx-probe + port-scan + vhost.
- Surface mới (sub/host/param) -> insert_assets + LOOP: 05-scan-hosts với target_hosts="<host mới>" rồi theo delta.
EOF
)

P3=$(cat <<'EOF'
## PHASE 3 — PHÂN TÍCH LỖ HỔNG (mọi finding workflow là LEAD, phải VERIFY)
- WEB: httpx fingerprint; URL gau/waymore; crawl katana -jc -kf all; JS -> linkfinder/jsluice + *.js.map sourcemapper + trufflehog; API swagger/openapi/GraphQL-introspection/.well-known; param arjun/x8; content ffuf (.git/.env/admin/backup/upload).
- CVE: cập nhật feed (nuclei -ut, searchsploit -u) -> nuclei full template mọi host/panel -> đối chiếu product+version với CISA KEV + PoC. Edge (Citrix/Fortinet/Ivanti/GlobalProtect/F5/Exchange/Zimbra/Confluence) = đường vào nhanh nhất.
- SERVICE: trên port đã mở -> default/weak cred mọi panel + service.
- CLOUD: bucket cloud_enum/s3scanner; SSRF -> cloud metadata -> IAM.
- VERIFY trước report_finding: tự tái lập độc lập (curl / 1 nuclei template / skill khớp / re-run 05-scan-hosts) 2 lần, không phá hoại. graph_note(verified | false-positive). record_fact cho quan sát version/CVE; report_finding chỉ cho cái đã CHỨNG MINH.
EOF
)

P4=$(cat <<'EOF'
## PHASE 4 — KHAI THÁC / ĐƯỜNG VÀO (TA0001)
- Injection: SQLi/NoSQLi, OS-cmd, SSTI, XXE, LDAP. SSRF (mọi param url/fetch/webhook/import) -> internal/metadata/port-scan phía app.
- Access control: IDOR/BOLA (đổi id giữa 2 account), BFLA (role/verb), auth-bypass, forced-browse, mass-assignment, multi-tenant.
- Auth: default+weak cred mọi panel; JWT (alg/none/secret-yếu), OAuth/SAML, reset password, 2FA bypass, session fixation.
- Files: upload -> webshell/RCE, LFI/RFI, path traversal, deserialization.
- Đường vào khác: edge CVE (KEV) / cred rò từ code+JS / spray cẩn thận (canh lockout) / phishing-nếu-scoped.
- ROUTE skill: web->web-pentest; SMB/LDAP/Kerberos/RDP->network-attack + active-directory-attack; cloud->cloud-security; docker/k8s->container-k8s-escape; secret->red-team-ops; code/SAST->semgrep-sast + appsec-code-audit; bug-bounty->bug-bounty-methodology.
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
- CONVERGENCE "xong" = objective đạt, HOẶC mọi ledger item terminal (tested / reasoned-negative / out-of-scope / deferred-có-lý-do). BẮT BUỘC: mỗi domain có worker + plan, đã qua VHOST MATRIX sống+chết, mọi IP phủ port-scan + vhost, đã khai thác sâu tới hạn. Baseline (resolve+probe+port-scan+vhost) KHÔNG BAO GIỜ defer.
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
