# Agent A — Flow Engine (Tuần 2, ưu tiên Go)

Nối **source → function → sink** trên code thật, tiêu thụ `taint_spec.db` của Agent B.
Frontend đầu tiên: **Go**, dùng parser gốc `go/ast` (chính xác hơn tree-sitter).

```
go_extract/  (Go + go/types)   ┐
  AST → IR JSON (ops, closures) │   callgraph.py        engine.py        run_go.py
ssa_extract/ (Go + x/tools)    ├─► CALL GRAPH tường ─► taint + summaries ─► CLI + graph
  SSA/VTA edges (chính xác)    ┘   minh (nodes+edges)   (+ taint_spec.db)   + export
```

### Hai engine graph (hybrid)
- **SSA/VTA** (`ssa_extract`, dùng `go/ssa` + `callgraph/vta`): khi project **build được**
  → call graph **sound**: interface dispatch, closure, func-value, generics, **liên package**.
- **AST heuristic** (`go_extract` + `callgraph.py`): khi **không build được** (code lỗi/thiếu,
  như Snyk/Semgrep) → vẫn chạy, dùng `go/types` cho receiver + heuristic.
`run_go` tự chọn SSA khi được, in `engine:` cho biết chế độ. Taint luôn chạy trên IR
(source-level: phân biệt nối chuỗi vs parameterized), graph lấy từ engine tốt nhất.

## Chạy

```bash
# cần Go trên PATH (dùng `go run` cho extractor)
python3 agent_a/run_go.py <thư_mục_go> [--db taint_spec.db]
       [--cats SQLI,XSS,PATH,CMDI,SSRF,OPEN_REDIRECT,CODE_INJECTION]
       [--graph callgraph] [--show-unresolved] [--json]

python3 agent_a/run_go.py samples/vuln_go               # demo đa lỗ hổng
python3 agent_a/run_go.py samples/vuln_go2 --graph cg   # demo method-edge + variadic
dot -Tsvg cg.dot -o cg.svg                               # render graph
```

## Call graph đầy đủ (`callgraph.py`)

Mọi hàm = một **node** (tên, receiver type, **param đầy đủ tên+kiểu+variadic**, số result);
mọi lời gọi = một **edge** caller→callee kèm **binding đối số→tham số** (theo vị trí, variadic
hấp thụ phần dư). Phân giải callee:

| resolution | nghĩa |
|---|---|
| `ssa` / `ssa-dynamic` | **SSA/VTA phân giải** (tĩnh / động qua interface) — chính xác nhất |
| `typed` | receiver type do `go/types` phân giải (`x.M()` với `x:*T` → `T.M`) |
| `closure` | gọi qua func-literal: IIFE `func(){}()` hoặc biến `f := func(){}; f()` |
| `by-name` | hàm thường `foo()` → `func foo` |
| `by-name?` | method `x.M()` chưa rõ kiểu → mọi method tên `M` (over-approx) |
| `cross-pkg?` | `pkg.Func` là hàm user ở package khác (heuristic AST, SSA sẽ thay bằng `ssa`) |

**Model C — function summaries** (`summaries.py`, như Snyk/Semgrep để scale): mỗi hàm
tóm tắt `param→return`, `src→return`, `param→sink` một lần; caller suy luận trên summary
của callee (fixpoint đơn điệu, xử lý đệ quy). Xem bằng `--summaries`; findings từ summary
được chéo-kiểm với engine (phải bằng nhau).

**Vá lỗ "bỏ sót" (B)**: closure giờ là node (bắt sink trong closure); call liên package
user được nối (không còn xếp nhầm thư viện ngoài, không im lặng).

Lời gọi không phân giải được vào **coverage-ledger** với lý do: `external-pkg` /
`library-method` / `library-chain` (thư viện ngoài — spec xử lý, **không** phải điểm đứt),
`builtin`, hoặc `unknown-func` / `dynamic/interface` (**taint-break thật** — nguy cơ bỏ sót,
in bằng `--show-unresolved`). Xuất `--graph`: `<prefix>.json` (nodes/edges/bindings/ledger)
và `<prefix>.dot` (Graphviz). Taint chạy trên chính graph này (truyền param qua binding,
return qua `ret-tainted`).

## Engine làm gì (recall-first — "không bỏ sót")

- **Liên hàm**: đối số bị nhiễm → tham số hàm được gọi bị nhiễm; hàm trả về giá
  trị nhiễm → đánh dấu "ret-tainted". Lan truyền tới điểm bất động (fixpoint).
  → bắt được flow qua nhiều hàm (vd `handler → buildQuery → runQuery`).
- **Flow-insensitive** (một biến đã nhiễm thì giữ nhiễm): over-approx có chủ đích
  để ưu tiên recall.
- **Sanitizer**: chỉ tin sanitizer `kb`/`generic`. Sanitizer `mined_diff`/
  `mined_confirm` **bị bỏ qua** khi làm sạch taint (chúng nhiễu — vd `filepath.Join`
  bị mine nhầm là "fix" → nếu tin sẽ **giấu mất** lỗ hổng). Sanitizer yếu (`weak=1`)
  không làm sạch mà hạ finding xuống `needs-review`.
- **SQLi tinh chỉnh**: giá trị nhiễm truyền dưới dạng **placeholder parameter**
  (không nối chuỗi vào câu query) được coi là parameterized → an toàn.
- **State theo từng category** (sanitizer đặc thù category, không rò taint chéo).
- **Chọn sink tốt nhất**: khi một call khớp nhiều signature, lấy bản ưu tiên
  `kb > generic > mined`, rồi confidence cao → sink thật quyết định độ nghiêm trọng.

## KB Go (trong Agent B, họ `go`)

Thêm trong `agent_b/knowledge_base.py`: sources (`r.FormValue`, `r.URL.Query().Get`,
`mux.Vars`, `os.Getenv`…), sinks theo category (SQLi: `db.Query/Exec/QueryRow`,
gorm `Raw`; CMDi: `exec.Command`; PATH: `os.Open/ReadFile`, `http.ServeFile`;
XSS: `w.Write`, `fmt.Fprintf`, `text/template`; SSRF: `http.Get/Do`,
`http.NewRequest`; OPEN_REDIRECT: `http.Redirect`), sanitizers (`html/template`,
`html.EscapeString`, `filepath.Clean/Base`, SQL `Prepare`), propagators
(`+`, `fmt.Sprintf`, `strings/filepath.Join`).

## Kết quả demo (`samples/vuln_go`)

| # | Loại | Hàm | Ghi chú |
|---|---|---|---|
| ✅ | CMDI | handlerCmd | `exec.Command("sh","-c","ping "+host)` |
| ✅ | PATH | handlerFile | `os.ReadFile(filepath.Join("/data", name))` |
| ✅ | SQLI | runQuery | **liên hàm** 3 tầng, nối đúng về `r.FormValue` |
| ✅ | XSS | handlerXSS | `fmt.Fprintf(w, "<p>%s</p>", q)` |
| — | — | handlerSafeSQL | parameterized `$1` → **không báo** (đúng) |
| — | — | handlerSafeFile (PATH) | `filepath.Base` → **không báo** (đúng) |

## Kiểm định đầy đủ graph (`audit_graph.py`)

Vì "graph tất cả function đầy đủ" là yêu cầu cốt lõi khi upload repo lớn, có bộ audit
riêng chạy trên mọi sample:

```bash
python3 audit_graph.py           # PASS/FAIL cho từng target
```

Bất biến kiểm tra: **mọi `CallExpr` được bắt** (`call_seen == call_total` — không rớt
call), **node == số hàm** (không mất hàm do trùng key), **key duy nhất**, **mọi cạnh trỏ
node tồn tại**, **mọi call site được phân loại** (thành cạnh hoặc vào ledger — không bỏ
âm thầm), và với `stress_go`: **sink nhiễm được tìm thấy ở MỌI vị trí câu lệnh**.

4 lỗ "bỏ sót" đã tìm ra & vá qua audit:
1. **Trùng key ở quy mô lớn** (2 package cùng `(T).M`, nhiều `init`) → key gồm **package
   + hậu tố duy nhất**, không còn đè node.
2. **Call trong `if`/`for`-cond, `switch`-tag, `case`, `select`, `send`, `var =`** bị bỏ →
   thay `ast.Inspect` bằng **bộ duyệt câu lệnh tường minh** bắt mọi vị trí.
3. **Call ở receiver của chuỗi** `getRepo().Do()` bị bỏ → bắt luôn phía receiver.
4. **Biến bắt bởi closure** (`go func(){ sink(name) }()`) không nhiễm → closure **kế thừa
   môi trường taint của hàm cha**.
5. **Chuỗi gọi ở cấp câu lệnh** `exec.Command(...).Run()` trong `defer`/`go`/ExprStmt → receiver
   bị bỏ → cho 3 loại này đi qua `exprInfo` (bắt cả receiver chain).

### Audit riêng cho engine SSA/VTA
`audit_graph.py` còn kiểm đường SSA: **mọi edge SSA map được về node AST** (không mất độ
chính xác), và **SSA phủ mọi edge user→user mà AST tìm ra** (không hồi quy). Ba vá đường SSA:
- **Thiếu `go.mod`** → `go/packages` load ad-hoc → `userPaths` sai → SSA trả 0 edge nhưng
  vẫn báo "precise" (giả). Vá: **tự tạo `go.mod` tạm** khi thiếu + từ chối load ad-hoc +
  báo mode trung thực (`AST` nếu SSA không dùng được, `partial build` nếu có lỗi biên dịch).
- **Override khớp theo tên callee** trượt cho closure/func-value (SSA đặt tên `f$1` ≠ biến
  `f` trong AST) → đổi sang **khớp theo call-site `(file,line)`**, tên chỉ là gợi ý.

## Đa ngôn ngữ (tree-sitter frontends)

`callgraph.py` + `engine.py` + `summaries.py` là ngôn ngữ-bất-khả-tri. Ngoài Go
(frontend gốc `go/ast` + SSA/VTA), có **framework tree-sitter dùng chung**
`ts_extract/extract.py` + 1 plugin/ngôn ngữ trong `ts_extract/plugins/<lang>.py`.

```bash
python3 agent_a/run_lang.py <lang> <dir>     # python|java|csharp|cpp|ruby|kotlin|swift|javascript|typescript|rust|php
python3 audit_multilang.py                    # kiểm cả 11 ngôn ngữ (findings + interproc + closure + seen==total)
```

**11 ngôn ngữ đã đạt** (mỗi ngôn ngữ: call-graph + taint liên hàm + closure, `call_seen==call_total`):
Python, Java, C#, C/C++, Ruby, Kotlin, Swift, JavaScript, TypeScript, Rust, PHP — cộng **Go** (frontend SSA/VTA riêng). Mẫu kiểm chứng ở `samples/langs/<lang>/`.

Mỗi plugin chỉ map node-type của grammar sang vai trò (sources/sinks khớp qua KB
`taint_spec.db`); không cần type-inference → gọi liên hàm resolve bằng `by-name`/
`closure`/`cross-pkg?` (recall-first). Chỉ Go có dispatch SSA/VTA sound.

## Hạn chế đã biết (cho Tuần 3)
- **Over-taint qua đọc file/DB**: `data := os.ReadFile(path)` lan taith sang `data`,
  nên `w.Write(data)` bị gắn XSS (conf thấp 0.7). Verify-agent sẽ lọc.
- **Flow-insensitive & context-insensitive**: có thể sinh FP; đổi lại không bỏ sót.
- **Dynamic dispatch / interface / func values**: chưa nối được (taint-break) —
  nên bổ sung coverage-ledger phơi các điểm đứt ở bước sau.
- Dùng `go run` mỗi lần; có thể build sẵn binary extractor để nhanh hơn.
```
