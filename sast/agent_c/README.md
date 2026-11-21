# Agent C — Orchestrator + Verify + Report (Tuần 3–4)

Ghép candidate từ Agent A → verify → coverage-ledger → báo cáo; và đo recall trên benchmark.

## Chạy
```bash
# Orchestrate (tự nhận ngôn ngữ): ghép + verify + ledger
python3 agent_c/orchestrator.py <dir> [--lang go|java|python|...] [--json out.json]

# Xuất báo cáo HTML
python3 agent_c/report.py <dir> [--lang L] [--out report.html]
```

## Tuần 3 — Orchestrator (`orchestrator.py`)
1. **Ghép candidate**: chạy Agent A (Go → frontend SSA/VTA; ngôn ngữ khác → tree-sitter),
   lấy findings + call graph + coverage-ledger; **dedupe** theo (category, func, line, sink).
2. **Evidence bundle** mỗi candidate: **đường đi liên hàm** (entry→…→sink, dựng từ graph),
   đoạn code quanh sink, và **`llm_prompt`** sẵn sàng cho một lượt LLM-verify.
3. **Verify (pluggable)**: mặc định `heuristic_verify` (xác định, không cần API) → gán
   verdict `confirmed | likely | needs-review | false_positive` + score + lý do. Có thể
   thay bằng LLM-verifier (dùng `bundle['llm_prompt']`; trả JSON verdict) — interface để
   nối API hoặc chạy qua subagent.
4. **Coverage-ledger**: liệt kê **taint-break** (call `unknown-func`/`dynamic/interface` =
   nguy cơ bỏ sót) để review tay — không giấu.

Output JSON: `{target, summary, findings:[{verdict, score, reason, bundle{path,code,llm_prompt}}], ledger}`.

Quy tắc heuristic (recall-first): sanitizer yếu → `needs-review`; sink generic/confidence
thấp → `needs-review` (xác nhận đúng API); KB confidence cao + có taint → `confirmed`
(thêm "across functions" nếu liên hàm); còn lại → `likely`.

## Tuần 4 — Report (`report.py`) + Benchmark
- **Report HTML**: findings xếp theo verdict, badge màu, đường đi source→sink, snippet code,
  và coverage-ledger. Self-contained (mở bằng trình duyệt / phục vụ qua webapp).
- **Benchmark recall** (`../benchmark/` do harness đo): chạy tool trên **OWASP Benchmark**
  (Java, có ground-truth CSV), map finding→test case→nhãn thật, tính **recall/precision**
  theo từng category. Số đo thật được đưa vào README/report (xem phần kết quả benchmark).

## Lưu ý trung thực
- Verdict mặc định từ heuristic — **LLM-verify là tùy chọn** (bundle đã kèm prompt); heuristic
  giảm FP ở mức luật, không thay thế phán đoán ngữ nghĩa của LLM.
- Precision phụ thuộc frontend: **Go sound (SSA/VTA)**; ngôn ngữ tree-sitter recall-first.
