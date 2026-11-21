# Benchmark recall (Tuần 4) — OWASP BenchmarkJava v1.2

Đo **tỉ lệ bỏ sót thật** của Agent A (frontend Java tree-sitter, recall-first) trên
OWASP Benchmark (2740 test có ground-truth CSV). Số liệu **thật, không tô vẽ**.

## Tái lập
```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava bench
python3 agent_c/benchmark_run.py java bench/src/main/java/org/owasp/benchmark/testcode out.json
python3 agent_c/benchmark_score.py bench/expectedresults-1.2.csv out.json
```
`benchmark_run.py`: parse 1 lần (10071 hàm/2740 file) rồi chạy engine **per-file** (tránh fixpoint khổng lồ). `benchmark_score.py`: map finding→test→nhãn, chấm category-aware.

## Kết quả (category-aware; frontend syntactic, KHÔNG type-inference)

| category | #real | TP | FN | recall | precision |
|---|--:|--:|--:|--:|--:|
| xpathi | 15 | 12 | 3 | 80.0% | 52.2% |
| ldapi | 27 | 20 | 7 | 74.1% | 55.6% |
| xss | 246 | 165 | 81 | 67.1% | 65.5% |
| cmdi | 126 | 84 | 42 | 66.7% | 56.4% |
| sqli | 272 | 108 | 164 | 39.7% | 58.4% |
| pathtraver | 133 | 47 | 86 | 35.3% | 48.0% |
| **OVERALL** | **819** | **436** | **383** | **53.2%** | **58.7%** |

Youden (TPR−FPR) = 0.125. (Cải tiến trong lúc đo: thêm **for-each taint** cho frontend
— OWASP đưa taint qua vòng `for(Cookie c: req.getCookies())`, trước fix recall ~0.)

## Vì sao còn bỏ sót (nguyên nhân FN, trung thực)
1. **Không model container dataflow**: OWASP route taint qua `HashMap/List/array`,
   `StringBuilder`, `request.getParameterValues()[]` — taint-engine flow-insensitive,
   không theo put/get → mất nhiều ca **sqli/pathtraver** (hai category thấp nhất).
2. **Cross-file helper**: taint đi qua `Utils.*`/`benchmark/helpers/*` (file khác);
   scoring chạy **per-file** nên bỏ các flow liên file.
3. **Không type-inference**: resolve method theo tên (recall-first) — một số sink/sanitizer
   nhận diện kém hơn Go (vốn có SSA/VTA).
4. **Nguồn biến thể**: getHeader/getQueryString/getParameterMap + biến đổi (decode, substring)
   — một phần chưa trong KB.

## Vì sao precision ~59% (FP)
Engine recall-first over-approx: sink regex tên-đơn (vd `System.out.println`→XSS),
`by-name?` nối method trùng tên. **Verifier (Tuần 3)** để hạ FP: heuristic đã có; lượt
LLM-verify (dùng `bundle.llm_prompt`) sẽ cải thiện precision.

## Phân tích sâu (benchmark_analyze.py)

### (A) Hiệu lực của bước VERIFY lên precision (category-aware)
| policy | TP | FN | FP | recall | precision |
|---|--:|--:|--:|--:|--:|
| raw (không verify) | 436 | 383 | 307 | 53.2% | 58.7% |
| verify: drop needs-review | 436 | 383 | 307 | 53.2% | 58.7% |
| verify: confirmed-only | 68 | 751 | 55 | 8.3% | 55.3% |

→ **Heuristic verifier KHÔNG cải thiện precision** trên OWASP (findings Java phần lớn
origin `generic`, conf 0.6 → không rơi vào needs-review; confirmed-only thì sập recall).
**Kết luận: precision phải dựa LLM-verify (ngữ nghĩa), không phải heuristic.**

### (A2) LLM-verify thực sự cắt FP tới đâu (mẫu cân bằng 16 vuln + 16 safe)
`benchmark_llm_eval.py` — đo verifier trên mẫu (precision thô 50%):
| model + ngữ cảnh | TP-keep (giữ vuln thật) | FP-drop (bỏ đúng FP) | precision mẫu |
|---|--:|--:|--:|
| haiku + snippet quanh sink | 93.8% | 12.5% | 51.7% |
| **sonnet + cả-hàm (bắt sanitizer)** | 93.8% | **37.5%** | **60.0%** |

→ LLM-verify **có giá trị thật** (precision +10pp, không mất recall) **khi dùng model mạnh
+ ngữ cảnh đầy đủ**; haiku/ngữ cảnh mỏng ≈ vô dụng. Không phải thuốc tiên: OWASP FP tinh vi
nên ~62% FP vẫn lọt — precision tối đa bị chặn bởi việc engine đưa flow an toàn vào candidate.

### (B) Nguyên nhân bỏ sót 383 FN (định lượng)
| % | nguyên nhân |
|--:|---|
| 53.0% | cross-file-helper (taint qua helper ở file khác) |
| 36.6% | container + cross-file |
| 6.5% | container-dataflow (HashMap/List/StringBuilder) |
| 3.7% | khác (sink/transform chưa khớp) |
| 0.3% | source biến thể |

→ **~89.6% FN cần taint LIÊN FILE**; đòn bẩy recall #1 = **cross-file taint** (bỏ
per-file scoping + parse cả `helpers/`), #2 = **container dataflow**. Chỉ 3.7% là do
sink/source chưa phủ → KB khá đủ; vấn đề là mô hình dataflow.

## Đối chiếu khách quan
Đây là tool **syntactic, đa ngôn ngữ, không cần build** (giống Semgrep OSS/Snyk-style),
không phải DB-based như CodeQL. Recall ~53% / precision ~59% là mức hợp lý cho hạng này;
đường tăng recall rõ ràng: (a) container dataflow, (b) cross-file (bỏ per-file scoping),
(c) type-inference cho resolve sink. Go (SSA/VTA) sẽ cao hơn trên benchmark Go tương ứng.
