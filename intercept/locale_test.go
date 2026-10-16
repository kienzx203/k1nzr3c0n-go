package intercept

import (
	"github.com/Autumn-27/artex/locale"
	"strings"
	"testing"
)

func TestVerdictLanguageContractsRemainStrict(t *testing.T) {
	for _, input := range []string{
		`{"decision":"allow","comment":"Operation: read file; Effect if successful: return text; Rule: A5"}`,
		`{"decision":"ask","comment":"작업: 파일 삭제; 성공 시 영향: 파일 소실; 적용 규칙: ASK"}`,
		`{"decision":"deny","comment":"实际操作：删除订单；成功后的后果：数据丢失；命中规则：D4"}`,
	} {
		if v := ParseVerdict(input); v.Action == "" {
			t.Fatalf("valid language rejected: %s", input)
		}
	}
	for _, input := range []string{
		`{"decision":"allow","comment":"Operation: read; Effect if successful: ; Rule: A5"}`,
		`{"decision":"allow","comment":"작업: 읽기; Effect if successful: text; 적용 규칙: A5"}`,
		`{"decision":"allow","comment":"Operation: read; Effect if successful: text; Rule: A5","extra":"bypass"}`,
		`{"decision":"ALLOW","comment":"Operation: read; Effect if successful: text; Rule: A5"}`,
	} {
		if v := ParseVerdict(input); v.Action != "" {
			t.Fatalf("invalid contract accepted: %s", input)
		}
	}
}

func TestJudgePromptLanguagesPreservePolicyAndCustomText(t *testing.T) {
	for _, lang := range locale.Languages() {
		p := EffectiveJudgePrompt(DefaultJudgePrompt, lang)
		for _, rule := range []string{"D1", "D2", "D3", "D4", "D5", "D6", "A1", "A2", "A3", "A4", "A5", "A6", "ASK", "DEFAULT", "tool_name", "arguments"} {
			if !strings.Contains(p, rule) {
				t.Fatalf("%s prompt lost %s", lang, rule)
			}
		}
		contract := locale.Text(lang, JudgeOutputContract)
		if strings.Count(p, contract) != 1 {
			t.Fatalf("%s duplicated/missing output contract", lang)
		}
		custom := "用户自定义策略 한국어"
		if got := EffectiveJudgePrompt(custom, lang); !strings.HasPrefix(got, custom) {
			t.Fatal("custom policy rewritten")
		}
	}
}

func TestChineseJudgeRegistrationAndStockRecognition(t *testing.T) {
	if err := locale.ValidateTextTranslations([]string{DefaultJudgePrompt, JudgeContextBoundary, JudgeOutputContract}); err != nil {
		t.Fatal(err)
	}
	zh := locale.Text(locale.ZhHans, DefaultJudgePrompt)
	if !IsDefaultJudgePrompt(zh) {
		t.Fatal("Chinese stock judge not recognized")
	}
	for _, reason := range []string{"实际操作：读取测试文件；成功后的后果：返回内容；命中规则：A5", "实际操作：删除未知文件；成功后的后果：文件丢失；命中规则：ASK"} {
		if !strings.Contains(zh, "实际操作：") {
			t.Fatal("Chinese contract missing parser-compatible labels")
		}
		if got := ParseVerdict(`{"decision":"allow","comment":"` + reason + `"}`); got.Action != "allow" {
			t.Fatal("Chinese verdict rejected")
		}
	}
	if IsDefaultJudgePrompt(zh + " custom edit") {
		t.Fatal("edited Chinese policy treated as stock")
	}
}
