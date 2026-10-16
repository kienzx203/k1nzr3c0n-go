package locale

func init() {
	RegisterAll(map[string]map[Lang]string{
		"report.severity.critical":     {En: "CRITICAL", Ko: "치명적", ZhHans: "严重"},
		"report.severity.high":         {En: "HIGH", Ko: "높음", ZhHans: "高"},
		"report.severity.medium":       {En: "MEDIUM", Ko: "보통", ZhHans: "中"},
		"report.severity.low":          {En: "LOW", Ko: "낮음", ZhHans: "低"},
		"report.severity.info":         {En: "INFO", Ko: "정보", ZhHans: "信息"},
		"report.status.pending":        {En: "pending", Ko: "대기", ZhHans: "待确认"},
		"report.status.confirmed":      {En: "confirmed", Ko: "확인됨", ZhHans: "已确认"},
		"report.status.fixed":          {En: "fixed", Ko: "수정됨", ZhHans: "已修复"},
		"report.status.false_positive": {En: "false_positive", Ko: "오탐", ZhHans: "误报"},
		"report.status.accepted_risk":  {En: "accepted_risk", Ko: "위험 수용", ZhHans: "接受风险"},
		"report.status.open":           {En: "open", Ko: "미해결", ZhHans: "未解决"},
		"report.status.resolved":       {En: "resolved", Ko: "해결됨", ZhHans: "已解决"},
		"language must be one of %s":   {En: "language must be one of %s", Ko: "언어는 %s 중 하나여야 합니다", ZhHans: "语言必须为 %s 之一"},
	})
}
