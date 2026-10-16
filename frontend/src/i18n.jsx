import React, { createContext, useContext, useEffect, useState } from 'react'

/* Minimal i18n: vi/en dictionary + localStorage persistence. Original
   k1nzr3c0n pages stay English (upstream strings); the shell and the new
   ScopeWeaver-integrated surfaces are bilingual. */

const DICT = {
  vi: {
    'nav.overview': 'Tổng quan', 'nav.operations': 'Vận hành', 'nav.capture': 'Ghi nhận', 'nav.system': 'Hệ thống',
    'nav.dashboard': 'Bảng điều khiển', 'nav.agent': 'AI Agent', 'nav.runs': 'Lượt chạy', 'nav.workflows': 'Workflow',
    'nav.findings': 'Findings', 'nav.inventory': 'Kho asset', 'nav.targets': 'Targets', 'nav.graph': 'Asset Graph',
    'nav.schedules': 'Lịch chạy', 'nav.traffic': 'Traffic', 'nav.upload': 'Tải lên',
    'nav.terminal': 'Terminal', 'nav.keys': 'API Keys', 'nav.tools': 'Công cụ',
    'agent.title': 'AI Agent', 'agent.sub': 'Vận hành bằng GLM — tự chạy scan, triage findings, quản lý asset graph',
    'agent.newChat': 'Hội thoại mới', 'agent.conversations': 'Hội thoại', 'agent.noConvs': 'Chưa có hội thoại nào',
    'agent.profile': 'Cấu hình LLM', 'agent.saveProfile': 'Lưu profile', 'agent.saving': 'Đang lưu…',
    'agent.autopilot': 'Autopilot', 'agent.placeholder': 'ví dụ: Recon example.com — register target rồi chạy full pipeline…',
    'agent.thinking': 'agent đang gọi tools / soạn câu trả lời…',
    'agent.tryQuick': 'Thử một trong các lệnh nhanh:',
    'agent.noProfileTitle': '⚙ Chưa cấu hình LLM',
    'agent.noProfileBody': 'Tạo profile ở sidebar trái: Base URL https://api.z.ai/api/coding/paas/v4, model glm-4.7, API key từ Z.ai — rồi bắt đầu chat.',
    'agent.name': 'Tên', 'agent.baseUrl': 'Base URL', 'agent.apiKey': 'API key', 'agent.model': 'Model', 'agent.preset': 'Preset',
    'graph.title': 'Asset Graph', 'graph.companies': 'Công ty', 'graph.all': 'Tất cả công ty',
    'graph.newCompany': 'công ty mới…', 'graph.search': 'tìm giá trị…', 'graph.allTypes': 'mọi loại',
    'graph.empty': 'Chưa có asset — chạy workflow (findings tự nạp vào graph) hoặc thêm công ty + asset thủ công.',
    'graph.assets': 'assets', 'traffic.title': 'Traffic Evidence',
    'traffic.captureOn': 'capture BẬT', 'traffic.captureOff': 'capture TẮT',
    'traffic.start': 'Bật capture', 'traffic.stop': 'Tắt capture', 'traffic.filter': 'lọc host…',
    'traffic.rules': 'Traffic rules — chặn (block) / giữ chờ duyệt (hold) host khớp pattern',
    'traffic.pending': '⏸ Pending approvals — request đang bị GIỮ chờ quyết định',
    'traffic.approve': '✓ Duyệt', 'traffic.deny': '✕ Từ chối',
    'traffic.empty': 'Chưa có traffic. Bật Start capture rồi chạy workflow — HTTP của tool đi qua proxy và được ghi lại làm evidence (tự gắn run id).',
    'traffic.selectRow': 'Chọn một bản ghi bên trái để xem request / response đầy đủ.',
    'traffic.bindFinding': 'Gắn vào finding', 'traffic.evidenceTo': 'evidence → finding',
    'dash.aiAgent': 'AI Agent', 'dash.assetGraph': 'Asset Graph', 'dash.trafficEv': 'Traffic Evidence',
    'dash.report': 'Báo cáo Engagement', 'dash.noLLM': 'chưa cấu hình LLM', 'dash.captured': 'cặp đã ghi',
    'dash.assetsAcross': 'assets theo công ty', 'dash.mdAll': 'markdown · mọi vuln mở',
    'footer.system': 'hệ thống', 'footer.capture': 'capture', 'footer.turns': 'lượt',
    'footer.updateAvail': 'có bản mới',
  },
  en: {
    'nav.overview': 'Overview', 'nav.operations': 'Operations', 'nav.capture': 'Capture', 'nav.system': 'System',
    'nav.dashboard': 'Dashboard', 'nav.agent': 'AI Agent', 'nav.runs': 'Runs', 'nav.workflows': 'Workflows',
    'nav.findings': 'Findings', 'nav.inventory': 'Inventory', 'nav.targets': 'Targets', 'nav.graph': 'Asset Graph',
    'nav.schedules': 'Schedules', 'nav.traffic': 'Traffic', 'nav.upload': 'Upload',
    'nav.terminal': 'Terminal', 'nav.keys': 'API Keys', 'nav.tools': 'Tools',
    'agent.title': 'AI Agent', 'agent.sub': 'GLM-driven operator — launches scans, triages findings, maintains the graph',
    'agent.newChat': 'New chat', 'agent.conversations': 'Conversations', 'agent.noConvs': 'No conversations yet',
    'agent.profile': 'LLM profile', 'agent.saveProfile': 'Save profile', 'agent.saving': 'Saving…',
    'agent.autopilot': 'Autopilot', 'agent.placeholder': 'e.g. Recon example.com — register target and run the full pipeline…',
    'agent.thinking': 'agent is calling tools / composing the reply…',
    'agent.tryQuick': 'Try one of the quick commands:',
    'agent.noProfileTitle': '⚙ No LLM configured',
    'agent.noProfileBody': 'Create a profile in the left sidebar: Base URL https://api.z.ai/api/coding/paas/v4, model glm-4.7, API key from Z.ai — then start chatting.',
    'agent.name': 'Name', 'agent.baseUrl': 'Base URL', 'agent.apiKey': 'API key', 'agent.model': 'Model', 'agent.preset': 'Preset',
    'graph.title': 'Asset Graph', 'graph.companies': 'Companies', 'graph.all': 'All companies',
    'graph.newCompany': 'new company…', 'graph.search': 'search value…', 'graph.allTypes': 'all types',
    'graph.empty': 'No assets yet — run a workflow (findings auto-ingest into the graph) or add a company + asset manually.',
    'graph.assets': 'assets', 'traffic.title': 'Traffic Evidence',
    'traffic.captureOn': 'capture ON', 'traffic.captureOff': 'capture OFF',
    'traffic.start': 'Start capture', 'traffic.stop': 'Stop capture', 'traffic.filter': 'filter host…',
    'traffic.rules': 'Traffic rules — block / hold requests matching a pattern',
    'traffic.pending': '⏸ Pending approvals — requests HELD awaiting decision',
    'traffic.approve': '✓ Approve', 'traffic.deny': '✕ Deny',
    'traffic.empty': 'No traffic yet. Start capture and run a workflow — tool HTTP goes through the proxy and is recorded as evidence (auto-tagged with the run id).',
    'traffic.selectRow': 'Select a record on the left to view the full request / response.',
    'traffic.bindFinding': 'Bind to finding', 'traffic.evidenceTo': 'evidence → finding',
    'dash.aiAgent': 'AI Agent', 'dash.assetGraph': 'Asset Graph', 'dash.trafficEv': 'Traffic Evidence',
    'dash.report': 'Engagement Report', 'dash.noLLM': 'no LLM configured', 'dash.captured': 'pairs captured',
    'dash.assetsAcross': 'assets across companies', 'dash.mdAll': 'markdown · all open vulns',
    'footer.system': 'system', 'footer.capture': 'capture', 'footer.turns': 'turns',
    'footer.updateAvail': 'update available',
  },
}

const I18nCtx = createContext({ lang: 'vi', t: k => k })

export function I18nProvider({ children }) {
  const [lang, setLang] = useState(() => localStorage.getItem('k1z-lang') || 'en')
  useEffect(() => { localStorage.setItem('k1z-lang', lang) }, [lang])
  const t = key => (DICT[lang] && DICT[lang][key]) || (DICT.en[key] || key)
  return <I18nCtx.Provider value={{ lang, setLang, t }}>{children}</I18nCtx.Provider>
}

export const useI18n = () => useContext(I18nCtx)
