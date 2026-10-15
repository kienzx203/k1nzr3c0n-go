import React, { useEffect, useRef, useState } from 'react'

const API = '/api/v1'

export default function Agent() {
  const [messages, setMessages] = useState([]) // {role, content, tool_calls}
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [convId, setConvId] = useState(null)
  const [convs, setConvs] = useState([])
  const [profiles, setProfiles] = useState([])
  const [profileId, setProfileId] = useState(null)
  const [showConfig, setShowConfig] = useState(false)
  const [form, setForm] = useState({ name: '', base_url: 'https://api.z.ai/api/paas/v4', api_key: '', model: 'glm-4.7' })
  const bottomRef = useRef(null)

  useEffect(() => { loadConvs(); loadProfiles() }, [])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, busy])

  async function loadConvs() {
    try {
      const r = await fetch(`${API}/agent/conversations`)
      setConvs(await r.json())
    } catch {}
  }
  async function loadProfiles() {
    try {
      const r = await fetch(`${API}/llm`)
      const p = await r.json()
      setProfiles(p)
      if (p.length) setProfileId(p[0].id)
    } catch {}
  }

  async function openConv(id) {
    setConvId(id)
    const r = await fetch(`${API}/agent/conversations/${id}/messages`)
    const msgs = await r.json()
    setMessages(msgs)
  }

  async function send() {
    const text = input.trim()
    if (!text || busy) return
    setInput('')
    setMessages(m => [...m, { role: 'user', content: text }])
    setBusy(true)
    try {
      const body = { message: text }
      if (convId) body.conversation_id = convId
      if (profileId) body.profile_id = profileId
      const r = await fetch(`${API}/agent/chat`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await r.json()
      if (!r.ok) {
        setMessages(m => [...m, { role: 'assistant', content: `⚠️ ${data.detail || r.statusText}` }])
      } else {
        setConvId(data.conversation_id)
        setMessages(m => [...m, { role: 'assistant', content: data.reply, tool_calls: data.tool_calls }])
        loadConvs()
      }
    } catch (e) {
      setMessages(m => [...m, { role: 'assistant', content: `⚠️ ${e.message}` }])
    }
    setBusy(false)
  }

  async function createProfile(e) {
    e.preventDefault()
    const r = await fetch(`${API}/llm`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(form),
    })
    if (r.ok) { setShowConfig(false); loadProfiles() }
  }

  function newChat() { setConvId(null); setMessages([]) }

  const noProfile = profiles.length === 0

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 16, height: 'calc(100vh - 130px)' }}>
      {/* sidebar: conversations + profile */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
        <button className="btn" onClick={newChat}>+ New chat</button>
        <div style={{ overflowY: 'auto', flex: 1, border: '1px solid #232a3a', borderRadius: 8 }}>
          {convs.map(c => (
            <div key={c.id} onClick={() => openConv(c.id)}
                 style={{ padding: '8px 10px', cursor: 'pointer', borderBottom: '1px solid #1b2230',
                          background: convId === c.id ? '#16281e' : 'transparent', fontSize: 12 }}>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</div>
              <div style={{ color: '#6e7681', fontSize: 10 }}>{(c.updated_at || '').replace('T', ' ').slice(0, 16)}</div>
            </div>
          ))}
          {!convs.length && <div style={{ padding: 10, color: '#6e7681', fontSize: 12 }}>No conversations yet</div>}
        </div>
        <select value={profileId || ''} onChange={e => setProfileId(+e.target.value)}
                style={{ background: '#0d1117', border: '1px solid #232a3a', color: '#e6edf3', borderRadius: 6, padding: 6 }}>
          {profiles.map(p => <option key={p.id} value={p.id}>{p.name} · {p.model}</option>)}
        </select>
        <button className="btn" onClick={() => setShowConfig(v => !v)}>⚙ LLM profile</button>
        {showConfig && (
          <form onSubmit={createProfile} style={{ display: 'flex', flexDirection: 'column', gap: 6,
            border: '1px solid #232a3a', borderRadius: 8, padding: 10 }}>
            <input placeholder="name" value={form.name} required
                   onChange={e => setForm({ ...form, name: e.target.value })} />
            <input placeholder="base_url" value={form.base_url}
                   onChange={e => setForm({ ...form, base_url: e.target.value })} />
            <input placeholder="api_key" type="password" value={form.api_key} required
                   onChange={e => setForm({ ...form, api_key: e.target.value })} />
            <input placeholder="model" value={form.model}
                   onChange={e => setForm({ ...form, model: e.target.value })} />
            <button className="btn" type="submit">Save</button>
          </form>
        )}
      </div>

      {/* chat panel */}
      <div style={{ display: 'flex', flexDirection: 'column', border: '1px solid #232a3a', borderRadius: 8, minWidth: 0 }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {noProfile && (
            <div style={{ border: '1px dashed #2ea043', borderRadius: 8, padding: 14, fontSize: 13 }}>
              ⚙ Chưa cấu hình LLM. Tạo profile GLM/Z.ai ở sidebar (base_url
              <code> https://api.z.ai/api/paas/v4</code>, model <code>glm-4.7</code>) rồi chat.
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} style={{
              alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
              maxWidth: '78%', padding: '10px 12px', borderRadius: 10, fontSize: 13,
              whiteSpace: 'pre-wrap',
              background: m.role === 'user' ? '#1f6feb33' : '#161b22',
              border: '1px solid ' + (m.role === 'user' ? '#1f6feb66' : '#232a3a'),
            }}>
              {m.content}
              {m.tool_calls && m.tool_calls.length > 0 && (
                <div style={{ marginTop: 6, fontSize: 10, color: '#7ee2a8' }}>
                  ⚙ tools: {m.tool_calls.join(', ')}
                </div>
              )}
            </div>
          ))}
          {busy && <div style={{ color: '#6e7681', fontSize: 12, alignSelf: 'flex-start' }}>agent thinking…</div>}
          <div ref={bottomRef} />
        </div>
        <div style={{ display: 'flex', gap: 8, padding: 12, borderTop: '1px solid #232a3a' }}>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
            placeholder="ví dụ: Recon example.com — register target và chạy full pipeline"
            rows={2}
            style={{ flex: 1, resize: 'none', background: '#0d1117', color: '#e6edf3',
                     border: '1px solid #232a3a', borderRadius: 8, padding: 10 }}
          />
          <button className="btn" onClick={send} disabled={busy || !input.trim()}>Send</button>
        </div>
      </div>
    </div>
  )
}
