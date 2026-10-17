export const MAX_BATCH = 512

export function cidrToIPs(cidr) {
  const [ip, bits] = cidr.split('/')
  const prefix = parseInt(bits, 10)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return [cidr]
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return [cidr]
  const base = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  const network = (base & mask) >>> 0
  const count = 2 ** (32 - prefix)
  const result = []
  for (let i = 0; i < Math.min(count, MAX_BATCH + 1); i++) {
    const a = (network + i) >>> 0
    result.push([(a >>> 24) & 0xff, (a >>> 16) & 0xff, (a >>> 8) & 0xff, a & 0xff].join('.'))
  }
  return result
}

export function parseTargetList(raw) {
  const tokens = raw.split(/[\n,]+/).map(t => t.trim()).filter(Boolean)
  const out = []
  for (const t of tokens) {
    if (/^[\d.]+\/\d+$/.test(t)) out.push(...cidrToIPs(t))
    else out.push(t)
  }
  return [...new Set(out)]
}
