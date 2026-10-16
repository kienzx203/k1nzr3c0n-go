/* critical=red, high=orange, medium=amber, low=blue — distinct hues keep
   critical/high readable for colorblind users (they were both red before).
   The dot gives a non-color second encoding. */
export const SEV_COLOR = {
  critical: '#f85149',
  high:     '#f0883e',
  medium:   '#f0b429',
  low:      '#58a6ff',
  info:     '#9aa7b8',
  unknown:  '#5c6773',
}
export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

export default function SevBadge({ sev }) {
  const s = (sev || 'unknown').toLowerCase()
  const c = SEV_COLOR[s] ?? SEV_COLOR.unknown
  return (
    <span
      style={{ color: c, borderColor: c + '4d', background: c + '16' }}
      className="inline-flex items-center gap-1 text-[10px] font-mono border rounded-full px-2 py-0.5 uppercase tracking-wide whitespace-nowrap"
    >
      <span className="w-[5px] h-[5px] rounded-full flex-shrink-0" style={{ background: c }} />
      {s}
    </span>
  )
}
