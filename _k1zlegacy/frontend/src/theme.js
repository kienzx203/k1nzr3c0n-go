const KEY = 'vrecon-theme'

export function getTheme() {
  const v = localStorage.getItem(KEY)
  return v === 'dark' ? 'dark' : 'light' // ScopeWeaver defaults to light
}

export function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem(KEY, theme)
}
