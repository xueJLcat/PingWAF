/**
 * Tab vocabulary for the site's Web-protection page.
 *
 * The page was reorganised (UX-09) from the old `settings | managed | custom |
 * cc | paths` shape into six entries that follow the operator's mental model:
 * the overview first, then the engine and detection controls, then the three
 * enforcement surfaces. `?tab=` stays the deep-link contract, so old values are
 * translated instead of dropped.
 */
export type ProtectionTab =
  | 'overview'
  | 'engine'
  | 'managed'
  | 'custom'
  | 'paths'
  | 'cc'
  | 'integrity'

/**
 * Tabs accepted from `?tab=`, in display order. Every entry must stay in this
 * list: `parseTab` runs on every render, so a value missing here makes the URL
 * write and the next read disagree — the tab writes `engine`, reads it back as
 * `overview`, and the panel never opens.
 */
export const PROTECTION_TABS: ProtectionTab[] = [
  'overview',
  'engine',
  'managed',
  'custom',
  'paths',
  'cc',
  'integrity',
]

/**
 * Older or shorthand tab names still accepted in links, normalized on load.
 *
 * - `settings` was the pre-0.22 engine/detection tab → `engine`
 * - `rules` was the pre-0.22 custom-rule tab → `custom`
 * - `detection` / `waf` are shorthand for the engine tab
 * - `rate` / `ratelimit` / `challenge` / `mitigation` all point at the
 *   rate-limiting & challenge tab (its canonical value stays `cc` because the
 *   logs page and the legacy route redirect already link to `?tab=cc`)
 * - `exceptions` is shorthand for the path-exceptions tab
 *
 * The page rewrites the URL in place, so the address bar always ends up on the
 * current vocabulary while every other parameter (`?rule=`, …) is preserved.
 */
export const LEGACY_TABS: Record<string, ProtectionTab> = {
  settings: 'engine',
  rules: 'custom',
  detection: 'engine',
  waf: 'engine',
  rate: 'cc',
  ratelimit: 'cc',
  challenge: 'cc',
  mitigation: 'cc',
  exceptions: 'paths',
}

/** Whether `value` is an older name that should be rewritten in the URL. */
export function isLegacyTab(value: string | null): boolean {
  return Boolean(value && LEGACY_TABS[value])
}

export function parseTab(value: string | null): ProtectionTab {
  if (value && LEGACY_TABS[value]) return LEGACY_TABS[value]
  return PROTECTION_TABS.includes(value as ProtectionTab)
    ? (value as ProtectionTab)
    : 'overview'
}
