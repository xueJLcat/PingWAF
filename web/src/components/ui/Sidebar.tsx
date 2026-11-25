import { NavLink } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { navigationGroups, type NavLeaf } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'

export interface SidebarProps {
  collapsed: boolean
  onNavigate?: () => void
}

export function Sidebar({ collapsed, onNavigate }: SidebarProps) {
  const { t } = useTranslation()
  // Must mirror router/index.tsx's RequireAdmin: hidden, not merely blocked.
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'

  const linkBase =
    'group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150'
  const linkIdle = 'text-fg-subtle hover:bg-recessed hover:text-fg'
  // Active state: the label uses the readable brand token (the orange itself is
  // only ~2.6:1 on white) plus a 2px brand indicator bar on the leading edge.
  const linkActive =
    'bg-brand-soft text-fg-brand-strong before:absolute before:left-0 before:top-1/2 before:h-5 before:w-0.5 before:-translate-y-1/2 before:rounded-full before:bg-brand before:content-[\'\']'

  const renderLeaf = (entry: NavLeaf) => {
    const IconCmp = entry.icon
    return (
      <NavLink
        key={entry.labelKey}
        to={entry.to}
        onClick={() => onNavigate?.()}
        title={collapsed ? t(entry.labelKey) : undefined}
        className={({ isActive }) =>
          cn(
            linkBase,
            isActive ? linkActive : linkIdle,
            collapsed && 'justify-center px-0',
          )
        }
      >
        <IconCmp weight="duotone" className="h-5 w-5 shrink-0" />
        {!collapsed && <span className="truncate">{t(entry.labelKey)}</span>}
      </NavLink>
    )
  }

  return (
    <nav className="flex h-full flex-col gap-3 overflow-y-auto px-2 py-3">
      {navigationGroups(isAdmin).map((group) => {
        return (
          <div key={group.labelKey} className="flex flex-col gap-0.5">
            {!collapsed && (
              <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-[0.04em] text-fg-subtle">
                {t(group.labelKey)}
              </p>
            )}
            {group.items.map(renderLeaf)}
          </div>
        )
      })}
    </nav>
  )
}
