import {
  House,
  FileText,
  Monitor,
  ShieldCheck,
  FolderOpen,
  Database,
  HardDrives,
  Globe,
  Lock,
  ChartLine,
  List,
  Desktop,
  Gear,
  FunnelSimple,
  Prohibit,
  UserCircle,
  FlowArrow,
  Bell,
  ClockCounterClockwise,
  type Icon,
} from '@phosphor-icons/react'

export interface NavLeaf {
  to: string
  labelKey: string
  adminOnly?: boolean
  icon: Icon
}

interface NavGroup {
  labelKey: string
  items: NavLeaf[]
}

const groups: NavGroup[] = [
  {
    labelKey: 'nav.group.overview',
    items: [
      { to: '/dashboard', labelKey: 'nav.dashboard', icon: House },
      { to: '/reports', labelKey: 'nav.protectionReports', icon: FileText },
      { to: '/live-protection', labelKey: 'nav.liveProtection', icon: Monitor },
    ],
  },
  {
    labelKey: 'nav.group.trafficLogs',
    items: [
      { to: '/traffic', labelKey: 'nav.traffic', icon: ChartLine },
      { to: '/logs', labelKey: 'nav.logs', icon: List },
      { to: '/lifecycle', adminOnly: true, labelKey: 'nav.lifecycle', icon: FlowArrow },
    ],
  },
  {
    labelKey: 'nav.group.securityAssets',
    items: [
      { to: '/sites', labelKey: 'nav.sites', icon: Globe },
      { to: '/page-protection', labelKey: 'pages.sites.pageProtection', icon: ShieldCheck },
      { to: '/ip-groups', labelKey: 'nav.ipGroups', icon: FunnelSimple },
      { to: '/blocked-ips', labelKey: 'nav.blockedIps', icon: Prohibit },
      { to: '/ssl', labelKey: 'nav.ssl', icon: Lock },
    ],
  },
  {
    labelKey: 'nav.group.platform',
    items: [
      { to: '/agents', labelKey: 'nav.agents', icon: Desktop },
      { to: '/static-directories', adminOnly: true, labelKey: 'nav.staticDirectories', icon: FolderOpen },
      { to: '/asn-data', adminOnly: true, labelKey: 'nav.asnData', icon: Database },
      { to: '/log-buffer', adminOnly: true, labelKey: 'nav.logBuffer', icon: HardDrives },
      { to: '/notifications', labelKey: 'nav.notifications', icon: Bell },
      {
        to: '/config-versions', adminOnly: true,
        labelKey: 'nav.configVersions',
        icon: ClockCounterClockwise,
      },
      { to: '/account', labelKey: 'nav.account', icon: UserCircle },
      { to: '/settings', labelKey: 'nav.settings', icon: Gear },
    ],
  },
]

export function navigationGroups(isAdmin: boolean) {
  return groups.map(group => ({ ...group, items: group.items.filter(item => !item.adminOnly || isAdmin) }))
}
