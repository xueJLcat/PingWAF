import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useInfiniteQuery } from '@tanstack/react-query'
import { sitesApi, siteKeys } from '@/api/sites'
import { ErrorState } from '@/components/ErrorState'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { useDebouncedValue } from '@/hooks'
import { formatSiteAddress } from '@/lib/format'

interface Props {
  label: string
  options: { value: string; label: string }[]
  value: string
  onChange: (value: string) => void
}

export function ConfigSiteSelect({ label, options, value, onChange }: Props) {
  const { t } = useTranslation()
  const [input, setInput] = useState('')
  const [selected, setSelected] = useState({ value, label: value })
  const search = useDebouncedValue(input.trim())
  const sites = useInfiniteQuery({
    queryKey: [...siteKeys.all, 'snapshot-scope-options', search],
    initialPageParam: 1,
    queryFn: ({ pageParam }) => sitesApi.list({ search, page: pageParam, page_size: 200 }),
    getNextPageParam: (last, _pages, page) => page * 200 < last.total ? page + 1 : undefined,
  })
  const choices = new Map(options.map(option => [option.value, option]))
  for (const page of sites.data?.pages ?? []) {
    for (const site of page.items) choices.set(site.id, { value: site.id, label: formatSiteAddress(site) })
  }
  if (!choices.has(value)) choices.set(value, selected.value === value ? selected : { value, label: value })

  return (
    <div role="group" aria-label={label} className="min-w-0 space-y-2">
      {(input || (sites.data?.pages[0].total ?? 0) > 200) && (
        <Input type="search" label={t('syslog.search')} value={input}
          onChange={event => setInput(event.target.value)} />
      )}
      <Select label={label} value={value} options={Array.from(choices.values())}
        onChange={event => {
          setSelected({ value: event.target.value, label: event.target.selectedOptions[0].text })
          onChange(event.target.value)
        }} />
      {sites.hasNextPage && <Button size="sm" loading={sites.isFetchingNextPage}
        onClick={() => void sites.fetchNextPage()}>{t('pages.configVersions.moreSites')}</Button>}
      {sites.isError && <ErrorState variant="inline" error={sites.error}
        onRetry={() => sites.isFetchNextPageError ? sites.fetchNextPage() : sites.refetch()} />}
    </div>
  )
}
