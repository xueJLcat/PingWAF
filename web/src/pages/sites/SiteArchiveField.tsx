import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { sitesApi } from '@/api/sites'
import { Select } from '@/components/ui/Select'
import { localizedErrorMessage } from '@/lib/errorMessages'

interface Props {
  site?: string
  digest: string
  onChange: (digest: string, draft?: string) => void
}

export function SiteArchiveField({ site, digest, onChange }: Props) {
  const { t } = useTranslation()
  const version = useRef(0)
  const draft = useRef<string | undefined>(undefined)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState('')
  const versions = useQuery({
    queryKey: ['static-versions', site], enabled: !!site,
    queryFn: () => sitesApi.archiveVersions(site!),
  })
  function discard() {
    version.current += 1
    if (draft.current) void sitesApi.discardArchive(draft.current).catch(() => {})
    draft.current = undefined
  }
  useEffect(() => discard, [])
  async function upload(file: File) {
    discard()
    const generation = version.current
    setError('')
    setPreview('')
    onChange('')
    try {
      const result = await sitesApi.uploadArchive(file)
      if (generation !== version.current) {
        await sitesApi.discardArchive(result.id)
        return
      }
      draft.current = result.id
      const session = await sitesApi.previewArchive(result.id)
      if (generation === version.current) {
        setPreview(session.url)
        onChange(result.sha256, result.id)
      }
    } catch (err) {
      if (generation === version.current) setError(localizedErrorMessage(err as Error))
    }
  }
  return <div className="space-y-2">
    <label className="block text-sm">{t('pages.sites.uploadZip')}
      <input className="block w-full" type="file" accept=".zip,application/zip"
        onChange={event => { const file = event.target.files?.[0]; if (file) void upload(file) }} />
    </label>
    {!!site && <Select label={t('pages.sites.publishedVersions')} value={draft.current ? '' : digest}
      onChange={event => { discard(); setPreview(''); setError(''); onChange(event.target.value) }}>
      <option value="">—</option>
      {versions.data?.map(item => <option key={item.digest} value={item.digest}>
        {new Date(item.published_at).toLocaleString()} · {item.digest.slice(0, 16)}
      </option>)}
    </Select>}
    {versions.isError && <p role="alert">{localizedErrorMessage(versions.error)}</p>}
    {error && <p role="alert">{error}</p>}
    {preview && <details><summary>{t('pages.sites.previewIndex')}</summary>
      <iframe sandbox="" referrerPolicy="no-referrer" title={t('pages.sites.previewIndex')} src={preview} className="h-64 w-full border" />
    </details>}
  </div>
}
