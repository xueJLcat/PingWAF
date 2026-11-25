import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { sitesApi } from '@/api/sites'
import { Select } from '@/components/ui/Select'
import { Input } from '@/components/ui/Input'
import { localizedErrorMessage } from '@/lib/errorMessages'

interface Props {
  site?: string
  digest: string
  onChange: (digest: string, draft?: string) => void
  onBusy: (busy: boolean) => void
  disabled: boolean
}

export function SiteArchiveField({ site, digest, onChange, onBusy, disabled }: Props) {
  const { t } = useTranslation()
  const version = useRef(0)
  const draft = useRef<string | undefined>(undefined)
  const [error, setError] = useState('')
  const [preview, setPreview] = useState('')
  const [uploading, setUploading] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)
  const versions = useQuery({
    queryKey: ['static-versions', site], enabled: !!site,
    queryFn: () => sitesApi.archiveVersions(site!),
  })
  function discard() {
    version.current += 1
    if (draft.current) void sitesApi.discardArchive(draft.current).catch(() => {})
    draft.current = undefined
  }
  useEffect(() => () => { discard(); onBusy(false) }, [onBusy])
  async function upload(file: File) {
    const generation = ++version.current
    let candidate: string | undefined
    setUploading(true)
    onBusy(true)
    setError('')
    try {
      const result = await sitesApi.uploadArchive(file)
      candidate = result.id
      if (generation !== version.current) return
      const session = await sitesApi.previewArchive(result.id)
      if (generation === version.current) {
        if (draft.current) void sitesApi.discardArchive(draft.current).catch(() => {})
        draft.current = candidate
        candidate = undefined
        setPreview(session.url)
        onChange(result.sha256, result.id)
      }
    } catch (err) {
      if (generation === version.current) {
        if (fileInput.current) fileInput.current.value = ''
        setError(localizedErrorMessage(err as Error))
      }
    } finally {
      if (candidate) void sitesApi.discardArchive(candidate).catch(() => {})
      if (generation === version.current) { setUploading(false); onBusy(false) }
    }
  }
  return <div className="space-y-2">
    <Input ref={fileInput} label={t('pages.sites.uploadZip')} type="file" accept=".zip,application/zip"
        disabled={uploading || disabled} error={error}
        onChange={event => { const file = event.target.files?.[0]; if (file) void upload(file) }} />
    {uploading && <p className="text-xs text-fg-subtle" role="status">{t('pages.sites.archivePreparing')}</p>}
    {digest && <p className="break-all text-xs text-fg-subtle">SHA-256 · {digest}</p>}
    {!!site && <Select label={t('pages.sites.publishedVersions')} value={preview ? '' : digest}
      disabled={uploading || disabled} onChange={event => {
        discard(); setPreview(''); setError('')
        if (fileInput.current) fileInput.current.value = ''
        onChange(event.target.value)
      }}>
      <option value="">—</option>
      {versions.data?.filter(item => !item.directory_id).map(item => <option key={item.digest} value={item.digest}>
        {new Date(item.published_at).toLocaleString()} · {item.digest.slice(0, 16)}
      </option>)}
    </Select>}
    {versions.isError && <p role="alert">{localizedErrorMessage(versions.error)}</p>}
    {preview && <details><summary>{t('pages.sites.previewIndex')}</summary>
      <iframe sandbox="" referrerPolicy="no-referrer" title={t('pages.sites.previewIndex')} src={preview} className="h-64 w-full border" />
    </details>}
  </div>
}
