import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'

interface Database { path: string; path_from_env: boolean; active: boolean; configured: boolean; database_type: string | null; error: string | null }
interface Names { path: string; operator_path: string | null; entries: number; error: string | null }

export function AsnDataCard({ canWrite }: { canWrite: boolean }) {
  const client = useQueryClient()
  const db = useQuery({ queryKey: ['asn', 'database'], queryFn: () => api.get<Database>('/asn/database') })
  const names = useQuery({ queryKey: ['asn', 'names'], queryFn: () => api.get<Names>('/asn/names') })
  const [mmdb, setMmdb] = useState<File | null>(null)
  const [tsv, setTsv] = useState<File | null>(null)
  const [count, setCount] = useState<number | null>(null)
  const [message, setMessage] = useState('')
  const action = useMutation({
    mutationFn: async (kind: 'database' | 'remove-db' | 'preview' | 'apply' | 'restore') => {
      if (kind === 'preview' && tsv) {
        setCount(await api.post<number>('/asn/names/preview', tsv))
        return '校验完成，请核对记录数并应用。'
      }
      if (kind === 'database' && mmdb) {
        const body = new FormData()
        body.set('file', mmdb)
        await api.post('/asn/database', body)
      } else if (kind === 'apply' && tsv) {
        await api.put('/asn/names', tsv)
        setCount(null)
      } else if (kind === 'restore') {
        await api.delete('/asn/names')
        setCount(null)
      } else if (kind === 'remove-db') {
        await api.delete('/asn/database')
      }
      await client.invalidateQueries({ queryKey: ['asn'] })
      return '已更新。'
    },
    onMutate: () => setMessage(''),
    onSuccess: setMessage,
    onError: (e) => setMessage(e.message),
  })
  const busy = action.isPending || !canWrite
  return <Card>
    <CardHeader title="ASN 数据源" description="流量分析用 MMDB 识别网络编号，用名称表显示对应机构。" />
    <CardBody className="grid gap-5 text-sm">
      <fieldset disabled={busy || !db.data} className="grid min-w-0 gap-2">
        <legend className="font-medium">网络编号数据库</legend>
        <p className="break-all">{db.error?.message || (db.data ? (db.data.active ? db.data.database_type : '未启用') + ' · ' + db.data.path : '加载中…')}</p>
        {db.data?.error && <p role="alert">{db.data.error}</p>}
        {db.data?.path_from_env && <p>上传会替换运维指定路径的文件。该文件由运维移除。</p>}
        <input aria-label="选择 ASN MMDB" type="file" accept=".mmdb" onChange={e => setMmdb(e.target.files?.[0] ?? null)} />
        <div className="flex flex-wrap gap-2">
          <Button disabled={!mmdb} onClick={() => { if (!db.data?.path_from_env || window.confirm('替换运维指定的数据库文件？')) action.mutate('database') }}>安装数据库</Button>
          <Button variant="secondary" disabled={!db.data?.configured || db.data.path_from_env} onClick={() => { if (window.confirm('移除已安装的 ASN 数据库？')) action.mutate('remove-db') }}>移除数据库</Button>
        </div>
      </fieldset>
      <fieldset disabled={busy || !names.data} className="grid min-w-0 gap-2 border-t border-line pt-3">
        <legend className="font-medium">机构名称覆盖表</legend>
        <p className="break-all">{names.error?.message || (names.data ? '控制台覆盖 ' + names.data.entries + ' 条 · ' + names.data.path : '加载中…')}</p>
        {names.data?.error && <p role="alert">{names.data.error}</p>}
        <p className="break-all">基础来源为内置名称表{names.data?.operator_path && '及 ' + names.data.operator_path}。上传 UTF-8 TSV，每行用制表符分隔 AS 编号与机构名称。</p>
        <input aria-label="选择 ASN 名称表" type="file" accept=".tsv,.txt" onChange={e => { setTsv(e.target.files?.[0] ?? null); setCount(null); setMessage('') }} />
        {count !== null && <p>待应用 {count} 条记录，将替换上次导入的名称表。</p>}
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" disabled={!tsv} onClick={() => action.mutate('preview')}>校验文件</Button>
          <Button disabled={count === null} onClick={() => action.mutate('apply')}>应用名称表</Button>
          <Button variant="secondary" disabled={!names.data?.entries && !names.data?.error} onClick={() => { if (window.confirm('撤销控制台导入的全部名称？')) action.mutate('restore') }}>恢复基础来源</Button>
        </div>
      </fieldset>
      <p role="status" aria-live="polite">{action.isPending ? '处理中…' : message}</p>
    </CardBody>
  </Card>
}
