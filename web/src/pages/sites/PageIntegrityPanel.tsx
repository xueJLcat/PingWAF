import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'

type Rule = { id: string; path: string; mode: string; active_version: number | null; candidate_digest: string | null; dynamic_stage: 'off' | 'test' | 'live' }
type Preview = {
  path: string; mode: string; candidate_digest: string | null; candidate_type: string | null
  dynamic_stage: string; dynamic_region: string; tested_digest: string;
  candidate_base64: string | null; approved_base64: string | null; approved_digest: string | null
  approved_type: string | null; approved_at: string | null; approved_by: string | null
  events: { category: string; detail: string; observations: number; last_seen: string }[]
}

function source(value: string | null, media: string | null) {
  if (value === null) return '暂无内容'
  const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0))
  const charset = /charset=["']?([^;"'\s]+)/i.exec(media || '')?.[1] || 'utf-8'
  try { return new TextDecoder(charset, { fatal: true }).decode(bytes) }
  catch { return 'Base64\n' + value }
}

export function PageIntegrityPanel({ siteId, canWrite }: { siteId: string; canWrite: boolean }) {
  const client = useQueryClient()
  const base = `/sites/${siteId}/integrity`
  const [path, setPath] = useState('')
  const [selected, select] = useState('')
  const [mode, setMode] = useState('alert')
  const [confirmRemoval, setConfirmRemoval] = useState(false)
  const list = useQuery({ queryKey: [base], queryFn: () => apiClient.get<Rule[]>(base) })
  const detail = useQuery({ queryKey: [base, selected], enabled: Boolean(selected),
    queryFn: () => apiClient.get<Preview>(`${base}/${selected}`), staleTime: Infinity, refetchOnWindowFocus: false })
  const preview = detail.data
  const mutation = useMutation({
    mutationFn: async (action: 'add' | 'approve' | 'remove') => {
      if (action === 'add') {
        const id = await apiClient.post<string>(base, { path })
        select(id); setMode('alert'); setPath(''); setConfirmRemoval(false)
      } else if (action === 'approve' && preview?.candidate_digest) {
        await apiClient.post(`${base}/${selected}/approve`, { digest: preview.candidate_digest, content_type: preview.candidate_type, mode })
      } else if (action === 'remove') {
        await apiClient.delete(`${base}/${selected}`)
        select(''); setConfirmRemoval(false)
      }
    },
    onSuccess: () => client.invalidateQueries({ queryKey: [base] }),
  })
  const error = mutation.error || detail.error || list.error
  return <section role="tabpanel" aria-label="网页防篡改" className="space-y-4">
    {canWrite && <form className="flex flex-wrap items-end gap-2" onSubmit={e => { e.preventDefault(); mutation.mutate('add') }}>
      <div className="min-w-0 flex-1"><Input required disabled={mutation.isPending} label="公开页面路径" placeholder="/index.html" value={path} onChange={e => setPath(e.target.value)} /></div>
      <Button type="submit" variant="primary" loading={mutation.isPending && mutation.variables === 'add'} disabled={!path.trim() || mutation.isPending}>登记页面</Button>
    </form>}
    {error && <p role="alert">{error.message}</p>}
    {list.isLoading && <p role="status">正在读取页面规则…</p>}
    {selected && detail.isLoading && <p role="status">正在读取候选正文与审批记录…</p>}
    {list.data?.length===0 && <p className="text-sm text-fg-subtle">尚未登记公开页面。登记路径后，访问该页以获取可预览的正文。</p>}
    <ul className="divide-y divide-border">{list.data?.map(rule => <li className="flex flex-wrap items-center justify-between gap-2" key={rule.id}>
      <button type="button" disabled={mutation.isPending} aria-pressed={selected === rule.id} className="min-w-0 break-all rounded-md px-2 py-2 text-left text-fg-brand-strong underline aria-pressed:bg-brand-soft" onClick={() => { select(rule.id); setMode(rule.mode); setConfirmRemoval(false) }}>
        {rule.path} · {rule.active_version ? `版本 ${rule.active_version}` : '等待审批'}
      </button>
      <span className="text-xs text-fg-subtle">{rule.active_version ? (rule.mode==='trusted_copy'?'可信副本':'仅告警') : rule.candidate_digest?'候选可预览':'等待公开访问'} · 动态防护{{off:'关闭',test:'测试中',live:'已发布'}[rule.dynamic_stage]}</span>
    </li>)}</ul>
    {preview && <div className="space-y-3">
      <h3 className="break-all font-medium">{preview.path}</h3>
      <Button loading={detail.isFetching} onClick={() => void detail.refetch()}>刷新候选与事件</Button>
      <div className="grid gap-3 md:grid-cols-2">
        {([['已批准正文', preview.approved_base64, preview.approved_type], ['当前候选正文', preview.candidate_base64, preview.candidate_type]] as const).map(([title, body, media]) =>
          <div key={title} className="min-w-0 rounded-lg border border-border"><h4 className="border-b border-border px-3 py-2 font-medium">{title}</h4><pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words p-3 text-xs">{source(body, media)}</pre></div>)}
      </div>
      {preview.approved_at && <p>审批人 {preview.approved_by} · {new Date(preview.approved_at).toLocaleString()}</p>}
      {preview.candidate_digest && <p className="break-all">{preview.candidate_type} · SHA-256 {preview.candidate_digest}</p>}
      {canWrite && <div className="flex flex-wrap items-end gap-2">
        <Select label="发现变化时" disabled={mutation.isPending} value={mode} onChange={e => setMode(e.target.value)}>
          <option value="alert">仅告警</option><option value="trusted_copy">告警并返回可信副本</option>
        </Select>
        <Button variant="primary" disabled={!preview.candidate_digest || mutation.isPending || detail.isFetching} onClick={() => mutation.mutate('approve')}>批准当前候选</Button>
        <Button disabled={mutation.isPending} onClick={() => setConfirmRemoval(true)}>撤销保护</Button>
        <ConfirmDialog open={confirmRemoval} title="撤销保护" description={preview.path} confirmLabel="确认撤销并删除已存版本"
          loading={mutation.isPending} onClose={() => setConfirmRemoval(false)} onConfirm={() => mutation.mutate('remove', {onError: () => setConfirmRemoval(false)})} />
      </div>}
      {canWrite && <DynamicRegion key={selected} base={base} rule={selected} initial={preview}
        refresh={()=>client.invalidateQueries({queryKey:[base]})} />}
      <h4 className="font-medium">最近事件</h4>
      {!preview.events.length && <p className="text-sm text-fg-subtle">暂无事件。</p>}
      <ul>{preview.events.map(event => <li key={event.category + event.detail}>
        {event.last_seen} · {event.category} · {event.detail} · {event.observations} 次
      </li>)}</ul>
    </div>}
  </section>
}

function DynamicRegion({base,rule,initial,refresh}: {
  base:string; rule:string; initial:Preview; refresh:()=>Promise<void>
}) {
  const [region,setRegion]=useState(initial.dynamic_region)
  const [sample,setSample]=useState<{html:string;digest:string;region:string}>()
  const [token,setToken]=useState('')
  const [confirmDisable, setConfirmDisable] = useState(false)
  const change=useMutation({mutationFn:async(stage:string)=>{
    if(stage==='disable'){
      await apiClient.post(base.replace(/\/integrity$/, '/dynamic/disable'),{})
      setToken('')
      setSample(undefined)
    }else{
      const value=await apiClient.post<{html?:string;test_token?:string}>(`${base}/${rule}/dynamic`,{stage,region,digest:initial.candidate_digest??''})
      if(value.html!==undefined)setSample({html:value.html,digest:initial.candidate_digest!,region})
      if(stage!=='preview')setToken(value.test_token??'')
      if(stage!=='preview')setSample(undefined)
    }
    await refresh()
  }, onSettled: () => setConfirmDisable(false)})
  const reviewed=sample?.digest===initial.candidate_digest && sample?.region===region
  const tested=initial.dynamic_stage==='test' && initial.dynamic_region===region &&
    !!initial.tested_digest && initial.tested_digest===initial.candidate_digest
  return <section className="space-y-3 rounded-lg border border-border p-4"><h4 className="font-medium">页面动态防护</h4>
    <p>当前状态：{({off:'已关闭',test:'测试访问',live:'正式发布'} as Record<string,string>)[initial.dynamic_stage]}</p>
    <Input label="纯文本元素 ID" disabled={change.isPending} value={region} onChange={e=>{setRegion(e.target.value);setSample(undefined);setToken('')}} placeholder="article-summary"/>
    <div className="flex flex-wrap gap-2">
      <Button disabled={!region || !initial.candidate_digest || change.isPending} onClick={()=>change.mutate('preview')}>预览变换</Button>
      <Button disabled={!reviewed || change.isPending} onClick={()=>change.mutate('test')}>开启测试访问</Button>
      <Button variant="primary" disabled={!tested || change.isPending} onClick={()=>change.mutate('live')}>发布该页面</Button>
      <Button disabled={change.isPending || initial.dynamic_stage==='off'} onClick={()=>change.mutate('off')}>关闭该页面</Button>
      <Button disabled={change.isPending} onClick={()=>setConfirmDisable(true)}>关闭整站动态防护</Button>
      <ConfirmDialog open={confirmDisable} title="关闭整站动态防护" description="该站点所有页面的动态防护都会关闭。" confirmLabel="确认关闭整站"
        loading={change.isPending} onClose={()=>setConfirmDisable(false)} onConfirm={()=>change.mutate('disable')} />
    </div>
    {sample && reviewed && <details open><summary>变换后的 HTML 源码</summary><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words">{sample.html}</pre></details>}
    {token && tested && <p className="break-all">测试请求头 <code>X-PingWAF-Page-Test: {token}</code></p>}
    {change.error && <p role="alert">{change.error.message}</p>}
  </section>
}
