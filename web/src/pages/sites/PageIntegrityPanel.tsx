import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'

type Rule = { id: string; path: string; mode: string; active_version: number | null; candidate_digest: string | null; dynamic_stage: 'off' | 'test' | 'live' }
type Preview = {
  path: string; mode: string; candidate_digest: string | null; candidate_type: string | null
  dynamic_stage: string; dynamic_region: string;
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
    {canWrite && <form className="flex items-end gap-2" onSubmit={e => { e.preventDefault(); mutation.mutate('add') }}>
      <label>公开页面路径<Input placeholder="/index.html" value={path} onChange={e => setPath(e.target.value)} /></label>
      <Button type="submit" disabled={!path || mutation.isPending}>登记页面</Button>
    </form>}
    {error && <p role="alert">{error.message}</p>}
    {list.data?.length===0 && <p className="text-sm text-fg-subtle">尚未登记公开页面。登记路径后，访问该页以获取可预览的正文。</p>}
    <ul className="divide-y divide-border">{list.data?.map(rule => <li className="flex flex-wrap items-center justify-between gap-2" key={rule.id}>
      <button type="button" className="py-2 underline" onClick={() => { select(rule.id); setMode(rule.mode); setConfirmRemoval(false) }}>
        {rule.path} · {rule.active_version ? `版本 ${rule.active_version}` : '等待审批'}
      </button>
      <span className="text-xs text-fg-subtle">{rule.active_version ? (rule.mode==='trusted_copy'?'可信副本':'仅告警') : rule.candidate_digest?'候选可预览':'等待公开访问'} · 动态防护{{off:'关闭',test:'测试中',live:'已发布'}[rule.dynamic_stage]}</span>
    </li>)}</ul>
    {preview && <div className="space-y-3">
      <h3>{preview.path}</h3>
      <Button onClick={() => void detail.refetch()}>刷新候选与事件</Button>
      <div className="grid gap-3 md:grid-cols-2">
        {([['已批准正文', preview.approved_base64, preview.approved_type], ['当前候选正文', preview.candidate_base64, preview.candidate_type]] as const).map(([title, body, media]) =>
          <div key={title}><h4>{title}</h4><pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words">{source(body, media)}</pre></div>)}
      </div>
      {preview.approved_at && <p>审批人 {preview.approved_by} · {new Date(preview.approved_at).toLocaleString()}</p>}
      {preview.candidate_digest && <p className="break-all">{preview.candidate_type} · SHA-256 {preview.candidate_digest}</p>}
      {canWrite && <div className="flex flex-wrap items-center gap-2">
        <label>发现变化时 <select value={mode} onChange={e => setMode(e.target.value)}>
          <option value="alert">仅告警</option><option value="trusted_copy">告警并返回可信副本</option>
        </select></label>
        <Button disabled={!preview.candidate_digest || mutation.isPending} onClick={() => mutation.mutate('approve')}>批准当前候选</Button>
        <Button disabled={mutation.isPending} onClick={() => confirmRemoval ? mutation.mutate('remove') : setConfirmRemoval(true)}>
          {confirmRemoval ? '确认撤销并删除已存版本' : '撤销保护'}
        </Button>
        {confirmRemoval && <button onClick={() => setConfirmRemoval(false)}>取消</button>}
      </div>}
      {canWrite && <DynamicRegion key={selected} base={base} rule={selected} initial={preview}
        refresh={()=>client.invalidateQueries({queryKey:[base]})} />}
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
  const change=useMutation({mutationFn:async(stage:string)=>{
    if(stage==='disable'){
      await apiClient.post(base.replace(/\/integrity$/, '/dynamic/disable'),{})
      setToken('')
    }else{
      const value=await apiClient.post<{html?:string;test_token?:string}>(`${base}/${rule}/dynamic`,{stage,region,digest:initial.candidate_digest??''})
      if(value.html!==undefined)setSample({html:value.html,digest:initial.candidate_digest!,region})
      if(stage!=='preview')setToken(value.test_token??'')
    }
    await refresh()
  }})
  const reviewed=sample?.digest===initial.candidate_digest && sample?.region===region
  return <section className="space-y-2"><h4>页面动态防护</h4>
    <p>当前状态：{({off:'已关闭',test:'测试访问',live:'正式发布'} as Record<string,string>)[initial.dynamic_stage]}</p>
    <label>纯文本元素 ID<Input value={region} onChange={e=>{setRegion(e.target.value);setSample(undefined)}} placeholder="article-summary"/></label>
    <div className="flex flex-wrap gap-2">
      <Button disabled={!region || !initial.candidate_digest || change.isPending} onClick={()=>change.mutate('preview')}>预览变换</Button>
      <Button disabled={!reviewed || change.isPending} onClick={()=>change.mutate('test')}>开启测试访问</Button>
      <Button disabled={!reviewed || initial.dynamic_stage!=='test' || initial.dynamic_region!==region || change.isPending} onClick={()=>change.mutate('live')}>发布该页面</Button>
      <Button disabled={change.isPending} onClick={()=>change.mutate('off')}>关闭该页面</Button>
      <Button disabled={change.isPending} onClick={()=>change.mutate('disable')}>关闭整站动态防护</Button>
    </div>
    {sample && <details open><summary>变换后的 HTML 源码</summary><pre className="max-h-64 overflow-auto whitespace-pre-wrap">{sample.html}</pre></details>}
    {token && <p>测试请求头 <code>X-PingWAF-Page-Test: {token}</code></p>}
    {change.error && <p role="alert">{change.error.message}</p>}
  </section>
}
