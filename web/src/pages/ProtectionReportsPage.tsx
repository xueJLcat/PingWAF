import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { apiClient, ApiError } from '@/api/client'
import { sitesApi } from '@/api/sites'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { Input } from '@/components/ui/Input'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Download, FileText, Monitor, Trash } from '@phosphor-icons/react'
import { formatSiteAddress } from '@/lib/format'
import { useCanWrite, useNow } from '@/hooks'
import { useAuthStore } from '@/stores/authStore'

type Job = { from: string; to: string; timezone: string; id: string; created_at: string; status: string; error: string | null }
type Measures = { requests: number | null; blocked: number | null; challenged: number | null }
type Row = Measures & { site: string; domain: string; bucket: string; local_time: string; covered: boolean }
type Live = { generated_at: string; metrics: Row[]; nodes: { id: string; name: string; heartbeat: string | null; online: boolean }[] }
const labels = { requests: '请求', blocked: '拦截', challenged: '挑战' }
const blank = (): Measures => ({ requests: null, blocked: null, challenged: null })
function totals(target: Measures, row: Measures) {
  for (const key of ['requests','blocked','challenged'] as const) {
    if (row[key] !== null) target[key] = (target[key] ?? 0) + row[key]
  }
}

function reportInterval(job: Job) {
  try {
    const local = new Intl.DateTimeFormat(undefined, {dateStyle:'short',timeStyle:'short',timeZone:job.timezone})
    return local.formatRange(new Date(job.from),new Date(job.to)) + ' · ' + job.timezone
  } catch {
    return job.from + ' – ' + job.to
  }
}

function localTime(date: Date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0,16)
}

export function ProtectionReportsPage({ live = false }: { live?: boolean }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const canWrite = useCanWrite()
  const client = useQueryClient()
  const user = useAuthStore(s => s.user?.id)
  const panel = useRef<HTMLElement>(null)
  const [fullscreen, setFullscreen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Job | null>(null)
  const remove = useMutation({
    mutationFn: (id: string) => apiClient.delete<void>(`/reports/${id}`),
    onSuccess: async () => {
      setDeleteTarget(null)
      await client.invalidateQueries({queryKey: ['report-jobs', user]})
    },
  })
  useEffect(() => {
    const update = () => setFullscreen(document.fullscreenElement === panel.current)
    document.addEventListener('fullscreenchange', update)
    return () => document.removeEventListener('fullscreenchange', update)
  }, [])
  const [page, setPage] = useState(1)
  const [chosen, setChosen] = useState<Record<string, string> | null>(null)
  const [timezone, setTimezone] = useState(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [from, setFrom] = useState(() => localTime(new Date(Date.now()-3600000)))
  const [to, setTo] = useState(() => localTime(new Date()))
  const sites = useQuery({queryKey:['report-site-options', user,page],queryFn:()=>sitesApi.list({page,page_size:40})})
  const emptyScope = sites.isSuccess && sites.data.total === 0
  const firstSite = sites.data?.items[0]
  const addresses = chosen ?? (firstSite ? { [firstSite.id]: formatSiteAddress(firstSite) } : {})
  const ids = Object.keys(addresses).sort()
  function chooseSite(id: string, address: string, checked: boolean) {
    const next = { ...addresses }
    if (checked) next[id] = address
    else delete next[id]
    setChosen(next)
  }
  const changePage = (next: number) => {
    setChosen(addresses)
    setPage(next)
  }
  const start = Date.parse(from)
  const end = Date.parse(to)
  const now = useNow(5000)
  const rangeError = !from || !to ? '' : start >= end ? '结束时间须晚于开始时间。'
    : end-start > 7*86400000 ? '单份报告最多包含七天，请缩短统计时段。'
    : end > now+30000 ? '结束时间不能晚于当前时间。' : ''
  const selection = {sites:ids, timezone}
  let validZone = false
  try { new Intl.DateTimeFormat('en', { timeZone: timezone }); validZone = true } catch { /* Editing an incomplete IANA name. */ }
  const [error,setError]=useState('')
  const jobs=useQuery({queryKey:['report-jobs', user],queryFn:()=>apiClient.get<Job[]>('/reports'),enabled:!live,refetchInterval:5000})
  const screen=useQuery({queryKey:['report-screen',user,ids,timezone],queryFn:()=>apiClient.post<Live>('/reports/live',selection),
    enabled:live && ids.length>0 && validZone,refetchInterval:15000,refetchIntervalInBackground:false,retry:false})
  const create=useMutation({mutationFn:()=>apiClient.post<string>('/reports',{...selection,from:new Date(from).toISOString(),to:new Date(to).toISOString()}),
    onSuccess:()=>client.invalidateQueries({queryKey:['report-jobs',user]})})
  const denied=screen.error instanceof ApiError && [401,403,404].includes(screen.error.status)
  const scopeKey=JSON.stringify([user,ids,timezone])
  const [lastOnline,setLastOnline]=useState<{scope:string;value:Live}>()
  if (denied && lastOnline) {
    setLastOnline(undefined)
  } else if (!denied && screen.data?.nodes.length && screen.data.nodes.every(node => node.online) &&
    (lastOnline?.scope !== scopeKey || lastOnline.value !== screen.data)) {
    setLastOnline({scope: scopeKey, value: screen.data})
  }
  const offline=screen.data?.nodes.some(n=>!n.online)
  const data=denied?undefined:offline && lastOnline?.scope===scopeKey?lastOnline.value:screen.data
  const buckets=new Map<string,{label:string;covered:boolean} & Measures>()
  const ranked=new Map<string,{domain:string;covered:boolean} & Measures>()
  const summary = blank()
  const incomplete = data?.metrics.some(row=>!row.covered)
  for(const row of data?.metrics ?? []){
    totals(summary,row)
    const bucket=buckets.get(row.bucket)??{...blank(),label:row.local_time.slice(11),covered:true}
    const site=ranked.get(row.site)??{...blank(),domain:row.domain,covered:true}
    totals(bucket,row);totals(site,row);bucket.covered&&=row.covered;site.covered&&=row.covered
    buckets.set(row.bucket,bucket);ranked.set(row.site,site)
  }
  for (const bucket of buckets.values()) {
    if (bucket.covered) continue
    for (const metric of ['requests', 'blocked', 'challenged'] as const) {
      if (bucket[metric] === 0) bucket[metric] = null
    }
  }
  const download = useMutation({
    mutationFn: async ({id, format}: {id:string; format:string}) => {
      const blob=await apiClient.get<Blob>(`/reports/${id}/${format}`,{rawBlob:true})
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `pingwaf-${id}.${format}`
      link.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
  })
  const alerts=[error,download.error?.message,sites.error?.message,jobs.error?.message,create.error?.message,screen.error?.message].filter(Boolean)
  return <section ref={panel} className="min-w-0 space-y-5 text-fg fullscreen:overflow-auto fullscreen:bg-base fullscreen:p-4">
    <PageHeader title={t(live ? 'nav.liveProtection' : 'nav.protectionReports')} actions={live && document.fullscreenEnabled &&
      <Button onClick={()=>void (fullscreen ? document.exitFullscreen() : panel.current?.requestFullscreen())?.catch(e=>setError(e.message))}>{fullscreen ? '退出全屏' : '全屏显示'}</Button>} />
    {emptyScope ? <Card padded><EmptyState icon={live ? <Monitor /> : <FileText />}
      title={t('nav.emptySiteScope')} description={t(live ? 'nav.emptyLiveHelp' : 'nav.emptyReportsHelp')}
      action={canWrite && <Button variant="primary" onClick={() => navigate('/sites?new=1')}>{t('pages.sites.addSite')}</Button>}
    /></Card> : <Card><CardBody className="grid items-start gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <div className="min-w-0 space-y-1.5"><span className="block text-[13px] font-medium text-fg-subtle">站点范围</span>
      <details><summary aria-label={`站点范围（${ids.length}）`} className="pw-touch-target h-9 cursor-pointer content-center rounded-md border border-line bg-elevated px-3 text-sm">已选 {ids.length} 个站点</summary><fieldset className="mt-2 max-h-64 space-y-1 overflow-y-auto rounded-md border border-line p-2">
        {sites.data?.items.map(s=><label className="pw-touch-check flex items-center gap-2 break-all text-sm" key={s.id}><input type="checkbox" checked={ids.includes(s.id)}
          disabled={!ids.includes(s.id)&&ids.length>=16} onChange={e=>chooseSite(s.id, formatSiteAddress(s), e.target.checked)}/> {formatSiteAddress(s)}</label>)}
        {!sites.data?.items.length && <p className="text-xs text-fg-subtle">{sites.isPending ? '正在读取站点…' : sites.isError ? '读取站点失败' : '没有可选站点'}</p>}
        {page>1 && <Button onClick={()=>changePage(page-1)}>上一页</Button>}
        {sites.data && sites.data.total>page*40 && <Button onClick={()=>changePage(page+1)}>下一页</Button>}
      </fieldset></details></div>
      <Input label="统计时区" error={!validZone && '请输入有效时区，例如 Asia/Shanghai。'} value={timezone} onChange={e=>setTimezone(e.target.value)} placeholder="Asia/Shanghai" />
      {!live && <><Input label="开始（本机时间）" type="datetime-local" value={from} onChange={e=>setFrom(e.target.value)}/>
        <Input label="结束（本机时间）" error={rangeError} type="datetime-local" value={to} onChange={e=>setTo(e.target.value)}/>
        <Button className="justify-self-start" variant="primary" loading={create.isPending} disabled={!!rangeError || !ids.length || !from || !to || !validZone} onClick={()=>create.mutate()}>生成报告</Button></>}
    </CardBody></Card>}
    {sites.data && sites.data.total > 0 && !ids.length && <p role="status">请在站点范围中选择至少一个站点。</p>}
    {alerts.map((message,i)=><p key={i} role="alert">{message}</p>)}
    {!live && jobs.isPending && <p role="status">正在加载报告任务…</p>}
    {!live && !emptyScope && jobs.data?.length === 0 && <p role="status">暂无报告任务。选择站点和统计时段后可生成报告。</p>}
    {!live && !!jobs.data?.length && <div className="overflow-x-auto rounded-lg border border-line bg-elevated"><table className="w-full min-w-[36rem] text-left text-sm [&_td]:px-3 [&_td]:py-2 [&_th]:p-3"><thead className="border-b border-line bg-recessed text-xs text-fg-subtle"><tr><th>提交时间</th><th>统计时段</th><th>状态</th><th>操作</th></tr></thead>
      <tbody>{jobs.data?.map(job=><tr key={job.id} data-report-id={job.id}><td>{new Date(job.created_at).toLocaleString()}</td>
        <td>{reportInterval(job)}</td>
        <td>{({queued:'排队中',running:'生成中',ready:'已生成',failed:'失败'} as Record<string,string>)[job.status]} {job.error}</td>
        <td><div className="flex items-center gap-1">{job.status==='ready' && ['pdf','csv'].map(format=><Button key={format} variant="ghost" size="sm" aria-label={`下载 ${format.toUpperCase()} 报告`} icon={<Download weight="duotone" className="h-4 w-4" />}
          disabled={download.isPending} loading={download.isPending && download.variables.id===job.id && download.variables.format===format}
          onClick={()=>download.mutate({id:job.id,format})}>{format.toUpperCase()}</Button>)}
          {canWrite && (job.status === 'ready' || job.status === 'failed') && <Button size="icon" variant="ghost"
            aria-label="删除报告" title="删除报告" className="hover:text-fg-danger" icon={<Trash weight="duotone" className="h-4 w-4" />}
            onClick={() => { remove.reset(); setDeleteTarget(job) }} />}
        </div></td></tr>)}</tbody></table></div>}
    <ConfirmDialog open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="删除报告"
      description={deleteTarget ? reportInterval(deleteTarget) : ''} confirmLabel="删除报告" loading={remove.isPending}
      onConfirm={() => { if (deleteTarget) remove.mutate(deleteTarget.id) }}>
      <p>删除后，此次报告的 PDF 和 CSV 将同时移除。</p>
      {remove.error && <p role="alert" className="text-fg-danger">{remove.error.message}</p>}
    </ConfirmDialog>
    {live && ids.length > 0 && validZone && screen.isLoading && <p role="status">正在读取实时防护数据…</p>}
    {live && data && <><p>更新于 {new Date(data.generated_at).toLocaleString()} · 每 15 秒刷新
      {(offline || screen.isError || now-Date.parse(data.generated_at)>45000) && ' · 部分节点或数据已过期'}
      {data.metrics.some(r=>!r.covered) && ' · 部分时段缺少采集记录'}</p>
      <dl className="grid gap-3 sm:grid-cols-3">
        {(['requests','blocked','challenged'] as const).map(key=><div key={key} className="rounded-lg border border-border p-4">
          <dt className="text-sm text-fg-subtle">{labels[key]} · 最近 15 分钟</dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums">{summary[key]===null || (incomplete && summary[key]===0) ? '缺失' : summary[key]?.toLocaleString()}</dd>
          {incomplete && (summary[key]??0)>0 && <span className="text-xs text-fg-subtle">已观测数量</span>}
        </div>)}
      </dl>
      <Card padded><h2 className="mb-3 font-medium">最近 15 分钟请求与处置趋势</h2><div className="h-64"><ResponsiveContainer width="100%" height="100%">
        <LineChart data={[...buckets.values()]}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="label"/><YAxis allowDecimals={false}/><Tooltip/><Legend/>
          {(['requests','blocked','challenged'] as const).map((key,i)=><Line key={key} dataKey={key} name={labels[key]} stroke={['#3986c8','#cd6148','#a18130'][i]} connectNulls={false} isAnimationActive={false}/>)}
        </LineChart></ResponsiveContainer></div></Card>
      <div className="grid gap-5 md:grid-cols-2"><Card padded className="min-w-0"><h2 className="mb-3 font-medium">站点排行</h2><table className="w-full text-left text-sm [&_td]:py-1 [&_th]:pr-2"><thead><tr><th>站点</th><th>请求</th><th>拦截</th><th>挑战</th></tr></thead>
        <tbody>{[...ranked.entries()].sort((a,b)=>(b[1].requests??-1)-(a[1].requests??-1)).map(([id,r])=><tr key={id}><td className="break-all pr-2">{addresses[id] || r.domain}{!r.covered?'（部分）':''}</td>
          {(['requests','blocked','challenged'] as const).map(k=><td key={k}>{r[k]===null || (!r.covered && r[k]===0)?'缺失':r[k]}</td>)}</tr>)}</tbody></table></Card>
      <Card padded className="min-w-0"><h2 className="mb-3 font-medium">节点状态</h2>{data.nodes.length===0 && <p>所选站点无已分派节点</p>}
        {(screen.data?.nodes??data.nodes).map(n=><p key={n.id} className="break-all py-1 text-sm">{n.name} · {n.online?'在线':'离线'} · {n.heartbeat?new Date(n.heartbeat).toLocaleString():'无心跳'}</p>)}</Card></div>
    </>}
  </section>
}
