import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { apiClient, ApiError } from '@/api/client'
import { sitesApi } from '@/api/sites'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
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
  const client = useQueryClient()
  const user = useAuthStore(s => s.user?.id)
  const panel = useRef<HTMLElement>(null)
  const [page, setPage] = useState(1)
  const [chosen, setChosen] = useState<string[] | null>(null)
  const [timezone, setTimezone] = useState(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  const [from, setFrom] = useState(() => localTime(new Date(Date.now()-3600000)))
  const [to, setTo] = useState(() => localTime(new Date()))
  const sites = useQuery({queryKey:['report-site-options', user,page],queryFn:()=>sitesApi.list({page,page_size:40})})
  const ids = chosen ?? (sites.data?.items[0] ? [sites.data.items[0].id] : [])
  const selection = {sites:ids, timezone}
  const [now,setNow]=useState(Date.now())
  useEffect(()=>{ if (!live) return; const timer=setInterval(()=>setNow(Date.now()),5000);return ()=>clearInterval(timer) },[live])
  const [error,setError]=useState('')
  const jobs=useQuery({queryKey:['report-jobs', user],queryFn:()=>apiClient.get<Job[]>('/reports'),enabled:!live,refetchInterval:5000})
  const screen=useQuery({queryKey:['report-screen',user,ids,timezone],queryFn:()=>apiClient.post<Live>('/reports/live',selection),
    enabled:live && ids.length>0 && !!timezone,refetchInterval:15000,refetchIntervalInBackground:false,retry:false})
  const create=useMutation({mutationFn:()=>apiClient.post<string>('/reports',{...selection,from:new Date(from).toISOString(),to:new Date(to).toISOString()}),
    onSuccess:()=>client.invalidateQueries({queryKey:['report-jobs',user]})})
  const denied=screen.error instanceof ApiError && [401,403,404].includes(screen.error.status)
  const scopeKey=JSON.stringify([user,ids,timezone])
  const [lastOnline,setLastOnline]=useState<{scope:string;value:Live}>()
  useEffect(()=>{
    if(denied) {setLastOnline(undefined);return}
    if(screen.data?.nodes.length && screen.data.nodes.every(n=>n.online)){
      setLastOnline({scope:scopeKey,value:screen.data})
    }
  },[denied,scopeKey,screen.data])
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
  async function download(id:string,format:string){
    try {
      setError('')
      const blob=await apiClient.get<Blob>(`/reports/${id}/${format}`,{rawBlob:true})
      const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`pingwaf-${id}.${format}`;a.click()
      setTimeout(()=>URL.revokeObjectURL(url),1000)
    }catch(err){setError(err instanceof Error?err.message:'下载失败')}
  }
  const alerts=[error,sites.error?.message,jobs.error?.message,create.error?.message,screen.error?.message].filter(Boolean)
  return <main ref={panel} className="space-y-5 overflow-y-auto bg-bg p-4 text-fg">
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="text-2xl font-semibold">{live?'实时防护大屏':'防护报告'}</h1>
      {live && <Button onClick={()=>void (document.fullscreenElement?document.exitFullscreen():panel.current?.requestFullscreen())?.catch(e=>setError(e.message))}>全屏显示</Button>}</div>
    <div className="flex flex-wrap items-end gap-4">
      <details className="relative"><summary>站点范围（{ids.length}）</summary><fieldset className="space-y-2 border p-3">
        {sites.data?.items.map(s=><label className="block" key={s.id}><input type="checkbox" checked={ids.includes(s.id)}
          disabled={!ids.includes(s.id)&&ids.length>=16} onChange={e=>setChosen(e.target.checked?[...ids,s.id].sort():ids.filter(id=>id!==s.id))}/> {s.domain}</label>)}
        {page>1 && <Button onClick={()=>setPage(page-1)}>上一页</Button>}
        {sites.data && sites.data.total>page*40 && <Button onClick={()=>setPage(page+1)}>下一页</Button>}
      </fieldset></details>
      <label>统计时区<Input value={timezone} onChange={e=>setTimezone(e.target.value)} placeholder="Asia/Shanghai" /></label>
      {!live && <><label>开始（本机时间）<Input type="datetime-local" value={from} onChange={e=>setFrom(e.target.value)}/></label>
        <label>结束（本机时间）<Input type="datetime-local" value={to} onChange={e=>setTo(e.target.value)}/></label>
        <Button disabled={create.isPending || !ids.length || !from || !to || !timezone} onClick={()=>create.mutate()}>生成报告</Button></>}
    </div>
    {alerts.map((message,i)=><p key={i} role="alert">{message}</p>)}
    {!live && <table className="w-full text-left"><thead><tr><th>提交时间</th><th>统计时段</th><th>状态</th><th>下载</th></tr></thead>
      <tbody>{jobs.data?.map(job=><tr key={job.id}><td>{new Date(job.created_at).toLocaleString()}</td>
        <td>{reportInterval(job)}</td>
        <td>{({queued:'排队中',running:'生成中',ready:'已生成',failed:'失败'} as Record<string,string>)[job.status]} {job.error}</td>
        <td>{job.status==='ready' && ['pdf','csv'].map(format=><Button key={format} onClick={()=>void download(job.id,format)}>{format.toUpperCase()}</Button>)}</td></tr>)}</tbody></table>}
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
      <section><h2>最近 15 分钟请求与处置趋势</h2><div className="h-64"><ResponsiveContainer width="100%" height="100%">
        <LineChart data={[...buckets.values()]}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="label"/><YAxis allowDecimals={false}/><Tooltip/><Legend/>
          {(['requests','blocked','challenged'] as const).map((key,i)=><Line key={key} dataKey={key} name={labels[key]} stroke={['#3986c8','#cd6148','#a18130'][i]} connectNulls={false} isAnimationActive={false}/>)}
        </LineChart></ResponsiveContainer></div></section>
      <div className="grid gap-5 md:grid-cols-2"><section><h2>站点排行</h2><table className="w-full text-left"><thead><tr><th>站点</th><th>请求</th><th>拦截</th><th>挑战</th></tr></thead>
        <tbody>{[...ranked.entries()].sort((a,b)=>(b[1].requests??-1)-(a[1].requests??-1)).map(([id,r])=><tr key={id}><td>{r.domain}{!r.covered?'（部分）':''}</td>
          {(['requests','blocked','challenged'] as const).map(k=><td key={k}>{r[k]===null || (!r.covered && r[k]===0)?'缺失':r[k]}</td>)}</tr>)}</tbody></table></section>
      <section><h2>节点状态</h2>{data.nodes.length===0 && <p>所选站点无已分派节点</p>}
        {(screen.data?.nodes??data.nodes).map(n=><p key={n.id}>{n.name} · {n.online?'在线':'离线'} · {n.heartbeat?new Date(n.heartbeat).toLocaleString():'无心跳'}</p>)}</section></div>
    </>}
  </main>
}
