import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { sitesApi, siteKeys } from '@/api/sites'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Switch } from '@/components/ui/Switch'
import { Button } from '@/components/ui/Button'
import { Card, CardBody } from '@/components/ui/Card'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { useRegisterUnsaved } from '@/hooks/useUnsavedGuard'
import { formatSiteAddress } from '@/lib/format'

type Config = {
  enabled:boolean; name:string; host:string; port:number; transport:string
  access:boolean; security:boolean; sites:string[] | null
  facility:number; severity:number|null; threshold:number; format:string; body:string; framing:string
  hostname:string; app:string; ip_mode:string; max_bytes:number; server_name:string; trust:string; mtls:boolean
  connect_seconds:number; write_seconds:number; retry_min:number; retry_max:number; retention_hours:number; queue_mib:number
}
type FileKind = 'ca'|'cert'|'key'
type Info = {sha256:string;expires:string}
type View = {revision:number;configured:boolean;config:Config;has_key:boolean;ca_info:Info|null;cert_info:Info|null}
type Status = {active_revision:number;enabled:boolean;host:string;port:number;transport:string;queue_count:number;queue_bytes:number;oldest:string|null;since:string;
  stats:{access_written:number;security_written:number;filtered:number;dropped_full:number;dropped_size:number;expired:number;discarded:number;storage_errors:number;retries:number;last_write:string|null;last_failure:string|null;error:string|null;peer:string|null}}
const endpoint='/settings/syslog'
const cfgKey=['settings','syslog']
const statusKey=['settings','syslog-status']
const facilities='kern user mail daemon auth syslog lpr news uucp cron authpriv ftp ntp audit alert clock local0 local1 local2 local3 local4 local5 local6 local7'.split(' ')
const levels='emerg alert crit err warning notice info debug'.split(' ')
const when=(s:string|null)=>s ? new Date(s).toLocaleString() : '—'
type Draft={revision:number;config:Config;files:Partial<Record<FileKind,string>>}
type Operation='save'|'remove'|'test'
type Confirmation={action:'remove'|'save';revision:number;target:string;discard:boolean}
function describeTarget(config:Config){
  return [config.name,config.transport.toUpperCase(),config.host,String(config.port)].filter(Boolean).join(' · ')
}

function SelectedSites({ ids, onRemove }: { ids: string[]; onRemove: (id: string) => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [page, setPage] = useState(0)
  const unique = [...new Set(ids)]
  const pages = Math.max(1, Math.ceil(unique.length / 20))
  const current = Math.min(page, pages - 1)
  if (page !== current) setPage(current)
  const visible = unique.slice(current * 20, current * 20 + 20)
  const params = { ids: visible.join(','), page_size: 20 }
  const names = useQuery({
    queryKey: siteKeys.list(params), queryFn: () => sitesApi.list(params),
    enabled: open && visible.length > 0,
  })
  const labels = new Map(names.data?.items.map(site => [site.id, formatSiteAddress(site)]))
  if (!unique.length) return <p role="status">{t('syslog.noMatch')}</p>
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary className="pw-touch-target cursor-pointer text-sm">{t('common.batch.selected', { count: unique.length })}</summary>
    {open && <div className="space-y-2 py-2">
      {names.isError && <p role="alert">{names.error.message} <Button type="button" size="sm" onClick={() => void names.refetch()}>{t('syslog.reload')}</Button></p>}
      <ul className="divide-y divide-line">{visible.map(id => <li key={id} className="flex items-center justify-between gap-3 py-1">
        <span className="min-w-0 break-all text-sm">{labels.get(id) ?? id}</span>
        <Button type="button" size="sm" variant="ghost" aria-label={t('syslog.removeSite', { site: labels.get(id) ?? id })}
          onClick={() => onRemove(id)}>{t('common.remove')}</Button>
      </li>)}</ul>
      {pages > 1 && <div className="flex items-center gap-2">
        <Button type="button" size="sm" disabled={current === 0} onClick={() => setPage(current - 1)}>{t('pagination.previous')}</Button>
        <span className="text-sm tabular-nums">{current + 1} / {pages}</span>
        <Button type="button" size="sm" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>{t('pagination.next')}</Button>
      </div>}
    </div>}
  </details>
}
export function SyslogSettings(){
  const {t}=useTranslation()
  const label=(k:string)=>t('syslog.'+k)
  const cache=useQueryClient()
  const query=useQuery({queryKey:cfgKey,queryFn:()=>api.get<View>(endpoint)})
  const status=useQuery({queryKey:statusKey,queryFn:()=>api.get<Status>(endpoint+'/status'),refetchInterval:5000})
  const [draft,setDraft]=useState<Draft|null>(null)
  const [message,setMessage]=useState('')
  const [error,setError]=useState('')
  const [conflict,setConflict]=useState(false)
  const [confirm,setConfirm]=useState<Confirmation|null>(null)
  const [busy,setBusy]=useState(false)
  const [siteSearch,setSiteSearch]=useState('')
  const [page,setPage]=useState(1)
  const [autoPort,setAutoPort]=useState(true)
  const form=useRef<HTMLFormElement>(null)
  const v=query.data
  const c=draft?.config
  useRegisterUnsaved(!!draft && (JSON.stringify(c)!==JSON.stringify(v?.config)||Object.keys(draft.files).length>0))
  const sites=useQuery({queryKey:['syslog-site-options',siteSearch,page],queryFn:()=>sitesApi.list({search:siteSearch,page,page_size:20}),enabled:!!c && c.sites!==null})
  function begin(value:View){
    setPage(1);setSiteSearch('')
    setDraft({revision:value.revision,config:{...value.config},files:{}})
    setAutoPort(value.config.port===(value.config.transport==='tls'?6514:514))
    setError('');setMessage('');setConflict(false)
  }
  function change(patch:Partial<Config>){
    setDraft(d=>d && {...d,config:{...d.config,...patch}})
    setError('');setMessage('')
  }
  async function run(op:Operation,confirmation?:Confirmation){
    if(!v || busy)return
    if(op!=='remove' && !form.current?.reportValidity())return
    const revision=confirmation?.revision??draft?.revision??v.revision
    const target=confirmation?.target??describeTarget(v.config)
    const discard=confirmation?.discard??false
    setBusy(true);setError('');setMessage('');setConfirm(null);setConflict(false)
    try{
      const body={revision,config:c??v.config,...draft?.files,discard}
      if(op==='test'){
        const r=await api.post<{id:string;peer:string;time:string}>(endpoint+'/test',body)
        setMessage([label('sent'),r.peer,r.id,when(r.time)].join(' · '))
      }else{
        const saved=op==='remove'? await api.delete<View>(endpoint,{body:{revision:body.revision,discard}}):await api.put<View>(endpoint,body)
        await cache.cancelQueries({queryKey:cfgKey,exact:true})
        cache.setQueryData(cfgKey,saved);setDraft(null);setMessage(label('saved'))
        await cache.invalidateQueries({queryKey:statusKey})
      }
    }catch(e){
      if(e instanceof ApiError && e.code==='syslog.queue_not_empty' && op!=='test'){
        await status.refetch();setConfirm({action:op,revision,target,discard:true})
      }else{
        setError(e instanceof Error?e.message:String(e));setConflict(e instanceof ApiError && e.status===409)
      }
    }finally{setBusy(false)}
  }
  function txt(k:'name'|'host'|'hostname'|'app'|'server_name',required=false){
    return <Input key={k} label={label(k)} value={c![k]} required={required} onChange={e=>change({[k]:e.target.value})}/>
  }
  function num(k:'port'|'max_bytes'|'connect_seconds'|'write_seconds'|'retry_min'|'retry_max'|'retention_hours'|'queue_mib',min:number,max:number){
    return <Input key={k} type="number" label={label(k)} min={min} max={max} required value={c![k] || ''} onChange={e=>{
      if(k==='port')setAutoPort(false)
      change({[k]:Number(e.target.value)})
    }}/>
  }
  function select(k:'format'|'body'|'framing'|'trust'|'ip_mode',options:string[],localized=false){
    return <Select label={label(k)} value={c![k]} onChange={e=>change({[k]:e.target.value})}>{options.map(o=><option key={o} value={o}>{localized?label(o):o}</option>)}</Select>
  }
  function pem(k:FileKind,info?:Info|null){
    const modified=draft?.files[k]
    return <div className="min-w-0 space-y-1" key={k}><Input key={modified===''?'cleared':k} type="file" label={label(k)} accept=".pem,.crt,.cer,.key" onChange={async e=>{
      const file=e.target.files?.[0];if(!file)return
      if(file.size>262144){setError(label('large'));e.target.value='';return}
      setBusy(true);try{const data=await file.text();setDraft(d=>d && {...d,files:{...d.files,[k]:data}});setError('');setMessage('')}
      catch{setError(label('readError'))}finally{setBusy(false)}
    }}/>
    <small className="block break-all text-fg-subtle">{modified!==undefined ? label(modified?'replacement':'clear') : info ? info.sha256+' · '+info.expires : k==='key' && v?.has_key ? label('configured'):'—'}</small>
    {(modified || info || (k==='key' && v?.has_key)) && <Button type="button" size="sm" onClick={()=>setDraft(d=>d && {...d,files:{...d.files,[k]:''}})}>{label('clear')}</Button>}</div>
  }
  const st=status.isError ? undefined : status.data
  const stats=st?.stats
  const grid='grid gap-3 sm:grid-cols-2 lg:grid-cols-3'
  return <Card><CardBody className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3 [&_button]:min-h-11 sm:[&_button]:min-h-9"><h2 className="text-base font-semibold text-fg-strong">{label('title')}</h2>
      {v && !draft && <div className="flex flex-wrap gap-2"><Button onClick={()=>begin(v)}>{label(v.configured?'edit':'configure')}</Button>
      {v.configured && <Button disabled={busy} onClick={()=>setConfirm({action:'remove',revision:v.revision,target:describeTarget(v.config),discard:false})}>{label('remove')}</Button>}</div>}</div>
    {query.isError && <p role="alert">{query.error.message} <Button onClick={()=>void query.refetch()}>{label('reload')}</Button></p>}
    {query.isPending && <p role="status">{label('loading')}</p>}
    {status.isError && <p role="alert">{label('unknown')} · {status.error.message} <Button onClick={()=>void status.refetch()}>{label('reload')}</Button></p>}
    {st && v && <div className="space-y-2 text-sm">
      <p>{label(st.enabled?(stats?.error?'retrying':'running'):v.configured?'paused':'off')}{st.host && ' · '+st.transport.toUpperCase()+' '+st.host+' · '+st.port}</p>
      <p>{label('versions')} {v.revision} / {st.active_revision} · {label('queue')} {st.queue_count} ({st.queue_bytes} B) · {label('last_write')} {when(st.stats.last_write)}</p>
      <details><summary className="cursor-pointer">{label('status')}</summary><dl className={'mt-2 '+grid}>
        {Object.entries(st.stats).filter(([k])=>k!=='error').map(([k,val])=><div key={k}><dt className="text-fg-subtle">{label(k)}</dt><dd className="break-all">{k==='last_write'||k==='last_failure'?when(val as string|null):val??'—'}</dd></div>)}
        <div><dt>{label('oldest')}</dt><dd>{when(st.oldest)}</dd></div><div><dt>{label('since')}</dt><dd>{when(st.since)}</dd></div>
      </dl></details>{st.stats.error && <p role="alert">{st.stats.error}</p>}
    </div>}
    {draft && c && <form ref={form} onSubmit={e=>{e.preventDefault();void run('save')}}>
    <fieldset disabled={busy} className="space-y-4">
      <Switch label={label('enabled')} checked={c.enabled} onCheckedChange={enabled=>change({enabled})}/>
      {txt('name',c.enabled)}
      <div className={grid}><Select label={label('transport')} value={c.transport} onChange={e=>{
        const transport=e.target.value
        change({transport,...(autoPort?{port:transport==='tls'?6514:514}:{}),...(transport==='tls'?{format:'5424',framing:'octet'}:{}),
          max_bytes:transport==='udp' ? (c.max_bytes===8192?480:Math.min(c.max_bytes,8192)) : (c.max_bytes===480?8192:c.max_bytes)})
      }}>{['tls','tcp','udp'].map(o=><option key={o} value={o}>{o.toUpperCase()}</option>)}</Select>{txt('host',c.enabled)}{num('port',1,65535)}</div>
      <div className="flex flex-wrap gap-4"><Switch label={label('security')} checked={c.security} onCheckedChange={security=>change({security})}/><Switch label={label('access')} checked={c.access} onCheckedChange={access=>change({access})}/></div>
      <Select label={label('scope')} value={c.sites===null?'all':'selected'} onChange={e=>change({sites:e.target.value==='all'?null:[]})}><option value="all">{label('all')}</option><option value="selected">{label('selected')}</option></Select>
      {c.sites!==null && <div className="space-y-2"><Input type="search" label={label('search')} value={siteSearch} onChange={e=>{setSiteSearch(e.target.value);setPage(1)}}/>
        <SelectedSites ids={c.sites} onRemove={id=>change({sites:c.sites!.filter(site=>site!==id)})}/>
        {sites.error && <p role="alert">{sites.error.message}</p>}
        {sites.data?.items.map(site=><label key={site.id} className="flex min-h-9 items-center gap-2"><input type="checkbox" checked={c.sites!.includes(site.id)} onChange={e=>change({sites:e.target.checked?[...c.sites!,site.id]:c.sites!.filter(id=>id!==site.id)})}/>{formatSiteAddress(site)}</label>)}
        {(page>1 || (sites.data?.total??0)>20) && <div className="flex items-center gap-2"><Button type="button" size="sm" disabled={page===1} onClick={()=>setPage(page-1)}>{t('pagination.previous')}</Button><span>{page}</span><Button type="button" size="sm" disabled={page*20>=(sites.data?.total??0)} onClick={()=>setPage(page+1)}>{t('pagination.next')}</Button></div>}</div>}
      {c.transport==='tls' && <fieldset className="space-y-3 rounded-lg border border-line p-3"><legend>TLS</legend><div className={grid}>{txt('server_name')}{select('trust',['system','custom'],true)}</div>
        {c.trust==='custom' && pem('ca',v?.ca_info)}<Switch label={label('mtls')} checked={c.mtls} onCheckedChange={mtls=>change({mtls})}/>
        {c.mtls && <div className={grid}>{pem('cert',v?.cert_info)}{pem('key')}</div>}</fieldset>}
      <details><summary className="cursor-pointer">{label('advanced')}</summary><div className={'mt-3 '+grid}>
        {select('format',c.transport==='tls'?['5424']:['5424','3164'])}{select('body',['json','kv'])}{c.transport==='tcp' && select('framing',['octet','lf'])}
        <Select label="Facility" value={c.facility} onChange={e=>change({facility:Number(e.target.value)})}>{facilities.map((f,i)=><option key={f} value={i}>{f} ({i})</option>)}</Select>
        {(['severity','threshold'] as const).map(k=><Select key={k} label={label(k)} value={c[k]??''} onChange={e=>change({[k]:e.target.value===''?null:Number(e.target.value)})}>
          {k==='severity' && <option value="">{label('auto')}</option>}{levels.map((l,i)=><option key={l} value={i}>{l} ({i})</option>)}</Select>)}
        {select('ip_mode',['omit','mask','full'],true)}{txt('hostname')}{txt('app',true)}{num('max_bytes',480,c.transport==='udp'?8192:65536)}
        {num('connect_seconds',1,60)}{num('write_seconds',1,60)}{num('retry_min',1,30)}{num('retry_max',c.retry_min,300)}{num('retention_hours',1,168)}{num('queue_mib',1,512)}
      </div></details>
      <div className="flex flex-wrap gap-2 [&_button]:min-h-11 sm:[&_button]:min-h-9"><Button type="submit" variant="primary" disabled={busy}>{label('save')}</Button><Button type="button" onClick={()=>void run('test')}>{label('test')}</Button><Button type="button" onClick={()=>{setDraft(null);setError('');setMessage('');setConflict(false)}}>{t('common.cancel')}</Button></div>
    </fieldset></form>}
    {error && <p role="alert">{error}</p>}{conflict && <Button onClick={async()=>{
      const r=await query.refetch()
      if(!r.isSuccess)return
      if(draft)begin(r.data)
      else{setConflict(false);setError('')}
    }}>{label('reload')}</Button>}
    {message && <p role="status" className="break-all text-sm">{message}</p>}
    <ConfirmDialog open={confirm!==null} title={label(confirm?.discard?'discard':'remove')} description={confirm && <span className="break-all">{confirm.target}
      {confirm.discard && ' · '+label('discardHelp')+' '+(st?.queue_count??'—')}</span>} onClose={()=>setConfirm(null)} onConfirm={()=>{
      if(confirm)void run(confirm.action,confirm)
    }}/>
  </CardBody></Card>
}
