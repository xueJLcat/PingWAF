import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { Dialog } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { useNow } from '@/hooks'

interface Inventory {
  revision: string
  paths: Record<string,string>
  public_root: string
  sites: Record<string,string[]>
  last_command: string
  last_error: string
}
type Edit = { id: string; path: string; revision: string; action: 'add'|'edit'|'remove' }

export function StaticRootsDialog({node, name, close}: {node: string; name?: string; close: () => void}) {
  const endpoint = '/agents/' + encodeURIComponent(node) + '/static-roots'
  const [edit,setEdit] = useState<Edit>()
  const [pending,setPending] = useState<{id:string; deadline:number}>()
  const query = useQuery({queryKey:['agent-static-roots',node], queryFn:()=>apiClient.get<Inventory>(endpoint),
    retry:false, refetchInterval: q => pending && q.state.data?.last_command !== pending.id && Date.now() < pending.deadline ? 2000 : false})
  const data = query.data
  const now = useNow(2000)
  const waiting = !!pending && data?.last_command !== pending.id && now < pending.deadline
  const write = useMutation({mutationFn:(value:Edit)=>apiClient.put<{command_id:string}>(endpoint,
    {identifier:value.id, path:value.action==='remove'?null:value.path, revision:value.revision}),
    onSuccess:r=>{ setPending({id:r.command_id,deadline:Date.now()+90000});setEdit(undefined);void query.refetch() }})
  function start(action: Edit['action'], id='') {
    if (!data) return
    write.reset();setPending(undefined)
    setEdit({action,id,path:data.paths[id]??'',revision:data.revision})
  }
  const valid = edit && /^[a-zA-Z0-9_-]{1,64}$/.test(edit.id) &&
    (edit.action==='remove' || edit.path.startsWith('/')) &&
    (edit.action!=='add' || !Object.hasOwn(data?.paths??{},edit.id))
  return <Dialog open onClose={write.isPending ? () => undefined : close} size="lg" className="[overflow-wrap:anywhere]" title="静态目录" description={name??node}>
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button onClick={()=>void query.refetch()} loading={query.isFetching}>刷新节点清单</Button>
        <Button variant="primary" disabled={!data?.revision || waiting || !!edit} onClick={()=>start('add')}>登记目录</Button>
      </div>
      {query.error && <p role="alert">{query.error.message}</p>}
      {data && !data.revision && <p role="alert">{data.last_error || '节点尚未返回可用清单'}</p>}
      {data && <><p className="text-sm text-fg-subtle">可登记的父目录 <code className="break-all">{data.public_root}</code></p>
        {Object.keys(data.paths).length===0 && <p>暂无目录。登记后可在静态站点的目录列表中选择。</p>}
        <ul className="divide-y divide-border">{Object.entries(data.paths).sort(([a],[b])=>a.localeCompare(b)).map(([id,path])=>
          <li key={id} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <div className="min-w-0"><strong>{id}</strong><p className="break-all font-mono text-sm">{path}</p>
              {data.sites[id]?.length>0 && <p className="text-xs text-fg-subtle">使用站点 · {data.sites[id].join('、')}</p>}</div>
            <div className="flex gap-1">{(['edit','remove'] as const).map(action=><Button key={action}
              disabled={waiting || !!edit || !!data.sites[id]?.length} onClick={()=>start(action,id)}>{action==='edit'?'改路径':'移除'}</Button>)}</div>
          </li>)}</ul></>}
      {edit && <form className="space-y-3 rounded-lg border border-line p-3" onSubmit={e=>{e.preventDefault();if(valid && !write.isPending)write.mutate(edit)}}>
        <Input label="目录标识" hint="使用 1–64 个英文字母、数字、下划线或短横线。" value={edit.id} required disabled={edit.action!=='add' || write.isPending}
          error={edit.action==='add' && Object.hasOwn(data?.paths??{},edit.id) ? '此标识已登记。' : undefined} onChange={e=>setEdit({...edit,id:e.target.value})}/>
        {edit.action!=='remove' && <Input label="节点绝对路径" disabled={write.isPending} value={edit.path} required placeholder={data?.public_root+'/public'}
          onChange={e=>setEdit({...edit,path:e.target.value})}/>}
        {edit.action==='remove' && <p>移除登记后，新增站点将无法选择该目录。源文件会保留。</p>}
        <div className="flex gap-2"><Button type="submit" variant={edit.action==='remove'?'danger':'primary'} loading={write.isPending} disabled={!valid}>{edit.action==='remove'?'确认移除':'保存到节点'}</Button>
          <Button type="button" disabled={write.isPending} onClick={()=>setEdit(undefined)}>取消</Button></div>
      </form>}
      {write.error && <p role="alert">{write.error.message}</p>}
      {pending && <p role="status">{waiting?'已发送，等待节点校验并回报。':data?.last_command===pending.id?
        (data.last_error || '节点已应用目录变更。'):'尚未收到此次变更的回执，请刷新核对当前清单。'}</p>}
    </div>
  </Dialog>
}
