/** Compare Linux path components, as the node and control plane do before checking the filesystem. */
export function directoryPathError(path: string, root: string, allowRoot: boolean): string | undefined {
  if (path.includes(String.fromCharCode(0))) return '目录不能包含空字符。'
  if (!path.startsWith('/')) return '请输入以 / 开头的绝对路径。'
  const parts = (value: string) => value.split('/').filter(part => part && part !== '.')
  const candidate = parts(path)
  if (candidate.includes('..')) return '目录不能包含上级路径（..）。'
  const parent = parts(root)
  if (!root.startsWith('/') || parent.some((part, i) => part !== candidate[i]) ||
      (!allowRoot && candidate.length === parent.length)) {
    return allowRoot ? '请选择 ' + root + ' 或其子目录。' : '请选择 ' + root + ' 下的子目录。'
  }
}
