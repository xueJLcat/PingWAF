---
title: API
description: REST 分组、认证、gRPC 控制面契约、API Key 与自动化入口。
minutes: 7
---

同一主域名的自定义入口站点用 UUID 区分。站点写接口成对接收 `ingress_port` 和 `ingress_protocol`，启用时检查分派节点的当前受管会话和监听回报。迁移 000107 完成后开放自定义入口写入。

## REST

所有端点都在控制面地址的 `/api/v1` 下：`https://<host>:9080/api/v1`。认证使用 Bearer access token：

```bash
TOKEN=$(curl -s -X POST https://localhost:9080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@pingwaf.local","password":"..."}' | jq -r .access_token)

curl -s https://localhost:9080/api/v1/sites -H "Authorization: Bearer $TOKEN"
```

登录返回 `access_token`、`refresh_token`、`token_type: Bearer`、`expires_in`（43200 秒）与 `role`。只有 `/auth/login`、`/auth/register`、`/auth/status`、两步 Passkey 流程、`/health` 与 `/version` 无需认证；`/system/*` 还要求管理员身份。

## 端点分组

| 分组 | 代表端点 |
| --- | --- |
| 认证 | `POST /auth/login`、`POST /auth/refresh`、`GET|PUT /auth/me`、`PUT /auth/password` |
| 站点 | `GET|POST /sites`、`GET|PUT|DELETE /sites/{id}`、`POST /sites/{id}/clone` |
| 规则 | `GET|POST /sites/{id}/rules`、`GET|PUT|DELETE /sites/{id}/rules/{rule_id}`、`POST /sites/{id}/waf/defaults` |
| WAF | `GET|PUT /sites/{id}/waf/settings`、`GET /sites/{id}/waf/posture`、`GET /managed-rules` |
| 日志 | `GET /logs/security`、`GET /logs/access`、`GET /logs/access/{id}`、`DELETE /logs/purge` |
| Agent | `GET /agents`、`POST /agents/enroll`、`PUT /agents/{id}/sites`、`POST /agents/{id}/commands` |
| 配置版本 | `GET /config-versions`、`GET /config-versions/{id}`、`POST /config-versions/{id}/rollback`、`POST /config-versions/prune` |
| 系统 | `GET /system/metrics`、`/system/profile`、`/system/nodes`、`/system/status` |

站点级接口通过租户边界（`load_site_read` / `load_site_write`）读写，token 只能看到自己有权管理的站点。包含全部查询参数与响应结构的完整参考见仓库中的 `docs/api.md`。

## 证书共享

站点的共享证书和可选证书列表不会返回签发方的 DNS 凭据。选择共享证书后可用其 PEM 提供 TLS，续期由签发方负责。自定义入口不支持 HTTP-01；HSTS 与域名重叠的自定义 HTTP 入口互斥，自定义 HTTP 站点也不能强制跳转到 HTTPS。

一张证书（例如泛域名证书）可以服务多个站点。站点能看到自己拥有的证书以及共享给它的证书——每项带 `relation` 字段（`owner`、`linked` 或 `available`）。证书的归属站点仍然负责续期与 ACME 记账。

| 端点 | 用途 |
| --- | --- |
| `GET /sites/{id}/certificate-links` | 共享给本站的证书（与证书列表同构） |
| `POST /sites/{id}/certificate-links` | 关联证书：`{ "certificate_id": "uuid" }` → `201`；本站已拥有或已关联 → `409`；无权读取归属站点 → `404` |
| `DELETE /sites/{id}/certificate-links/{cert_id}` | 解除关联 → `204`；该证书是本站当前 TLS 证书 → `409` |
| `GET /sites/{id}/certificates/available` | 本站还可关联的证书 |

`PUT /sites/{id}/ssl-settings` 接受本站拥有或已关联的 `certificate_id`（否则 `400 does not belong to this site and is not linked to it`），以及用于解绑的 `clear_certificate: true`。选中证书后会清空 `site_ssl` 上的旧内联 PEM 副本——边缘始终以下发的选中证书为准。

## 路径例外

运营者可以把若干请求路径加白，使其跳过选定的防护层（`waf`、`bot`、`access`、`basic_auth`、`mtls`、`ai_bot`、`rate_limit`、`challenge`，或 `*` 表示全部）。路径例外在所有 WAF 模式（观察与拦截）下都可保存并生效。暂停站点、fail-closed 边缘与动态 IP 封禁不可绕过。`log_hits: true` 时每次命中都会写入 `path_bypass` 安全事件。`challenge` 放行所有质询来源（WAF 规则/评分、CC 与限速的挑战动作、Bot 防护、IP/地区规则、独立质询插件），拦截仍生效。

| 端点 | 用途 |
| --- | --- |
| `GET /sites/{id}/path-exceptions` | 列出例外（每站最多 64 条，`path` 唯一） |
| `POST /sites/{id}/path-exceptions` | 创建：`path`（以 `/` 开头，≤512；`regex` 时为正则表达式）、`match_type`（`prefix`/`exact`/`wildcard`/`regex`，其中 regex 为未锚定、区分大小写的 Rust 正则）、`skip_layers`、`note`、`log_hits`、`enabled` |
| `GET|PUT|DELETE /sites/{id}/path-exceptions/{id}` | 读取 / 部分更新 / 删除（`204`） |

## 自定义页面作用域

自定义页面（`GET|POST /error-pages`，管理员；API 路径沿用历史名称）带有 `scope` 作用域：

- **`site`**（默认）—— 替换已匹配站点的错误响应；状态码 400–599；模板可用完整上下文（`request_id`、`error_code`、`site_name`、`client_ip` 等）。
- **`unmatched_host`** —— 边缘对 `Host` 不匹配任何已配置站点请求的兜底（裸 IP + 端口、未知主机名）。仅接受 404、421、503；同 `(scope, status_code)` 重复返回 `409`。只有存在至少一条启用的该作用域页面时边缘才会生成兜底 Location——否则网关保持默认 404——且它永远不会覆盖已匹配站点自身的 Location。模板只能使用 `{{ host }}`（已 HTML 转义）与 `{{ request_id }}`；响应带 `Cache-Control: no-store`。
- **`challenge`** —— JS / managed / interactive 挑战页；固定 503、`text/html`。仅展示层：编译好的挑战 JS 通过 `{{ challenge_scripts | safe }}` 注入；模板必须保留 `countdown`、`title`、`subtitle`、`status`、`spinnerWrap`、`progressBar`、`progressFill` 这些 id，且不能包含 `<script>`。该作用域与站点、未匹配 Host 的 503 错误页相互独立，修改它不会影响那些页面。

## 站点复制与凭据

复制站点以暂停状态创建，并保留源站的转发头信任设置。默认入口之间复制时，克隆持有独立的自有证书副本；任一端为自定义入口时，需单独配置服务端证书和 mTLS 凭据。证书共享授权不会转移。Basic Auth 凭据和访客授权仍随站点复制；复制后的 OIDC 配置初始禁用，启用前需核对回调和身份提供方登记。

## 缓存规则优先级与预设

缓存分两层：显式规则（`cache-rules` 端点，按表达式匹配）与 `cache-settings` 上的五个按扩展名分类的预设（`web_assets`、`image`、`media`、`other`、`html`）。显式规则**先**匹配、预设兜底（first-match-wins）；预设只按扩展名匹配，API 端点与无扩展名路径仍需显式规则。只有预设的站点也能正常缓存；REST API 不变（仍是 `cache-rules` + `cache-settings`），控制台的合并列表只是展示层。控制台的「转为规则」会把预设转成 `http.request.uri.path matches "(?i)\.(?:ext|…)$"` 形式的显式规则（沿用预设的扩展名与 TTL）并禁用原预设。

## 日志实时同步

`POST /agents/flush-logs`（管理员）要求所有在线 agent 立即上报内存中的日志缓冲，而不是等待批次间隔。返回 `{ "delivered": N, "offline": M }`；离线 agent 只计数、不入队，且 `delivered` 表示命令已下发——不等于日志已入库。

## gRPC

Agent 使用 `9090` 上的 `ControlPlane` 服务，定义在 `pingwaf-proto/proto/control_plane.proto`。它承载 `RegisterAgent`、`Heartbeat`、`SyncRules`、`ShipLogs`、`ShipCertEvents`、`ShipMetrics`、`GetSiteConfig`，以及挑战流程使用的访客会话 RPC。TLS 为默认；`grpc_tls_mode = "off"` 只应在可信网络内使用。

## API Key

服务账号使用 `pwk_` 前缀的密钥认证，密钥以 128 位熵生成、以 bcrypt 哈希存储，明文只在创建时返回一次；每个密钥带有 `read` 或 `write` 作用域与过期时间。

```bash
curl -s -X POST https://localhost:9080/api/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"ci","scopes":["read"],"expires_in_days":90}'
```

## MCP

控制面在 `POST /mcp` 暴露 Streamable HTTP 的 MCP 端点（根路径，刻意不在 `/api/v1` 下）。它接受 `pwk_…` API Key 或 JWT；写操作还要求密钥拥有者是管理员。`GET` 与 `DELETE` 返回 `405`，请求体上限 256 KiB。这是让助手查看站点、规则与日志而无需交付控制台凭据的推荐方式。

## 通知

Webhook 通知通过 `PINGWAF_WEBHOOK_URL` 配置，通知路由可以从控制台读取当前配置。可以用它把安全事件投递到现有的告警链路。

## 自动化实践

- **配置可复盘** —— 每次变更后用 `GET /config-versions` 生成快照，并在应急脚本中用 `POST /config-versions/{id}/rollback` 回滚。
- **在 CI 中纳管边缘节点** —— `POST /agents/enroll` 返回安装命令，因此流水线本身不需要保存 API Key。
- **日志外送** —— 轮询 `/logs/security` 获取被拦截请求，或开启 Elasticsearch 上报后直接查询。

### 受管静态目录和重定向站点

在控制台左侧「平台 → 静态目录」选择目标节点，可打开与节点页共用的目录登记表单。关闭表单后保留原搜索和页码。在「安全资产 → 页面防护」按域名和监听端口选择站点，可维护公开路径的防篡改规则和动态防护。报告与大屏位于「总览」，按协议、域名和端口选择统计范围。

创建站点时可设置 `site_handler`。已有反向代理使用空值。重定向示例为 `{"kind":"redirect","target":"https://www.example.org","status":302,"preserve_path":true,"preserve_query":true}`。预置目录站点使用 `{"kind":"static","directory_id":"public","digest":"<节点报告的 SHA-256>"}`。两种模式都需要显式配置监听端口，启用时须选择支持该类型的节点。站点管理端口保留规则继续生效。

在节点的 `/etc/pingwaf/static-roots.json` 登记目录，例如 `{"public":"/srv/www/public"}`。目录需要包含 `index.html`。控制台显示目录标识和内容摘要，发布时节点验证并复制到 `/var/lib/pingwaf/site-content`。通过 `PINGWAF_STATIC_ROOTS_FILE` 和 `PINGWAF_SITE_CONTENT_DIR` 可指定其他位置。确保运行服务的账户能读取源目录、写入版本目录。

支持目录管理的节点还可通过「节点 → 静态目录」登记、修改和移除。平台管理员可以查看使用站点及节点校验结果。新增路径位于 `/srv/www` 下，父目录可由运维通过 `PINGWAF_STATIC_PUBLIC_DIR` 指定。移除登记会保留源文件；已引用目录需要先调整站点配置。站点的预置目录下拉框旁有直达入口和刷新按钮。

上传 ZIP 时，控制台先建立仅上传者可访问的草稿，再取得十分钟有效、仅能读取该草稿的预览地址。预览页面使用独立的浏览器沙箱，允许站内样式和图片。发布时将 `static_draft_id` 和 `{"kind":"zip","digest":"<草稿 SHA-256>"}` 提交到站点接口。节点每次最多下载 256 KiB，在私有临时目录完成校验后原子发布。配置生效情况见站点详情。查询 `GET /sites/{id}/static-versions` 获取该站点的版本，使用站点更新接口提交此前的摘要即可回退。数据库全量备份包含发布包；配置快照引用对应摘要。
