# PingWAF 部署指南（中文摘要）

> 本文是英文 [`docs/deployment.md`](../deployment.md) 的**中文摘要**，覆盖部署形态、端口、关键环境变量、TLS、备份与升级回滚。完整参数、逐项说明与故障排查以英文原文为准（[deployment.md](../deployment.md)）。

## 1. 部署形态

| 形态 | 说明 |
| --- | --- |
| `all-in-one`（默认） | 单进程同时跑控制面 + 数据面 + 内嵌 agent，配合 PostgreSQL。适合单机/演示。 |
| `server` + `agent`（分布式） | 控制面集中管理，多个边缘 agent 各自承载站点流量；agent 只持有本站点配置与 agent token。 |

## 2. 端口与防火墙

| 端口 | 协议 | 用途 | 是否必需 |
| --- | --- | --- | --- |
| 80 | TCP | HTTP 业务 / ACME HTTP-01 | 代理站点需要 |
| 443 | TCP | HTTPS 业务 | 代理站点需要 |
| 9080 | TCP | 控制台 + REST API（HTTPS，自签证书） | 是 |
| 9090 | TCP | gRPC 控制面（agent 与 tunnel 连接器） | 分布式模式需要 |
| 9443 | TCP | 隧道监听（`agent.tunnel_addr`） | 仅作为隧道入口的边缘节点需要 |
| 5432 | TCP | PostgreSQL | 仅内网 |

- **9080 是管理面，不要直接暴露公网**：绑定 `127.0.0.1` 或私网，经 VPN/SSH 隧道或反代访问；
- **9090 只允许 agent 主机访问**；
- 5432 保持内网/Compose 内部网络。

**隧道（Tunnel）端口**：`9443` 默认**关闭**，只有显式配置了
`agent.tunnel_addr`（或 `--tunnel-addr 0.0.0.0:9443`）的边缘节点才接受连接器
会话。该端口需要对连接器所在网络可达——这正是隧道的意义所在；连接器自身只需
**出站** 9090（控制面）与 9443（入口边缘），不需要任何入站端口。接入步骤见
[用户指南](user-guide.md#tunnel内网服务免入站端口接入) 与
[英文部署文档](../deployment.md#firewall--port-requirements)。

## 3. Docker Compose

```bash
# 在存放 docker-compose.yml 的目录执行
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
PINGWAF_SECRET_KEY=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -hex 16)
ALLOW_REGISTRATION=false
EOF
chmod 600 .env          # .env 含密钥，权限 600 且不要提交到版本库
docker compose up -d
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9080/healthz   # 期望 200
```

## 4. 安装器加固（install.sh / compose installer）

两个官方安装器都已按安全默认值加固：

- **控制台对外开放、gRPC 只监听环回**：二进制安装器把控制台绑在 `0.0.0.0:9080`（装完即可从浏览器访问，避免"装完打不开"），
  gRPC 仍是 `127.0.0.1:9090`；compose 通过 `PINGWAF_ADMIN_BIND` 默认发布在 `0.0.0.0`、`PINGWAF_GRPC_BIND` 默认在 `127.0.0.1`。
  管理员口令由安装器随机生成，且全新数据库在改密前拒绝一切写操作；仍建议用防火墙把 9080 限制在管理网，或用 TLS 反向代理暴露。
  `--listen-public` 只用于远程 agent 场景开放 9090。
- **校验 release 校验和**：每个发布资产都有 `.sha256`；缺失、格式错误或不匹配时安装器直接退出，不会安装被篡改/截断的包。
- **Agent 模式下载专用构建**：`--mode agent` 优先下载 `pingwaf-agent-<os>-<arch>.tar.xz`
  （仅数据面，不含 PostgreSQL / REST API / 控制台），并以 `/usr/local/bin/pingwaf`
  名称安装，单元与升级路径不变；更早的 release 没有该资产时回退到完整二进制并告警。
- **随机管理员口令**：未提供 `--admin-password`/`PINGWAF_ADMIN_PASSWORD` 时生成随机口令并**只打印一次**（结束前保存好）；不再有内置默认口令。
- **生成 `PINGWAF_SECRET_KEY`**：二进制安装器写入 `/etc/pingwaf/pingwaf.env`（`0600`，属主 `pingwaf`，systemd 通过
  `EnvironmentFile=-/etc/pingwaf/pingwaf.env` 读取）；compose 安装器写入 `.env`（`0600`）。升级时保留已有主密钥——静默轮换会使已密封的渠道/AI/备份凭据无法解密。
- **mimalloc arena**：生成的 systemd 单元会根据内存上限（cgroup v2/v1 限制，否则 `MemTotal`）写入
  `MIMALLOC_ARENA_RESERVE` 与 `MIMALLOC_ARENA_EAGER_COMMIT`：小于 1 GiB 用 64 MiB，小于 4 GiB 用 256 MiB，
  不超过 16 GiB 用 512 MiB，否则 1 GiB；仅 4 GiB 及以上开启 eager commit。原因是 mimalloc 在
  `allocator_tune::apply()` 之前就创建了第一个 arena，已存在的 arena 无法缩小。主机内存布局特殊时可用
  `systemctl edit pingwaf` 覆盖。
- **已有配置优先**：如果 `/etc/pingwaf/pingwaf.toml` 已存在，安装器不会改写它，`--server-url` / `--api-key`
  不会生效；agent 模式以文件为准。以启动日志里的 `server_url=...` 为准，需要变更时编辑 `[agent]` 后重启。
- **Agent 未绑定站点**：当前 agent 会收到 API key 属主的**全部站点**，而不是单个站点；控制面自身的控制台站点
  （通常上游为 `127.0.0.1:9080`）也会被下发，在边缘节点上该回环地址没有控制台，站点会 502。尚无按节点绑定站点的
  API，部署边缘时应使用专用控制面，或删除边缘不应运行的站点。
- **控制面版本要求**：如果控制面是 ACME 签发者（常见 all-in-one），需 **0.32.40+** 才会把内嵌数据面签发的 PEM
  同步到 `site_certificates` 并推送给 agent。旧控制面只下发 `acme_email`、没有 PEM，每个 agent 会自己发起
  HTTP-01；验证请求落到 80 端口所属实例（通常是控制面）而不是 agent，最终 `acme_failed`。暂不能升级控制面时，
  可在 agent 单元设置 `PINGAP_DISABLE_ACME=true` 停止重试，并改用上传证书。
- **CA 持久化**：安装器会把 `--server-ca-cert` 复制到 `/etc/pingwaf/grpc-ca.pem`，配置和单元引用该持久路径；
  源文件可以放在临时目录。控制台生成的安装命令不含 CA / `--server-tls-name`，自签控制面需要手动补上。
- **重启与注册校验**：安装器会重启已运行的 agent 单元（`enable --now` 不会重启），并在 60 秒内等待
  `Registered with control plane`；未注册会以非零退出，而不是只打印 “installed successfully”。
- **手动 tarball 安装（all-in-one）**：归档内的 `pingwaf.service` / `pingwaf.toml` 在
  `pingwaf-linux-<arch>/` 子目录；unit 需要 `WorkingDirectory=/var/lib/pingwaf`（仓库已加），否则相对
  `cache_dir = "./data/cache"` 会落到 `/data/cache`，被 `ProtectSystem=strict` 拒绝并导致缓存/ACME 状态无法持久化。
  非默认数据库使用 `PINGWAF_DB_URL`（**不是** `PINGWAF_DATABASE_URL`）；首次启动前设置 `PINGWAF_SECRET_KEY`
  和管理员口令；小于 4 GiB 的主机需固定 `MIMALLOC_ARENA_RESERVE`。从 agent 切换为 all-in-one 前，先移走旧的
  `/var/lib/pingwaf/cache`，否则会加载另一个控制面的站点/证书快照。
- **443 的 `wrong version number`**：这是客户端用明文 HTTP 访问 TLS 端口（扫描器/误配客户端），不是 agent
  连控制面的错误；公网边缘会持续出现，建议在日志采集侧过滤或限速，而不是关闭该监听目标的错误日志。
- **不删数据卷**：compose 安装器 `--force` 只重写 `.env`，保留 `postgres-data`/`pingwaf-data`/`pingwaf-certs`；
  清理主机磁盘只能显式运行 `scripts/sweep-host-storage.sh --prune-volumes`，且它**永不删除 `waf_*`** 数据卷。
- **旧 tag 提示**：安装器从 release tag 下载 compose 文件；若该 tag 的 compose 还没有上述加固（没有 `PINGWAF_SECRET_KEY` 透传、9080/9090 公网绑定、默认管理员口令），安装器会告警——请升级到包含这些改动的版本，而不要假定加固已生效。

## 5. 关键环境变量

> **挑战页模板**：在 **设置 → 自定义页面 → 挑战页**（`scope=challenge`，固定 503）编辑。模板是全局
> Tera 模板，只控制展示；编译进二进制的挑战 JS 通过 `{{ challenge_scripts | safe }}` 注入，必须保留
> `countdown`、`title`、`subtitle`、`status`、`spinnerWrap`、`progressBar`、`progressFill` 这些 DOM id，
> 且不能包含 `<script>`。模板渲染失败、缺少 `| safe`、缺少 DOM id 或包含脚本标签时回退内置页面。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PINGWAF_ADMIN_BIND` / `PINGWAF_GRPC_BIND` | `0.0.0.0` / `127.0.0.1` | 控制台（9080）/gRPC（9090）发布地址。控制台默认发布到所有网卡，装完即可访问；请改为指定管理网地址，或用防火墙/反向代理限制，并在首次登录时改管理员口令。gRPC 默认仅环回，远程 agent 才需放开 |
| `ADMIN_PASSWORD` | **无默认值（新库必填）** | 初始管理员口令；为空会让首次启动失败，而不是播种已知口令。安装器会生成随机口令并只打印一次；首次登录强制改密 |
| `POSTGRES_PASSWORD` | `pingwaf`（开发回退） | PostgreSQL 口令；正式部署务必在 `.env` 设置随机值（compose 仍会回退到 `pingwaf`，安装器不生成该项） |
| `PINGWAF_SECRET_KEY` | 未设置（密封功能必需） | 静态加密主密钥：加密通知渠道口令、AI Provider Key、备份目标凭据。**必须设为 32 字节随机值**；不设置则这些字段明文入库。安装器会生成（compose → `.env`；二进制 → `/etc/pingwaf/pingwaf.env` 0600）。无在线轮换，备份与轮换步骤见 [SECURITY.md](../../SECURITY.md#credentials-and-secrets) |
| `PINGWAF_JWT_SECRET` | `change-me-in-production` | JWT 签名密钥，至少 16 字符（建议 `openssl rand -hex 32`）；占位符会在首启时替换为随机持久化值 |
| `PINGWAF_ALLOW_REGISTRATION` | 代码默认 `true`（Compose 设为 `false`） | 是否允许自助注册；生产务必设为 `false` |

旧版 Agent 协议仅下发默认入口的站点。TCP 绑定上报不表示节点获得自定义入口的转发授权。
Linux 节点配置有效监听后消费受管全量快照，按会话和租约转发。迁移 000107 开放自定义入口写入。库中有自定义站点时降级会被拒绝；回到旧版须恢复事先验证的升级前备份。
| `PINGWAF_CORS_ORIGINS` | 空（仅同源） | 允许的跨域来源；为空时**不下发 CORS 头**，只有同源调用可用 |
| `PINGWAF_TLS_ENABLED` | `true` | 控制台/API 使用 HTTPS（自签证书，可上传正式证书）；反代终止 TLS 时可设 `false` |
| `PINGWAF_PASSKEY_ENABLED` | `true` | 启用 Passkey 登录。Passkey 需要安全上下文：HTTPS 主机名或 `localhost`；反代后需设 `PINGWAF_PASSKEY_ORIGIN` |

其余变量（连接池、心跳、日志级别、Elasticsearch、限流等）见英文 [deployment.md → Configuration Reference](../deployment.md#configuration-reference)。

## 6. TLS

- **控制面 9080**：首启自动生成自签名证书；生产建议在 **Settings → Control plane HTTPS** 上传正式证书，并用 `PINGWAF_TLS_SANS` 指定主机名。
- **业务站点**：使用 ACME（Let's Encrypt）或上传证书，启用 HSTS 并强制 HTTPS。all-in-one 模式下由内嵌数据面签发，
  控制面每 30 秒把 `acme_state.toml` 中签发的 PEM 同步到 `site_certificates` 并下发给所有 agent；这样 80 端口
  指向控制面的 edge agent 不必自己发起（也必然失败的）HTTP-01 订单。路径可用 `PINGWAF_ACME_STATE` 覆盖。
  远程 agent 若不是该域名 80 端口的落点，应改用 **DNS-01**。
- **gRPC 9090**：默认 TLS（首启生成自签 CA）；仅在完全受控的环回 all-in-one 场景才考虑 `grpc_tls_mode = "off"`。

## 7. 安全加固清单

逐项清单见 [SECURITY.md 加固清单](../../SECURITY.md#hardening-checklist)，要点：

1. 修改默认管理员口令（首登强制改密）；
2. 设置 `PINGWAF_JWT_SECRET` 与 `PINGWAF_SECRET_KEY`，备份主密钥；
3. 关闭自助注册，修改 PostgreSQL 默认口令；
4. 9080/9090 不暴露公网，启用主机防火墙；
5. 站点启用 TLS + HSTS；
6. **日志即凭据存储**：访问日志原样保存 `Authorization`/`Cookie`/`Set-Cookie` 与最多 8 KiB body，默认保留 180 天；限制数据库/Elasticsearch 访问并加密其备份；
7. MCP `write` key 等同管理员凭据；AI 助手会把站点/日志/WAF 事件发送给第三方 provider，按需启用。

## 8. 备份与恢复

部署配置快照使用 schema 4，包含隧道设置和连接器。恢复缺少这两张表的旧快照时保留现有隧道配置。节点绑定地址及各站点的地址覆盖自 schema 3 起纳入快照。恢复 schema 2 时沿用目标节点的地址策略。恢复后在节点页面核对站点分派和实际监听回执。

选择 DNS-01 后，手动 DNS 任务提供需要管理员发布的 TXT 记录；服务商无法识别时，节点记录原因并跳过该订单。

> 数据库是密钥库：`site_certificates` 含私钥、`site_basic_auth` 含明文口令、`site_oidc` 含 cookie secret。备份必须加密并限制读取。

```bash
# 备份
pg_dump -U pingwaf -d pingwaf -F c -f pingwaf_backup_$(date +%Y%m%d).dump
# 恢复
pg_restore -U pingwaf -d pingwaf --clean pingwaf_backup_20260101.dump
```

配置侧还应备份 `/etc/pingwaf/`、证书目录与 `.env`（权限 600）。注意：`PINGWAF_SECRET_KEY` 丢失时已密封的渠道/AI/备份凭据无法解密，需重新录入。

## 9. 升级与回滚

```bash
cd /path/to/compose
# 1) 升级前快照：数据库 + .env + compose
docker compose exec -T postgres pg_dump -U pingwaf -d pingwaf -Fc > pre-upgrade.dump
cp .env pre-upgrade.env && chmod 600 pre-upgrade.env
# 2) 固定新版本（修改 .env 中的 PINGWAF_TAG），只重建应用容器
docker compose pull pingwaf && docker compose up -d pingwaf
# 3) 验证
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost:9080/healthz
```

**回滚**：把 `PINGWAF_TAG` 改回旧版本并 `docker compose up -d pingwaf`。数据库迁移**只向前**——若旧版本拒绝启动，需用 `pre-upgrade.dump` 恢复数据库后再启动旧版本。生产环境请固定版本 tag，不要使用 `:latest`。

> **控制台监听地址**：新装默认把控制台绑在 `0.0.0.0:9080`。升级不会改写已有配置，因此本次改动之前装的实例仍保留 `admin_addr = "127.0.0.1:9080"`（compose 沿用 `.env` 里的旧值），只能从本机访问。想改成新默认值就显式设置 `admin_addr = "0.0.0.0:9080"`（或 `.env` 里 `PINGWAF_ADMIN_BIND=0.0.0.0`），并用防火墙/反向代理限制该端口。

> 安装器升级会保留密钥与数据卷：compose 安装器 `--force` 复用已有管理员口令与 `PINGWAF_SECRET_KEY`，二进制安装器保留
> `/etc/pingwaf/pingwaf.env`；两者都不会删除 `postgres-data`/`pingwaf-data`/`pingwaf-certs`。需要清理主机磁盘时只能显式运行
> `scripts/sweep-host-storage.sh --prune-volumes`（只清理未使用的**非 PingWAF** 卷，`waf_*` 永不删除）。
> 从**旧 release tag** 下载的 compose 文件不含本轮加固（环回绑定、`PINGWAF_SECRET_KEY` 透传、无默认管理员口令），
> 安装器会告警——请升级到包含这些改动的版本。

## 10. 管理员自救（break-glass）

维护 CLI 直连数据库执行，运行中的控制面会在数秒内感知：

```bash
pingwaf user reset-password --email admin@pingwaf.local   # 重置口令并撤销全部会话
pingwaf security allowlist off                            # 关闭控制面 IP 白名单（应急）
pingwaf mode observe|enforce|status                       # 观察模式开关
pingwaf config rollback --scope global                    # 回滚配置版本
```

详见英文 [deployment.md → Maintenance CLI](../deployment.md#maintenance-cli-break-glass)。

管理控制台默认监听 `0.0.0.0:9080`，运维可配置管理端口。默认 HTTP/HTTPS 站点监听 IPv4 全部接口。自定义入口 `http@81` 表示 `0.0.0.0:81`，仍可指定 IPv4 或 IPv6 地址。站点创建、复制、编辑与恢复时均保留控制台实际使用的端口，暂停站点同样受限。
