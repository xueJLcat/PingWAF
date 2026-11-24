---
title: 部署
description: Docker Compose 与源码构建、端口、配置优先级、systemd 单元以及分布式 Agent 部署。
minutes: 10
---

升级控制面前先备份 PostgreSQL。迁移 `000104` 会检查现有站点的域名与别名；遇到非规范域名或不同站点的域名覆盖时，迁移会回滚。重试前按迁移日志中的站点 UUID 修正配置。此迁移不开放自定义入口端口。

## 部署形态

**All-in-one** 在单个进程内同时运行控制面与一个数据面，适合单机、评估以及只需一个边缘的中小型部署。

**分布式** 运行一个 `pingwaf server` 与任意数量的 `pingwaf agent`。状态由控制面持有，Agent 除规则缓存外无状态，因此新增边缘节点无需触碰数据库。

## 端口

| 端口 | 用途 | 说明 |
| --- | --- | --- |
| `9080` | REST API + 控制台 | 使用自签证书提供 HTTPS，直到你替换它；请保持私有 |
| `9090` | gRPC 控制面 | Agent 在此连接；默认 TLS，`grpc_tls_mode = "off"` 会降级为明文 |
| `80` | 代理流量 | 创建首个站点后开始绑定 |
| `443` | 代理流量 | 证书签发或上传后才开放 |

`GET /healthz` 在 HTTP 与 HTTPS 下都会响应，适合作为 compose 健康检查与负载均衡探针；其余路径一律跳转 HTTPS。

Linux 的 Agent 和 all-in-one 配置有效的 `PINGWAF_INGRESS_LISTENERS` 后使用受管快照，自定义 HTTP/HTTPS 入口仅在已应用快照的租约有效时转发分派站点。默认未设置。

旧版 Agent 协议只下发默认入口站点。TCP 绑定上报不代表节点获准转发自定义入口流量。
控制面仍保留自定义入口建站门禁。

## Docker Compose

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

compose 文件以 all-in-one 模式启动 `ghcr.io/shuaizend/pingwaf:latest`，并与 `postgres:16-alpine` 一起运行，发布 `80`、`443`、`9080` 与 `9090`。数据库端口默认只绑定 `127.0.0.1`。

首次用 compose 时最常见的两类报错：

- `permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock`——当前用户不在 `docker` 组。改用 `sudo docker compose up -d`，或把用户加入 `docker` 组（`sudo usermod -aG docker $USER`，重新登录后生效）。
- `failed to bind host port 127.0.0.1:5432/tcp: address already in use`——本机已有 PostgreSQL 占用 5432。在 `.env` 中设置 `POSTGRES_PORT=55432`（或给 `deploy/compose/install.sh` 传 `--db-port 55432`，它会自动从 55432 起选择空闲端口），再重新启动。

> `hostname` 必须保持稳定。控制面按 hostname 与 API key 匹配重新注册，容器 ID 变化会留下「幽灵离线节点」。

## 源码构建

| 工具 | 版本 | 原因 |
| --- | --- | --- |
| Rust | 1.96+（MSRV） | 构建二进制 |
| Node.js | 26.12.1+ | 构建内嵌控制台，`web/.npmrc` 设置了 `engine-strict=true` |
| `protoc` | 较新版本 | gRPC 代码生成——**必需** |
| `cmake` | 较新版本 | 构建 TLS 后端 |
| PostgreSQL | 14+；本机安装以发行版包名为准（Ubuntu 24.04 是 `postgresql-16`，26.04 是 `postgresql-18`） | 控制面存储，角色需要建表权限 |

缺少 `protoc` 时 `pingwaf-proto` 会静默写入占位文件，随后下游 crate 编译失败——构建前先安装它。

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

在 Linux 上，`install.sh` 会下载预编译包、安装到 `/usr/local/bin`、生成 `/etc/pingwaf/pingwaf.toml` 与 systemd 单元，并启动服务。在终端上不带参数运行它会进入交互引导（部署模式、管理员凭证、PostgreSQL URL、证书 SAN 列表、版本）；通过管道执行则是一行命令的无人值守安装。

```bash
# 交互安装：打印安装计划并确认
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh -o install.sh && bash install.sh

# 一行命令、无人值守（管道执行没有终端，因此不做任何提问）
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | bash -s -- --mode all-in-one
```

Agent 模式下安装器会下载仅数据面的归档（`pingwaf-agent-<os>-<arch>`，不含 PostgreSQL、REST API 与控制台），并以 `/usr/local/bin/pingwaf` 名称安装，单元与命令保持不变。生成的单元还会根据内存上限固定 mimalloc 的第一个 arena（小于 1 GiB 用 64 MiB，小于 4 GiB 用 256 MiB，不超过 16 GiB 用 512 MiB，否则 1 GiB；仅 4 GiB 及以上开启 eager commit），因为 mimalloc 在运行时设置该选项之前就已创建 arena。参数：`--mode all-in-one|server|agent`，`--no-systemd` 跳过单元安装，`--admin-email` / `--admin-password` / `--tls-sans`（或对应的 `PINGWAF_*` 环境变量）免提问写入初始设置，`--dry-run` 只预览安装计划不做改动。

## 配置优先级

配置依次从 TOML 文件、`PINGWAF_*` 环境变量、CLI 参数读取，后者覆盖前者；未知 TOML 键会被报告并跳过。

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml
PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one   # 等价写法
```

`[server]` 表覆盖 `db_url`、`admin_addr`、`tls_enabled`、`tls_sans`、`grpc_addr`、`jwt_secret`、`admin_email` 与 `serve_frontend`；`[agent]` 表覆盖 `server_url`、`server_ca_cert`、`api_key`、`cache_dir`、`heartbeat_interval_secs`、日志批量参数、`fail_open` 与指标上报。

## 分布式 Agent

Agent 只需要三件事：控制面地址、认证方式与规则缓存目录。

```bash
PINGWAF_SERVER_URL="https://control.example.com:9090" \
PINGWAF_API_KEY="<enrollment key>" \
PINGWAF_CACHE_DIR="/var/lib/pingwaf/cache" \
pingwaf agent
```

纳管密钥在控制台创建（`POST /api/v1/agents/enroll` 会返回安装命令）。空的 `PINGWAF_API_KEY` 只在 all-in-one 模式的回环自动注册中有效。

当前 agent **未绑定站点**：会收到 API key 属主的全部站点，而不是单个站点；控制面自身的控制台站点（通常上游 `127.0.0.1:9080`）也会下发，在边缘节点上该回环地址没有控制台，站点会 502。尚无按节点绑定站点的 API，部署边缘时应使用专用控制面，或删除边缘不应运行的站点。

如果控制面是 ACME 签发者，需 **0.32.40+** 才会把内嵌数据面签发的 PEM 同步并推送给 agent。旧控制面只下发 `acme_email`、没有 PEM，每个 agent 会自己发起 HTTP-01，验证请求落到控制面而不是 agent，最终 `acme_failed`。暂不能升级控制面时，可在 agent 单元设置 `PINGAP_DISABLE_ACME=true` 停止重试，并改用上传证书。安装器会把 `--server-ca-cert` 复制到 `/etc/pingwaf/grpc-ca.pem`，控制台生成的命令不含 CA / `--server-tls-name`，自签控制面需手动补上。

## systemd

仓库自带的 `pingwaf.service` 以 `pingwaf` 用户运行，设置 `Restart=always`、`LimitNOFILE=65536`、`ProtectSystem=strict`，只允许写入 `/var/lib/pingwaf` 与 `/etc/pingwaf`。没有 reload 信号：配置变更由控制面应用，二进制或单元变更需要 `systemctl restart pingwaf`。

手动 tarball 安装时，`pingwaf.service` 与 `pingwaf.toml` 位于 `pingwaf-linux-<arch>/` 子目录。unit 已设置 `WorkingDirectory=/var/lib/pingwaf`，相对 `cache_dir` 才能持久化；否则 `ProtectSystem=strict` 会让缓存只读。数据库变量是 `PINGWAF_DB_URL`（不是 `PINGWAF_DATABASE_URL`）；首次启动前设置 `PINGWAF_SECRET_KEY` 和管理员口令；小于 4 GiB 的主机需固定 `MIMALLOC_ARENA_RESERVE`。把已有 agent 主机切换为 all-in-one 前，先移走 `/var/lib/pingwaf/cache`，因为 fail-open 快照可能包含另一个控制面的站点与证书。

## 控制面 TLS

控制台从首次启动起就使用生成的自签证书提供 HTTPS。请在生成前用 `PINGWAF_TLS_SANS`（逗号分隔）指定实际访问的主机名，或在 **设置 → 控制面 HTTPS** 上传真实证书。若控制台位于 TLS 终止代理之后，设置 `PINGWAF_TLS_ENABLED=false`。

## 安全

把控制台暴露到 localhost 之外前，请逐项完成
[SECURITY.md 加固清单](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md#hardening-checklist)。
要点：修改默认管理员口令；把 `PINGWAF_JWT_SECRET` 与 `PINGWAF_SECRET_KEY` 都设为
32 字节随机值；保持自助注册关闭（`PINGWAF_ALLOW_REGISTRATION=false`）；
`9080`/`9090` 只对可信网络开放；保持 gRPC TLS 开启；为每个站点启用 HTTPS 与 HSTS。

访问日志会原样保存请求/响应头（含 `Authorization`、`Cookie`、`Set-Cookie`）与最多
8 KiB 的 body，默认保留 180 天，因此请把 PostgreSQL 与 Elasticsearch 当作凭据存储。
MCP 的 `write` key 等同于 fleet-wide 管理员凭据；内置 AI 助手会把工具结果（站点、
日志、WAF 事件、审计条目）发送给所配置的第三方 provider——仅在该数据允许离开部署时
启用。漏洞请通过
[GitHub Security Advisories](https://github.com/shuaiZend/PingWAF/security/advisories/new)
或 `security@pingwaf.com` 私密报告。
