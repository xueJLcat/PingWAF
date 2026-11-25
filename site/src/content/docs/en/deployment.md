---
title: Deployment
description: Docker Compose and source builds, ports, configuration precedence, systemd units and distributed agent setups.
minutes: 10
---

## Deployment shapes

**All-in-one** runs the control plane and one data plane in a single process. It is the right choice for a single node, for evaluation, and for small deployments where one edge is enough.

**Distributed** runs one `pingwaf server` and any number of `pingwaf agent` processes. The control plane keeps state; agents stay stateless apart from their rule cache, so you can add edges without touching the database.

## Ports

| Port | Used by | Notes |
| --- | --- | --- |
| `9080` | REST API + dashboard | HTTPS with a self-signed certificate until you replace it; keep it private |
| `9090` | gRPC control plane | Agents connect here; TLS by default, `grpc_tls_mode = "off"` downgrades to plaintext |
| `80` | Proxied traffic | Bound once the first site exists |
| `443` | Proxied traffic | Bound once the first site exists; a new site is issued a self-signed certificate automatically |

`GET /healthz` answers on both HTTP and HTTPS, which is what the compose health check and most load balancers should probe. Everything else redirects to HTTPS.

Linux agents and all-in-one nodes bind the addresses and ports authorized by active site assignments. In Agents, open the listener address dialog to review the node policy and current socket report. Removing the last site using a port closes its socket.

The legacy agent protocol delivers default-ingress sites only. A TCP bind report does not authorize custom-ingress traffic.
Migration 000107 enables custom site creation. To return to the previous binary and schema after using custom sites, restore a pre-upgrade backup.

## Docker Compose

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
export JWT_SECRET="$(openssl rand -hex 32)"
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
```

The compose file starts `ghcr.io/shuaizend/pingwaf:latest` in all-in-one mode next to `postgres:16-alpine`, publishing `80`, `443`, `9080` and `9090`. The database port is bound to `127.0.0.1` by default.

Two failures account for most first-run compose errors:

- `permission denied while trying to connect to the Docker API at unix:///var/run/docker.sock` — your user is not in the `docker` group. Run `sudo docker compose up -d`, or add yourself to the group (`sudo usermod -aG docker $USER`, then log in again).
- `failed to bind host port 127.0.0.1:5432/tcp: address already in use` — a local PostgreSQL already owns 5432. Set `POSTGRES_PORT=55432` in `.env` (or pass `--db-port 55432` to `deploy/compose/install.sh`, which picks a free port from 55432 up automatically) and start again.

> Keep `hostname` stable. The control plane matches re-registrations by hostname plus API key, so a changing container ID leaves ghost offline agents behind.

## Source build

| Tool | Version | Why |
| --- | --- | --- |
| Rust | 1.96+ (MSRV) | The binary itself |
| Node.js | 26.12.1+ | Builds the embedded dashboard; `web/.npmrc` sets `engine-strict=true` |
| `protoc` | recent | gRPC code generation — **mandatory** |
| `cmake` | recent | TLS backend build |
| PostgreSQL | 14+; native installs use the distribution's package name (`postgresql-16` on Ubuntu 24.04, `postgresql-18` on 26.04) | Control-plane datastore; the role needs DDL rights |

Without `protoc`, `pingwaf-proto` silently writes placeholder files and the downstream crates fail to compile — install it before you build.

```bash
cd web && npm ci && npm run build && cd ..
cargo build --release --bin pingwaf --features full
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

On Linux, `install.sh` downloads the prebuilt archive, installs to `/usr/local/bin`, writes `/etc/pingwaf/pingwaf.toml` and a systemd unit, and starts the service. Run it on a terminal with no arguments for guided prompts (deployment mode, admin credentials, PostgreSQL URL, certificate SANs, version), or pipe it for a one-line unattended install.

Before upgrading the control plane, back up PostgreSQL. Migration `000104` checks the existing site hostnames and fails without changing the schema if it finds a noncanonical hostname or overlapping claims. Resolve the affected sites by their UUIDs in the migration log before retrying. This migration does not enable custom ingress ports.

```bash
# interactive prompts, with an installation plan and confirmation
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh -o install.sh && bash install.sh

# one line, unattended (no prompts — piping means there is no terminal)
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | bash -s -- --mode all-in-one
```

In agent mode the installer downloads the agent-only archive (`pingwaf-agent-<os>-<arch>`, the data plane without PostgreSQL, the REST API or the dashboard) and installs it as `/usr/local/bin/pingwaf`, so the unit and commands stay the same. The generated unit also pins mimalloc's first arena from the memory ceiling (64 MiB below 1 GiB, 256 MiB below 4 GiB, 512 MiB up to 16 GiB, else 1 GiB; eager commit only at 4 GiB and above), because mimalloc creates that arena before the runtime can set the option. Flags: `--mode all-in-one|server|agent`, `--no-systemd` to skip the unit, `--admin-email` / `--admin-password` / `--tls-sans` (or the matching `PINGWAF_*` environment variables) to seed settings without prompts, and `--dry-run` to preview the plan without installing.

## Configuration precedence

Settings are read from the TOML file first, then `PINGWAF_*` environment variables, then CLI flags — later channels win. Unknown TOML keys are reported and skipped.

```bash
pingwaf all-in-one --config /etc/pingwaf/pingwaf.toml
PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml pingwaf all-in-one   # equivalent
```

The `[server]` table covers `db_url`, `admin_addr`, `tls_enabled`, `tls_sans`, `grpc_addr`, `jwt_secret`, `admin_email` and `serve_frontend`. The `[agent]` table covers `server_url`, `server_ca_cert`, `api_key`, `cache_dir`, `heartbeat_interval_secs`, log batching, `fail_open` and metric shipping.

## Distributed agents

An agent needs three things: where the control plane is, how to authenticate, and where to cache rules.

```bash
PINGWAF_SERVER_URL="https://control.example.com:9090" \
PINGWAF_API_KEY="<enrollment key>" \
PINGWAF_CACHE_DIR="/var/lib/pingwaf/cache" \
pingwaf agent
```

Enrollment keys are created from the console (`POST /api/v1/agents/enroll` returns an install command). An empty `PINGWAF_API_KEY` is only valid for loopback auto-registration in all-in-one mode.

Agents are currently **unbound**: an agent receives every site owned by the API key's owner, not one site. The control plane's own dashboard site (typically `waf.<domain>` with upstream `127.0.0.1:9080`) is included; on an edge that loopback has no dashboard and the site returns 502. There is no per-node site binding yet — use a dedicated control plane or remove sites an edge must not run.

For ACME, the control plane must be **0.32.40 or newer** so the PEMs issued by its embedded data plane are synced into `site_certificates` and pushed to agents. An older control plane sends `acme_email` without a PEM, so each agent starts its own HTTP-01 order; the CA validation request reaches the host that owns port 80 (usually the control plane), not the agent, and fails. If the control plane cannot be upgraded yet, set `PINGAP_DISABLE_ACME=true` in the agent unit and upload certificates instead.

DNS-01 with Amazon Route 53 is supported from 0.33.2: select `dns-01` + `route53`, optionally pin `acme_dns_config.hosted_zone_id`, and give the issuing process an AWS credential (an EC2 instance role is the simplest). The issuer needs `GetHostedZone`, `ListResourceRecordSets` and `ChangeResourceRecordSets` on the zone (plus `ListHostedZones` for discovery); consumer agents need no AWS permission.

The installer copies `--server-ca-cert` to `/etc/pingwaf/grpc-ca.pem` and references that durable path; the console's generated command does not include the CA or `--server-tls-name`, so add them for a self-signed control plane.

## Tunnels (internal services without an inbound port)

A tunnel reaches a service inside a private network **without an inbound port and without a public IP on that host**. The `pingwaf-tunnel` connector dials out to the control plane and to the edge; the edge terminates the public side and proxies through a loopback bridge, so the WAF, rate limiting, cache, logs and certificates all apply exactly as they do for a direct origin.

**Edge:** enable the listener only on the edges that should terminate tunnels, and firewall the port to where the connectors run:

```toml
[agent]
tunnel_addr = "0.0.0.0:9443"   # off by default
```

Then give that edge a public ingress address in **Agents → [node] → Tunnel ingress** (`edge1.example.com:9443`); the panel also shows the listener state and the certificate fingerprint connectors pin.

**Connector:** create the tunnel in **Agents → Tunnels**, copy the one-time pairing command and run it inside the private network:

```bash
curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh \
  | sudo bash -s -- --mode tunnel \
      --server-url https://control-plane:9090 \
      --server-ca-cert control-plane.pem \
      --token <pairing-token>
```

It installs `/usr/local/bin/pingwaf-tunnel`, writes `/etc/pingwaf/tunnel.toml` (`0600`) and registers `pingwaf-tunnel.service`. Nothing needs to be open on the private-network side; the connector only makes outbound connections (9090 to the control plane, 9443 to the ingress edges).

**Use it:** bind an origin pool to the tunnel in the site's origin-pool dialog. Its node addresses (`10.0.0.5:8080`, `app.internal:8443`) are then resolved by the connector inside the private network instead of by the edge. The tunnel's target list is derived from the bound pools.

Revoke a tunnel when its host is decommissioned: the credential stops working and every edge refuses the session within one rule-bundle reload. Deleting the tunnel is refused while origin pools still reference it (`409`); `?force=true` unbinds them and they fall back to direct origins.

The complete operating guide — the three independent states, the request path, the connector's commands and config keys, SOCKS5 egress for a host with no direct route, and the troubleshooting table — is the [Tunnels](/docs/tunnel/) page.

## systemd

The shipped `pingwaf.service` runs as the `pingwaf` user with `Restart=always`, `LimitNOFILE=65536`, `ProtectSystem=strict` and write access limited to `/var/lib/pingwaf` and `/etc/pingwaf`. There is no reload signal: configuration changes are applied by the control plane, and a binary or unit change needs `systemctl restart pingwaf`.

For a manual tarball install, `pingwaf.service` and `pingwaf.toml` are inside `pingwaf-linux-<arch>/`. The unit sets `WorkingDirectory=/var/lib/pingwaf` so the relative `cache_dir` persists; without it `ProtectSystem=strict` makes the cache read-only. Use `PINGWAF_DB_URL` (not `PINGWAF_DATABASE_URL`), set `PINGWAF_SECRET_KEY` and an admin password before the first start, and pin `MIMALLOC_ARENA_RESERVE` on hosts below 4 GiB. When switching an existing agent host to all-in-one, move `/var/lib/pingwaf/cache` aside first: the fail-open snapshot can contain another control plane's sites and certificates.

## TLS on the control plane

The dashboard is HTTPS from the first boot with a generated self-signed certificate. Set `PINGWAF_TLS_SANS` to the hostname you actually use (comma separated) before generating it, or upload a real certificate under **Settings → Control plane HTTPS**. When the console sits behind a TLS-terminating proxy, set `PINGWAF_TLS_ENABLED=false`.

## Security

Before exposing the console beyond localhost, work through the hardening
checklist in
[SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md#hardening-checklist).
The essentials: change the seeded administrator password, set
`PINGWAF_JWT_SECRET` and `PINGWAF_SECRET_KEY` to 32 random bytes each, keep
self-service registration off (`PINGWAF_ALLOW_REGISTRATION=false`), bind
`9080`/`9090` to trusted networks, keep gRPC TLS on, and enable HTTPS + HSTS on
every site.

Access logs keep request/response headers verbatim — including
`Authorization`, `Cookie` and `Set-Cookie` — plus up to 8 KiB of each body, for
180 days by default, so treat PostgreSQL and Elasticsearch as credential
stores. MCP `write` keys are fleet-wide administrator credentials, and the
built-in AI assistant sends tool results (sites, logs, WAF events, audit
entries) to the provider you configure: enable it only where that data may
leave the deployment. Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/shuaiZend/PingWAF/security/advisories/new)
or `security@pingwaf.com`.
