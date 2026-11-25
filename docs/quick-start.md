# PingWAF Quick Start

Get a fully working PingWAF instance running locally in about 10 minutes, then
protect your first website.

**By the end of this guide you will have:**

- PingWAF running in `all-in-one` mode (control plane + data plane in one process)
- The web dashboard reachable at `https://localhost:9080` (self-signed certificate)
- A successful login with the seeded administrator account
- One site configured with WAF protection enabled
- A verified block of a malicious test request

> **Three installation paths are covered.** Pick one:
>
> | Path | Best for | Time | Requires |
> | --- | --- | --- | --- |
> | [1. Docker Compose](#path-1-docker-compose-recommended) | Trying PingWAF, local dev, single host | ~10 min (first build longer) | Docker Engine 24+ with Compose v2 |
> | [2. Build from source](#path-2-build-from-source) | Contributors, custom builds, no Docker | ~20 min | Rust 1.96+, Node 26.12.1+, protoc, cmake, clang |
> | [3. Binary + systemd](#path-3-binary--systemd-production) | Production Linux servers | ~10 min | Prebuilt binary (see note) |
>
> `install.sh` works on **Linux** (amd64/arm64) with prebuilt binaries from
> [GitHub Releases](https://github.com/shuaiZend/PingWAF/releases). There are no
> macOS release binaries — macOS users must
> [build from source](#path-2-build-from-source). **Docker Compose** pulls a
> pre-built image, so it works wherever Docker does.

---

## Table of Contents

1. [What is PingWAF](#what-is-pingwaf)
2. [Prerequisites](#prerequisites)
3. [Path 1: Docker Compose (recommended)](#path-1-docker-compose-recommended)
4. [Path 2: Build from source](#path-2-build-from-source)
5. [Path 3: Binary + systemd (production)](#path-3-binary--systemd-production)
6. [First login and your first protected site](#first-login-and-your-first-protected-site)
7. [Choosing a run mode](#choosing-a-run-mode)
8. [Configuration cheat sheet](#configuration-cheat-sheet)
9. [Troubleshooting](#troubleshooting)
10. [Next steps](#next-steps)

---

## What is PingWAF

PingWAF is a distributed, centrally managed Web Application Firewall built on
top of [pingap](https://github.com/vicanso/pingap), a high-performance reverse
proxy powered by Cloudflare's [Pingora](https://github.com/cloudflare/pingora).

A single binary, `pingwaf`, runs in one of three modes:

| Mode | What it runs | Typical use |
| --- | --- | --- |
| `all-in-one` | Control plane + data plane in one process | Single server, evaluation, small deployments |
| `server` | Control plane only: REST API, dashboard, gRPC, PostgreSQL | Central management node |
| `agent` | Data plane only: proxies traffic, pulls rules from a server | Edge nodes in a distributed deployment |

The mode is selected with a CLI subcommand (`pingwaf all-in-one`, `pingwaf
server`, `pingwaf agent`) or with the `PINGWAF_MODE` environment variable.

---

## Prerequisites

### Hardware and operating system

| Requirement | Minimum | Recommended |
| --- | --- | --- |
| OS | Linux (amd64/arm64), macOS 12+ | Ubuntu 22.04+, Debian 12+ |
| CPU | 1 vCPU | 2+ vCPU |
| RAM | 512 MB | 2 GB+ |
| Disk | 1 GB | 10 GB+ (logs and cache grow) |
| Ports | 80, 443, 9080, 9090 | — |

Port summary:

| Port | Purpose | When it listens |
| --- | --- | --- |
| `9080` | REST API + embedded dashboard over HTTPS; `GET /healthz` answers on HTTP and HTTPS | Always (server / all-in-one) |
| `9090` | gRPC control plane (agents connect here) | Always (server / all-in-one) |
| `80` / `443` | Proxied site traffic | **Only after at least one site is created** |
| `5432` | PostgreSQL | Your database, internal only |

### Deployment host checklist

Run this on the target host before choosing a path. Every line corresponds to a
failure that is otherwise reported far from its cause — by `compose up`, by
`systemctl status`, or by a 403 in the console.

```bash
uname -m                                   # amd64 or arm64 (the release assets)
free -m | sed -n 2p                        # 512 MB minimum, 2 GB comfortable
df -h / | tail -1                          # 1 GB minimum, 10 GB+ with logs
command -v git curl tar                    # Path 1 needs git, all paths need curl
docker compose version                     # Path 1: the v2 plugin, not docker-compose
id -nG | grep -q docker && echo "docker group ok" \
  || echo "not in docker group: run Docker commands with sudo, or: sudo usermod -aG docker $USER"
ss -ltn | grep -E ':(80|443|9080|9090|5432)\b' || echo "ports free"
```

A PostgreSQL that already listens on `5432` is the common case on a machine that
was set up for something else: Path 1 then needs `POSTGRES_PORT` (or the compose
installer's `--db-port`), and a native install needs its own database name rather
than the default `pingwaf` one.

### Software versions

| Component | Minimum | Notes |
| --- | --- | --- |
| Rust | **1.96** (MSRV) | CI tracks stable; the Docker image and the release binaries build with 1.98.1 |
| Node.js | **26.12.1** | Only needed to build the dashboard frontend — lower versions fail `npm ci` (`engine-strict`, ships the 2026-10 security fixes) |
| PostgreSQL | **14+** | Docker Compose ships `postgres:16-alpine`; a native install takes whatever the distribution packages — Ubuntu 26.04 ships `postgresql-18`, 24.04 ships `postgresql-16`. Check with `apt-cache search --names-only '^postgresql-[0-9]+$'` instead of copying a version from this page |
| Docker Engine | 24+ | With Compose v2 (`docker compose`, not `docker-compose`) |
| protoc | Any recent release | **Required.** See the warning below |

### Native build tools (only for [Path 2](#path-2-build-from-source))

`protoc`, `cmake`, `clang`/`libclang`, `pkg-config`, OpenSSL development
headers, and `nasm` (needed to assemble the TLS backend).

> ⚠️ **protoc is mandatory and fails silently.** The gRPC stubs for the control
> plane are generated by [`pingwaf-proto/build.rs`](../pingwaf-proto/build.rs).
> If `protoc` is **not** on `PATH`, the build script does not error out — it
> writes a placeholder file and prints only a `cargo:warning`. Compilation then
> fails later inside `pingwaf-server` / `pingwaf-agent` with confusing
> "cannot find type/value" errors.
>
> Install it **before** the first `cargo build`:
>
> ```bash
> # macOS
> brew install protobuf
>
> # Debian / Ubuntu
> sudo apt install -y protobuf-compiler
> ```
>
> Verify with `protoc --version`. If you already built once without protoc,
> force regeneration of the stale placeholder:
>
> ```bash
> cargo clean -p pingwaf-proto
> ```

### PostgreSQL

You need a reachable PostgreSQL 14+ instance. PingWAF creates its schema
automatically on startup via SeaORM migrations, but the database role must be
able to create tables in the target database (owner or `CREATEDB`).

Default connection string used throughout this guide:

```
postgres://pingwaf:pingwaf@localhost:5432/pingwaf
```

---

## Path 1: Docker Compose (recommended)

> **Shortest path:** the official installer wraps the same compose file — it
> downloads it, writes a private `.env` and starts the stack:
>
> ```bash
> curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/deploy/compose/install.sh | bash
> ```
>
> The installer generates a random administrator password (printed **once**, at
> the end) and a `PINGWAF_SECRET_KEY` in `.env` (mode `0600`), keeps the data
> volumes on `--force`, and publishes the console (9080) on **`0.0.0.0`** so it
> is reachable right after install — restrict it with `PINGWAF_ADMIN_BIND`, a
> firewall or a reverse proxy, and change the administrator password at the
> first sign-in. gRPC (9090) stays on **`127.0.0.1`**; set
> `PINGWAF_GRPC_BIND=0.0.0.0` only for remote agents.
>
> Use the steps below when you want to inspect or edit the compose file first.
> The command generator on the [install page](https://www.pingwaf.com/install/) writes the same flags.

The repository ships a [`docker-compose.yml`](../docker-compose.yml) with two
services: `pingwaf` (all-in-one) and `postgres` (`postgres:16-alpine`).

### Step 1 — Clone the repository

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
```

### Step 2 — Set the secrets

Docker Compose interpolates `POSTGRES_PASSWORD`, `JWT_SECRET` and
`ADMIN_PASSWORD` from your environment (or from a local `.env` file). Never run
a reachable instance with the built-in defaults.

**Option A — environment variables (throwaway local run):**

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 16)"
export JWT_SECRET="$(openssl rand -hex 32)"      # 32 random bytes (server floor: 16 chars)
export PINGWAF_SECRET_KEY="$(openssl rand -hex 32)"  # seals channel/AI/backup secrets
export ADMIN_PASSWORD="$(openssl rand -hex 16)"
```

**Option B — a local `.env` file (persists across shells):**

```bash
cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
PINGWAF_SECRET_KEY=$(openssl rand -hex 32)
ADMIN_EMAIL=admin@pingwaf.local
ADMIN_PASSWORD=$(openssl rand -hex 16)
ALLOW_REGISTRATION=false
RUST_LOG=info,sqlx=warn
EOF
chmod 600 .env
```

> `.env` holds secrets (the DSN, `PINGWAF_SECRET_KEY`, the JWT secret and the
> admin password) and is **not** covered by the repository `.gitignore`. Keep it
> out of version control, `chmod 600` it, and prefer a secret manager (systemd
> credentials, Kubernetes Secret, Docker secret) over a plain file.
>
> **Back up `PINGWAF_SECRET_KEY` separately from the database.** It encrypts
> notification-channel secrets, the AI provider key and backup-target
> credentials; without it those fields are stored in clear text. There is no
> online rotation — read the rotation note in
> [`SECURITY.md`](../SECURITY.md#credentials-and-secrets) before changing it.

Compose variables you can set:

| Variable | Default | Description |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | `pingwaf` (development fallback) | PostgreSQL password (also used to build the DSN). Set a random value for any real deployment |
| `PINGWAF_ADMIN_BIND` / `PINGWAF_GRPC_BIND` | `0.0.0.0` / `127.0.0.1` | Host address the console (9080) / gRPC (9090) publish on. The console is reachable from the network so a fresh install is usable — restrict it, or set a specific admin IP. gRPC stays loopback until remote agents need it |
| `JWT_SECRET` | `change-me-in-production-use-32-chars` | JWT signing secret, **32 random bytes** (`openssl rand -hex 32`; server floor 16 chars) |
| `PINGWAF_SECRET_KEY` | unset (required for sealing) | Instance key for sealed secrets (channels, AI key, backup targets); **set 32 random bytes**, unset = clear text. The installer generates it into `.env` |
| `ADMIN_EMAIL` | `admin@pingwaf.local` | Seeded administrator email |
| `ADMIN_PASSWORD` | **none — required on a fresh database** | Seeded administrator password; empty makes the first boot fail. The installer generates a random one and prints it once (forced change at first login) |
| `ALLOW_REGISTRATION` | `false` | Allow new user signups |
| `HEARTBEAT_INTERVAL` | `15` | Agent heartbeat interval (seconds) |
| `RUST_LOG` | `info,sqlx=warn` | Tracing log level filter |
| `POSTGRES_PORT` | `5432` | Host port mapped to PostgreSQL |

### Step 3 — Start the stack

```bash
sudo docker compose up -d
```

If your user is in the `docker` group, drop the `sudo`. Without either, compose
fails with `permission denied while trying to connect to the Docker API at
unix:///var/run/docker.sock`.

> ⚠️ **A fresh database rejects every write until the seeded password is
> changed.** Signing in succeeds, but creating a site or a rule answers
> `403 {"code":"password_change_required"}`. Before automating anything:
>
> ```bash
> TOKEN=$(curl -sk -X POST https://127.0.0.1:9080/api/v1/auth/login \
>   -H 'Content-Type: application/json' \
>   -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
>   | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
> curl -sk -X PUT https://127.0.0.1:9080/api/v1/auth/password \
>   -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
>   -d '{"current_password":"OLD","new_password":"NEW"}'
> ```
>
> The change revokes the token you used, so sign in again with the new password.

By default Compose pulls the pre-built image
`ghcr.io/shuaizend/pingwaf:latest`. **Pin a release for production** — set
`PINGWAF_TAG=0.32.27` (or the current version) in `.env` instead of tracking a
mutable tag, and follow [Upgrade Procedure](./deployment.md#upgrade-procedure)
(take a database snapshot first; roll back by re-pinning the previous tag). To
build from source instead, uncomment the
`build:` section in [`docker-compose.yml`](../docker-compose.yml) and run
`docker compose up -d --build` — the multi-stage [`Dockerfile`](../Dockerfile)
(Node 26.12.1 frontend build → Rust 1.98 builder with protoc/cmake/nasm → minimal
runtime) compiles the whole Rust workspace, so the **first** source build can
take 10–20 minutes; later builds reuse the layer cache.

Follow the logs:

```bash
docker compose logs -f pingwaf
```

Wait until Postgres is healthy and PingWAF reports it is listening:

```bash
docker compose ps          # both services should be "running" / "healthy"
```

### Step 4 — Verify

```bash
curl -sf http://localhost:9080/healthz
```

Expected response:

```json
{"status":"ok","database":"up"}
```

If `"database"` is not `"up"`, see
[Database connection failed](#database-connection-failed).

### Step 5 — Open the dashboard

Browse to **<https://localhost:9080>** and log in with:

| Field | Value |
| --- | --- |
| Email | `admin@pingwaf.local` (or your `ADMIN_EMAIL`) |
| Password | the `ADMIN_PASSWORD` you set in `.env` — the compose file has **no default** (an empty value makes the first boot fail), and the official installer generates a random one and prints it once |

The certificate is self-signed on first boot, so the browser shows a warning
until you either trust it or upload a real certificate under **Settings →
Control plane HTTPS** (where you can also download the current one). Set
`PINGWAF_TLS_SANS` / `tls_sans` to the hostname you use, otherwise the
generated certificate does not cover it.

The dashboard ships three languages — English, 中文, 日本語 — auto-detected from
your browser and switchable in the header.

**Change the administrator password immediately:** Profile → Change Password.

### Optional: talk to the REST API

```bash
TOKEN=$(curl -sk -X POST https://localhost:9080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@pingwaf.local","password":"'"$ADMIN_PASSWORD"'"}' \
  | jq -r .access_token)

curl -sk https://localhost:9080/api/v1/sites \
  -H "Authorization: Bearer $TOKEN" | jq .
```

`-k` skips certificate verification — required until the self-signed
certificate is trusted (or a real one is uploaded).

API base URL: `https://<host>:9080/api/v1` (plain `http://` is answered with a
`308` redirect to the `https://` URL) — full reference in
[`docs/api.md`](./api.md).

### Stopping and resetting

```bash
docker compose down        # stop, keep database and cache volumes
docker compose down -v     # stop AND delete volumes (full factory reset)
```

---

## Path 2: Build from source

### Step 1 — Install the toolchain

**macOS:**

```bash
xcode-select --install                        # clang / libclang
brew install rustup-init protobuf cmake pkg-config openssl nasm
rustup-init -y && source "$HOME/.cargo/env"
brew install node@26                          # Node 26 for the frontend (node -v must be ≥ 26.12.1)
```

**Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev \
    cmake clang libclang-dev protobuf-compiler nasm curl git

# Rust (MSRV 1.96+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Node 26.12.1+
curl -fsSL https://deb.nodesource.com/setup_26.x | sudo -E bash -
sudo apt install -y nodejs
```

Confirm everything is present **before** building:

```bash
rustc --version      # >= 1.96
cargo --version
node --version       # >= v26.12.1
npm --version
protoc --version     # MUST succeed — see the protoc warning above
cmake --version
```

### Step 2 — Clone the repository

```bash
git clone https://github.com/shuaiZend/PingWAF.git
cd PingWAF
```

### Step 3 — Build the dashboard frontend

The control plane embeds the dashboard with `rust-embed` from the `web/dist/`
directory **at compile time**, so build the frontend first:

```bash
cd web
npm ci
npm run build      # runs `tsc -b && vite build`, output in web/dist
cd ..
```

> `web/.npmrc` sets `engine-strict=true`, so an older runtime fails `npm ci`
> with `EBADENGINE` instead of silently building a bundle with a Node release
> that predates the 2026-10 security fixes. Upgrade with NodeSource (`setup_26.x`)
> or `brew install node@26`.
>
> Rebuild the Rust binary whenever you rebuild the frontend — the assets are
> baked into the executable, not read from disk at runtime.

### Step 4 — Build the `pingwaf` binary

```bash
cargo build --release --bin pingwaf --features full
```

The binary lands at `target/release/pingwaf`. `--features full` enables tracing
(OpenTelemetry/Sentry) and image optimisation; drop it for a smaller build.

To build against rustls instead of OpenSSL:

```bash
cargo build --release --bin pingwaf --no-default-features --features tls-rustls,full
```

> Build fails with "cannot find type … in `pingwaf_proto`"? You almost
> certainly built once without `protoc`. Install it, then:
> `cargo clean -p pingwaf-proto && cargo build --release --bin pingwaf --features full`.

Install it system-wide if you like:

```bash
sudo install -m 0755 target/release/pingwaf /usr/local/bin/pingwaf
pingwaf --version          # the installed build
pingwaf config --help      # PingWAF subcommands
```

> The top-level `pingwaf --help` answers with the `pingap`-compatible options
> (the two entry points share one binary); the PingWAF subcommand tree is
> reached through a subcommand, e.g. `pingwaf config --help`.

### Step 5 — Prepare PostgreSQL

**Option A — throwaway container (fastest):**

```bash
docker run -d --name pingwaf-postgres \
  -e POSTGRES_USER=pingwaf \
  -e POSTGRES_PASSWORD=pingwaf \
  -e POSTGRES_DB=pingwaf \
  -p 5432:5432 \
  postgres:16-alpine
```

**Option B — local install (Debian/Ubuntu):**

```bash
# Use the distribution's default PostgreSQL package. Ubuntu 26.04 ships 18;
# `postgresql-16` does not exist there. Anything 14+ works.
sudo apt install -y postgresql
# Idempotent: a reinstall or a host that already has the role/database is fine.
sudo -u postgres createuser pingwaf 2>/dev/null || true
sudo -u postgres createdb -O pingwaf pingwaf 2>/dev/null || true
sudo -u postgres psql -c "ALTER USER pingwaf PASSWORD 'pingwaf';"
```

> If your distribution does not package PostgreSQL 16, either add the
> [PGDG apt repository](https://www.postgresql.org/download/linux/) or install
> the version it does ship — anything from 14 upwards works.

Sanity-check the connection:

```bash
psql "postgres://pingwaf:pingwaf@localhost:5432/pingwaf" -c "SELECT 1"
```

### Step 6 — Run in all-in-one mode

Minimal runnable command:

```bash
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

A safer invocation for anything but a throwaway box:

```bash
./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf" \
  --admin-addr 0.0.0.0:9080 \
  --grpc-addr 0.0.0.0:9090 \
  --jwt-secret "$(openssl rand -hex 32)" \
  --admin-email "admin@pingwaf.local" \
  --admin-password "$(openssl rand -hex 16)"
```

Equivalent, environment-variable only (no subcommand needed when
`PINGWAF_MODE` is set):

```bash
export PINGWAF_MODE=all-in-one
export PINGWAF_DB_URL="postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
export PINGWAF_JWT_SECRET="$(openssl rand -hex 32)"
export PINGWAF_ADMIN_PASSWORD="$(openssl rand -hex 16)"
export RUST_LOG=info,sqlx=warn
./target/release/pingwaf
```

Run it in the background and tail the log:

```bash
RUST_LOG=info,sqlx=warn ./target/release/pingwaf all-in-one \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf" \
  > pingwaf.log 2>&1 &
tail -f pingwaf.log
```

### Step 7 — Verify

```bash
curl -sf http://localhost:9080/healthz
# {"status":"ok","database":"up"}
```

The health endpoint answers on both schemes, so a plain-HTTP probe keeps
working; everything else is served over HTTPS and redirects otherwise.

Then open <https://localhost:9080> and log in with `admin@pingwaf.local`.
For a manual install that copied the example config, the seeded password is
`pingwaf123` unless you changed it; for an `install.sh` install it is the
`--admin-password` you passed, or the random password printed once at the end.
Change it before exposing the console.

Stop with `Ctrl-C` in the foreground, or `kill <pid>` when backgrounded.

---

## Path 3: Binary + systemd (production)

Full details live in [`docs/deployment.md`](./deployment.md); the repository
also ships a hardened unit file, [`pingwaf.service`](../pingwaf.service).

> **Note:** the installer (`install.sh`) downloads a prebuilt
> `pingwaf-linux-{amd64,arm64}` archive from
> [GitHub Releases](https://github.com/shuaiZend/PingWAF/releases) and works on
> Linux. It runs in two modes:
>
> - **Interactive** — download the script and run `bash install.sh` on a
>   terminal: it asks for the deployment mode, the admin credentials (e-mail
>   and password twice; leaving the password empty generates a random one,
>   printed once at the end), the PostgreSQL URL, the dashboard certificate
>   SANs and the version, shows an installation plan, and asks for
>   confirmation.
> - **One line, unattended** —
>   `curl -fsSL https://raw.githubusercontent.com/shuaiZend/PingWAF/main/install.sh | sudo bash -s -- --mode all-in-one`
>   installs with the given values and defaults and never prompts (piping
>   means there is no terminal to prompt on; flags go after `-s --`).
>   `--dry-run` prints the resolved plan without changing anything.
>
> The installer is fail-closed: it **verifies the release `.sha256`** and aborts
> on a missing/mismatched checksum; it **generates `PINGWAF_SECRET_KEY`** and
> writes it to `/etc/pingwaf/pingwaf.env` (mode `0600`, read by the systemd
> unit), keeping an existing key on upgrade. The dashboard (9080) binds
> **`0.0.0.0`** so the console is reachable right after install — restrict the
> port to your admin network (firewall or a reverse proxy) and change the
> administrator password at the first sign-in. gRPC (9090) stays on
> **`127.0.0.1`**; `--listen-public` (or `PINGWAF_LISTEN_PUBLIC=1`) opens it for
> remote agents.
>
> On macOS there are no release binaries — build via
> [Path 2](#path-2-build-from-source), then follow the steps below.

```bash
# 1. Put the binary in place — download the release, or use a Path 2 build
#    (there is no need to compile for a production install)
cd /tmp && rm -rf pingwaf-rel && mkdir pingwaf-rel && cd pingwaf-rel
curl -fsSLO https://github.com/shuaiZend/PingWAF/releases/latest/download/pingwaf-linux-amd64.tar.gz
curl -fsSLO https://github.com/shuaiZend/PingWAF/releases/latest/download/pingwaf-linux-amd64.tar.gz.sha256
sha256sum -c pingwaf-linux-amd64.tar.gz.sha256    # fail-closed: no checksum, no install
tar xzf pingwaf-linux-amd64.tar.gz
sudo install -m 0755 pingwaf-linux-amd64/pingwaf /usr/local/bin/pingwaf
# on arm64 use pingwaf-linux-arm64.tar.gz

# 2. Create the service user and directories (idempotent: an upgrade or a
#    host that already ran an agent install has the user)
id -u pingwaf >/dev/null 2>&1 || \
  sudo useradd --system --home-dir /var/lib/pingwaf --shell /usr/sbin/nologin pingwaf
sudo mkdir -p /var/lib/pingwaf /etc/pingwaf
sudo chown -R pingwaf:pingwaf /var/lib/pingwaf /etc/pingwaf

# 3. Install the systemd unit (it lives inside the extracted directory, not at
#    the top of /tmp/pingwaf-rel)
sudo cp pingwaf-linux-amd64/pingwaf.service /etc/systemd/system/pingwaf.service
sudo systemctl daemon-reload

# 4. Provide the configuration (a file, environment, or both)
sudo cp pingwaf-linux-amd64/pingwaf.toml /etc/pingwaf/pingwaf.toml
sudo chown root:pingwaf /etc/pingwaf/pingwaf.toml
sudo systemctl edit pingwaf   # drop-in override
```

The `cp` is not optional when the drop-in names `PINGWAF_CONFIG`: a missing file
stops startup with `cannot read config file … No such file or directory` instead
of falling back to defaults.

In the drop-in, point the process at a configuration file and/or set the
environment it needs — the environment wins over the file, and a flag on the
command line wins over both:

```ini
[Service]
WorkingDirectory=/var/lib/pingwaf
Environment=PINGWAF_CONFIG=/etc/pingwaf/pingwaf.toml
Environment=PINGWAF_JWT_SECRET=RANDOM_32_BYTE_HEX
Environment=PINGWAF_ADMIN_PASSWORD=RANDOM_ADMIN_PASSWORD
Environment=PINGWAF_ALLOW_REGISTRATION=false
Environment=RUST_LOG=info,sqlx=warn
# Only needed when the database is not the default pingwaf/pingwaf@localhost:5432/pingwaf
Environment=PINGWAF_DB_URL=postgres://pingwaf:CHANGE_ME@localhost:5432/pingwaf
# Manual units have no memory probe; on a host below 4 GiB pin the first arena:
# Environment=MIMALLOC_ARENA_RESERVE=268435456
# Environment=MIMALLOC_ARENA_EAGER_COMMIT=0
```

`PINGWAF_DB_URL` is the database variable; `PINGWAF_DATABASE_URL` is not read.
The example config ships `admin_password = "pingwaf123"` and `jwt_secret =
"change-me-in-production"`; change both before the first start, or set the
environment variables above. The fresh database rejects every write with `403
password_change_required` until the admin password is changed, but the seeded
password is known, so do not expose the console before changing it.

The unit now sets `WorkingDirectory=/var/lib/pingwaf`; without it systemd starts
in `/`, the relative `cache_dir = "./data/cache"` resolves to `/data/cache`, and
`ProtectSystem=strict` makes it read-only (`Failed to create cache directory ...
Read-only file system`). If you use an older unit, set the working directory or
an absolute `cache_dir` yourself.

If `/var/lib/pingwaf/cache` was left by a previous **agent** install, move it
aside before starting all-in-one. The agent cache is fail-open and can contain
another control plane's sites and certificates; the all-in-one would serve that
snapshot until its own control plane pushes a new bundle.

The example config binds the dashboard and gRPC to `127.0.0.1`. For a remote
dashboard or remote agents, set `admin_addr`/`grpc_addr` to `0.0.0.0` (or use
`--listen-public` with the installer) only behind a reverse proxy or trusted
network, and change the admin password first.

The file is optional: without it, the `Environment=` lines below are the whole
configuration. If you point `PINGWAF_CONFIG` at a path, start from the example —
`sudo cp pingwaf.toml /etc/pingwaf/pingwaf.toml` (an `install.sh` run writes one
for you) — and remember that an unreadable path stops startup rather than being
ignored. Its `[server]` and `[agent]` tables take the flag names with
underscores (`admin_addr`, `max_body_log_size`, …) as described in the
[configuration cheat sheet](#configuration-cheat-sheet).

Generate the instance key the unit's `EnvironmentFile` reads (a manual install
does not create it; without it sealed notification/AI/backup credentials are
stored in clear text):

```bash
sudo install -m 0600 -o pingwaf -g pingwaf /dev/null /etc/pingwaf/pingwaf.env
echo "PINGWAF_SECRET_KEY=$(openssl rand -hex 32)" | \
  sudo tee -a /etc/pingwaf/pingwaf.env >/dev/null
```

```bash
# 5. Start and enable
sudo systemctl enable --now pingwaf
sudo systemctl status pingwaf
sudo journalctl -u pingwaf -f
```

A fresh database rejects every write with `403 password_change_required`
until the seeded password is changed (`PUT /api/v1/auth/password`, or Settings →
Account). Do that before creating a site, and before pointing automation at the
API.

Before exposing this to the internet, override every default credential:
`PINGWAF_JWT_SECRET` (32 random bytes; server floor 16 chars), `PINGWAF_ADMIN_PASSWORD`,
`PINGWAF_ADMIN_EMAIL`, and set `PINGWAF_ALLOW_REGISTRATION=false`. The
shipped unit (`pingwaf.service`) and the unit `install.sh` writes grant
`CAP_NET_BIND_SERVICE` via `AmbientCapabilities`, so the unprivileged
`pingwaf` user binds `80` and `443` directly — no root, no reverse proxy
required for the binding itself. Verify with
`systemctl show pingwaf -p AmbientCapabilities`; an empty value means the
unit predates the capability (an older `install.sh` run) — see the
[upgrade notes](./deployment.md#binary) for the drop-in fix.

---

## First login and your first protected site

This is a walkthrough; every screen is documented in depth in
[`docs/user-guide.md`](./user-guide.md).

### 1. Log in

Open `https://localhost:9080`, sign in as `admin@pingwaf.local`, then change the
password (Profile → Change Password).

### 2. Create a site

**Sites → Add Site**

| Field | Example | Notes |
| --- | --- | --- |
| Name | `Local Demo` | Human-readable label |
| Domain | `demo.local` | Hostname PingWAF should protect |
| Plan | `free` | Affects feature limits |

Then add at least one origin under **Sites → Local Demo → Upstreams → Add**
(e.g. `127.0.0.1:8080`). Ports `80`/`443` start listening once a site exists.

### 3. Enable the WAF

**Sites → Local Demo → Rules → Security Mode**

| Mode | Behaviour |
| --- | --- |
| `Off` | Traffic passes through uninspected |
| `Detection` | Rules evaluated and logged, never blocked |
| `Prevention` | Matching requests are blocked |

Start in **Detection** to watch false positives, then switch to **Prevention**.
Managed rulesets (SQLi, XSS, RCE, path traversal, command injection) can be
toggled individually.

### 4. Send traffic and observe

Resolve the site domain to the PingWAF host (a `/etc/hosts` entry is enough for
a local test):

```bash
echo "127.0.0.1 demo.local" | sudo tee -a /etc/hosts
```

A benign request:

```bash
curl -i http://demo.local/
```

A request that a managed SQLi rule should catch (in `Prevention` mode it is
answered with `403`):

```bash
curl -i "http://demo.local/?id=1%27%20OR%201%3D1--"
```

Inspect the outcome in the dashboard under **Logs → Security** (matched rule,
action, client IP) and **Logs → Access**. Analytics on the home page shows
request trends and top triggered rules.

### 5. Go further

Rate limiting, CC protection and challenges, caching, rewrites, custom error
pages, Geo/IP rules, bot protection and ACME certificates are all covered in
[`docs/user-guide.md`](./user-guide.md). Recent releases also add per-site
origin pools with load balancing and routing (the **Origin** tab on a site's
detail page) and global IP groups with subscription sync.

---

## Choosing a run mode

### all-in-one

One process, one host: REST API + dashboard + gRPC control plane + the proxying
data plane. The embedded agent connects to the local control plane over
loopback.

```bash
pingwaf all-in-one --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

Choose it when you protect a single server or a small number of sites, want the
simplest possible operations story, or are evaluating PingWAF.

### server + agent (distributed)

A central control plane stores configuration in PostgreSQL and pushes rules to
any number of edge agents over gRPC. Agents cache rules locally and keep
proxying if the control plane is unreachable (fail-open by default; per-site
failover policies and the global default are configurable in the console).

```bash
# Central control plane — gRPC TLS is on by default; the first boot generates
# a self-signed CA + certificate into the data directory
pingwaf server \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf" \
  --admin-addr 0.0.0.0:9080 \
  --grpc-addr 0.0.0.0:9090 \
  --jwt-secret "$(openssl rand -hex 32)"

# Each edge node — use the console's Nodes → Add node flow (or
# POST /api/v1/agents/enroll) to mint the enrollment key and command.
# The generated command does not include the control plane's CA; add it
# when the control plane uses its self-signed certificate.
pingwaf agent \
  --server-url "https://control-plane:9090" \
  --server-ca-cert /etc/pingwaf/grpc-ca.pem \
  --api-key "YOUR_AGENT_KEY" \
  --cache-dir /var/lib/pingwaf/cache
```

> **Agent scope and certificate source.** Agent nodes are currently
> **unbound**: an agent receives every site owned by the API key's owner, not
> just one site. The control plane's own dashboard site (typically
> `waf.<domain>` with upstream `127.0.0.1:9080`) is included too; on an edge
> that loopback has no dashboard and the site returns 502. There is no
> per-node site binding yet — use a dedicated control plane or remove sites an
> edge must not run. For ACME, the control plane must be **0.32.40 or newer**
> so the PEMs issued by its embedded data plane are synced into
> `site_certificates` and pushed to agents. An older control plane sends
> `acme_email` without a PEM, so each agent starts its own HTTP-01 order; the
> CA validation request reaches the host that owns port 80 (usually the
> control plane), not the agent, and fails with `acme_failed`. If the control
> plane cannot be upgraded yet, set `PINGAP_DISABLE_ACME=true` in the agent
> unit to stop the retry loop and upload certificates instead.

A node installed with `install.sh --mode agent` runs the agent-only build
(`pingwaf-agent`) under the same `/usr/local/bin/pingwaf` name and command, so
nothing above changes; see [cli.md → the agent-only build](cli.md#the-agent-only-build-pingwaf-agent).

Choose it when sites span multiple hosts or regions, when you need central
visibility and one-click rule rollout, or when the management plane must be
isolated from traffic-facing nodes. Only port `9090` has to be reachable from
agents to the control plane.

| Aspect | all-in-one | server + agent |
| --- | --- | --- |
| Processes | 1 | 1 server + N agents |
| PostgreSQL | Required | Required (server only) |
| Ports | 80, 443, 9080, 9090 | server: 9080, 9090 · agent: 80, 443 |
| Rule propagation | In-process | gRPC push + local cache |
| Scaling | Vertical | Horizontal, add agents |
| Upgrade order | Single restart | Server first, then agents one by one |

---

## Configuration cheat sheet

Configuration comes from three channels, and a later one overrides an earlier
one:

1. **A TOML file** — `--config /etc/pingwaf/pingwaf.toml` or `PINGWAF_CONFIG`.
   Its `[server]` and `[agent]` tables take the keys below with dashes written
   as underscores (`--max-body-log-size` → `max_body_log_size`), and lists are
   TOML arrays. The `all-in-one` mode reads both tables, `server` and `agent`
   only their own. Unknown keys are reported and ignored at startup.
2. **Environment variables** — the `Environment` column.
3. **CLI flags** — always win.

> 📌 The [`pingwaf.toml`](../pingwaf.toml) in the repository root is a
> reference example: pass it with `--config pingwaf.toml` to use it. Its
> `[[upstreams]]` / `[[locations]]` pingap sections belong to the plain
> `pingwaf -c pingwaf.toml` proxy mode (no subcommand) and are ignored by the
> PingWAF modes.

### Common / mode selection

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--config` | `PINGWAF_CONFIG` | — | TOML configuration file; lowest-precedence channel |
| — | `PINGWAF_MODE` | — | `all-in-one`, `server` or `agent`; lets you run bare `pingwaf` |
| `--db-url` | `PINGWAF_DB_URL` | `postgres://pingwaf:pingwaf@localhost:5432/pingwaf` | PostgreSQL DSN |
| `--admin-addr` | `PINGWAF_ADMIN_ADDR` | `0.0.0.0:9080` | REST API + dashboard listen address |
| `--grpc-addr` | `PINGWAF_GRPC_ADDR` | `0.0.0.0:9090` | gRPC control plane listen address |
| `--tls-enabled` | `PINGWAF_TLS_ENABLED` | `true` | Serve the REST API + dashboard over HTTPS (self-signed until a certificate is uploaded); `false` behind a TLS-terminating proxy |
| `--tls-sans` | `PINGWAF_TLS_SANS` | hostname, `localhost`, `127.0.0.1` | Comma-separated subject alternative names for the generated certificate |
| — | `PINGWAF_HTTP_ADDR` | — | Alias for the REST API / dashboard address read by the server config layer |
| — | `RUST_LOG` | `info,sqlx=warn` | Tracing log filter, e.g. `debug`, `pingwaf_server=debug` |

### Server (`server` / `all-in-one`)

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--jwt-secret` | `PINGWAF_JWT_SECRET` | `change-me-in-production` | JWT signing secret, **32 random bytes** (`openssl rand -hex 32`; server floor 16 chars) |
| `--admin-email` | `PINGWAF_ADMIN_EMAIL` | `admin@pingwaf.local` | Seeded administrator email |
| `--admin-password` | `PINGWAF_ADMIN_PASSWORD` | random, printed once | Seeded administrator password; when empty the installer generates one and prints it once |
| `--serve-frontend` | `PINGWAF_SERVE_FRONTEND` | `true` | Serve the embedded dashboard SPA |
| — | `PINGWAF_JWT_EXPIRATION_HOURS` | `12` | Access-token lifetime |
| — | `PINGWAF_ALLOW_REGISTRATION` | `true` (code); compose sets `false` | Allow new user signups |
| — | `PINGWAF_HEARTBEAT_INTERVAL` | `15` | Heartbeat interval handed to agents (the agent-side `--heartbeat-interval-secs` flag reads the same variable and falls back to `30`) |
| — | `PINGWAF_DB_MAX_CONNECTIONS` | `20` | Connection pool maximum |
| — | `PINGWAF_METRIC_RETENTION_DAYS` | `7` | Days of edge-metric samples kept |
| — | `PINGWAF_CORS_ORIGINS` | `[]` (same-origin only) | Allowed CORS origins, comma-separated; empty sends no CORS headers |
| — | `PINGWAF_PASSKEY_ENABLED` / `_RP_NAME` / `_RP_ID` / `_ORIGIN` / `_TRUST_FORWARDED_PROTO` | see [deployment guide](./deployment.md#server-configuration-server) | Passkey (WebAuthn) settings |

A dash means the setting has no counterpart in that column: the server rows
with a dash are **environment-only** (no flag, so no file key either), while
the agent log settings with a dash in the `Environment` column are
**flag-only** — they can still be written in the `[agent]` table of the file.

### Agent (`agent` / `all-in-one`)

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--server-url` | `PINGWAF_SERVER_URL` | `http://localhost:9090` | Control plane gRPC URL |
| `--api-key` | `PINGWAF_API_KEY` | `""` | Agent authentication key (empty = auto-register over loopback in all-in-one) |
| `--cache-dir` | `PINGWAF_CACHE_DIR` | `./data/cache` | Local rule cache directory |
| `--fail-open` | `PINGWAF_FAIL_OPEN` | `true` | Fallback policy when disconnected with no synced rules for a host; per-site failover policies and the control-plane default win once synced |
| `--heartbeat-interval-secs` | `PINGWAF_HEARTBEAT_INTERVAL` | `30` | Fallback heartbeat frequency, used only when the control plane hands no interval down at registration |
| `--metrics-ship-interval-secs` | `PINGWAF_METRICS_SHIP_INTERVAL` | `30` | Edge-metrics ship interval; `0` disables shipping |
| `--log-batch-size` | — | `100` | Log entries per flush |
| `--log-flush-interval-secs` | — | `5` | Maximum time between log flushes |
| `--max-body-log-size` | — | `8192` | Maximum request body bytes to log |

Flags that default to true (`--fail-open`, `--serve-frontend`,
`--tls-enabled`) take an optional value, so they are turned off with
`--fail-open=false` or `PINGWAF_FAIL_OPEN=false` — not by omitting them.

### Elasticsearch log shipping (optional)

Environment-only — set these on the control plane to ship logs to
Elasticsearch in addition to PostgreSQL:

| Environment | Description |
| --- | --- |
| `PINGWAF_ES_ENABLED` | Enable the Elasticsearch shipper |
| `PINGWAF_ES_URLS` | Comma-separated endpoints, e.g. `http://elasticsearch:9200` |
| `PINGWAF_ES_INDEX_PREFIX` | Prefix for daily indices |
| `PINGWAF_ES_USERNAME` / `PINGWAF_ES_PASSWORD` | Basic auth |
| `PINGWAF_ES_API_KEY` | Alternative to basic auth |
| `PINGWAF_ES_MAX_BODY_SIZE` | Body truncation limit for logged entries |
| `PINGWAF_ES_BUFFER_DIR` | On-disk buffer directory |

---

## Troubleshooting

### `cargo build` fails with "cannot find type/value … in pingwaf_proto"

**Cause:** `protoc` was missing during the first build, so
`pingwaf-proto/build.rs` wrote a placeholder instead of real gRPC code. The
build script only prints a `cargo:warning=protoc not found…` line, which is
easy to miss.

**Fix:**

```bash
protoc --version || brew install protobuf        # macOS
protoc --version || sudo apt install -y protobuf-compiler   # Debian/Ubuntu

cargo clean -p pingwaf-proto
cargo build --release --bin pingwaf --features full
```

Point Cargo at a non-standard protoc with `PROTOC=/path/to/protoc cargo build …`.

### Port already in use (`Address already in use` on 9080/9090/80/443)

```bash
# Linux
ss -tlnp | grep -E '9080|9090|:80 |:443 '
# macOS
lsof -nP -iTCP:9080 -sTCP:LISTEN
```

Either stop the other process or move PingWAF:

```bash
pingwaf all-in-one --admin-addr 0.0.0.0:18080 --grpc-addr 0.0.0.0:19090 \
  --db-url "postgres://pingwaf:pingwaf@localhost:5432/pingwaf"
```

For Docker Compose, edit the host side of the `ports:` mapping, and check that
`POSTGRES_PORT` does not clash with an existing local PostgreSQL.

### Database connection failed

`/healthz` returns `"database":"down"`, or startup logs
`error connecting to database`.

```bash
# 1. Is PostgreSQL up and reachable?
psql "postgres://pingwaf:pingwaf@localhost:5432/pingwaf" -c "SELECT 1"

# 2. Does the role own the database (migrations need DDL rights)?
psql "postgres://pingwaf:pingwaf@localhost:5432/pingwaf" -c "\dn"

# 3. Docker: is the DSN host correct?
#    Inside the compose network the host is `postgres`, not `localhost`.
docker compose exec pingwaf env | grep PINGWAF_DB_URL
```

Common causes: wrong password in the DSN, `localhost` used from inside a
container, `pg_hba.conf` rejecting the connection, or the role lacking DDL
privileges. Migrations run automatically on startup and need `CREATE TABLE`.

### Dashboard does not open (connection refused / blank page / 404)

1. Check the health endpoint first — if `/healthz` fails, the server is not up:
   `curl -sf http://localhost:9080/healthz` (the health endpoint answers on both
   schemes, so this works even with TLS on).
2. Confirm the bind address. The installer writes `admin_addr = "0.0.0.0:9080"`;
   if the file was edited to `127.0.0.1:9080`, the console is unreachable from
   another machine — set `0.0.0.0:9080` back and open the firewall port.
3. Building from source? The dashboard is embedded from `web/dist` **at compile
   time**. If you skipped `cd web && npm ci && npm run build`, or rebuilt the
   frontend after compiling Rust, rebuild the binary.
4. Make sure `--serve-frontend` was not set to `false`.
5. Cloud firewall / security group must allow `9080` (and `80`/`443` for sites).

### Browser warns about the certificate / a plain-HTTP request returns 308

Expected on a fresh install: the certificate is self-signed and browsers do not
trust it yet. Either accept it once, install the downloaded certificate into
your trust store (**Settings → Control plane HTTPS → Download certificate**), or
upload a certificate issued for the hostname you use. Requests over plain
`http://` are redirected to `https://` with `308` — use the `https://` URL, and
`curl -k` until the certificate is trusted.

If the warning says the name does not match, the certificate lacks your
hostname: add it to `PINGWAF_TLS_SANS` (or `tls_sans`) and regenerate, or upload
a certificate that includes it.

### Agent cannot connect to the server

```bash
RUST_LOG=debug pingwaf agent --server-url https://control-plane:9090 --server-ca-cert /etc/pingwaf/grpc-ca.pem --api-key YOUR_KEY
```

Checklist:

1. Port `9090` reachable from the agent host: `nc -vz control-plane 9090`.
2. `--server-url` uses the **gRPC** port (9090), not the dashboard port (9080),
   and the scheme matches the server's gRPC TLS mode — `https://` with the
   default TLS (hand the agent the server's CA via `--server-ca-cert`, e.g.
   `/var/lib/pingwaf/data/grpc-ca.pem` on the control plane), `http://` only
   when the server runs `grpc_tls_mode = "off"`.
3. The API key is valid — regenerate it in **Settings → API Keys**.
4. The server was started in `server` or `all-in-one` mode.
5. Clocks are synchronised (NTP); skewed clocks break TLS and token checks.
6. Agents cache rules in `--cache-dir`; a read-only or full directory prevents
   offline operation.

### Ports 80/443 are not listening

Expected behaviour: PingWAF only binds the proxy ports once at least one site
exists. Create a site in the dashboard, then re-check:

```bash
ss -tlnp | grep -E ':80 |:443 '
```

Binding ports below 1024 as an unprivileged user additionally requires
`CAP_NET_BIND_SERVICE`, root, or a port forward.

### I set `pingwaf.toml` but nothing changed

Check, in order:

1. **Was the file loaded?** The process prints
   `pingwaf: loaded N setting(s) from <path>` at startup. No such line means the
   path never reached it — pass `--config /path/pingwaf.toml` or set
   `PINGWAF_CONFIG`.
2. **Are the keys in `[server]` / `[agent]`?** Only those two tables are read
   by the PingWAF modes; the `[[upstreams]]` / `[[locations]]` pingap sections
   belong to the plain `pingwaf -c` proxy mode. Unknown keys come with a
   `warning: unknown key …` line.
3. **Is the environment overriding it?** The environment wins over the file and
   a flag wins over both. Startup also logs the effective addresses and any
   conflicting value at `info` level.

### The install script does not work

`install.sh` downloads prebuilt `pingwaf-linux-{amd64,arm64}.tar.gz` assets
from [GitHub Releases](https://github.com/shuaiZend/PingWAF/releases), so it
works on Linux (amd64/arm64) only — on macOS,
[build from source](#path-2-build-from-source) instead. If the script cannot
determine the latest version, pass one explicitly:
`./install.sh --version 0.25.0`.

### High memory or disk usage

- Lower `PINGWAF_DB_MAX_CONNECTIONS` and the agent's `--log-batch-size`.
- Reduce `--max-body-log-size` (default 8192 bytes) if you log large bodies.
- Prune logs in **Logs → Purge** and monitor cache size in **Cache → Status**.
- Ship high-volume logs to Elasticsearch instead of keeping them in PostgreSQL.

---

## Next steps

| Document | What you will find |
| --- | --- |
| [`docs/user-guide.md`](./user-guide.md) | Dashboard tour: sites, WAF rules, rate limiting, challenges, caching, SSL, logs, agents |
| [`docs/api.md`](./api.md) | Full REST API reference (`https://<host>:9080/api/v1`) |
| [`docs/deployment.md`](./deployment.md) | Production deployment, systemd, TLS/ACME, firewall, backups, upgrades |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Development setup, code style, PR workflow |
| [`SECURITY.md`](../SECURITY.md) | How to report a vulnerability privately |
