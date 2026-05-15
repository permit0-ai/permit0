# permit0 Docker 快速上手

把 permit0 用 `docker compose` 在本地跑起来——三个容器：两个 Postgres
（policy state 和 audit log 各一个）+ engine。大概 5 分钟搞定。

## 前置依赖

- Docker 24+ 和 Docker Compose v2（`docker compose version` 能跑）
- 大约 1.5 GB 磁盘（镜像 + 两个 Postgres 数据卷）
- 端口 `9090` 空闲

## 一键启动

```bash
git clone https://github.com/permit0-ai/permit0.git
cd permit0
docker compose up --build
```

第一次构建会比较慢（要拉 Rust 工具链 + 编译 release）。再启动就是秒级。

启动完成后能看到：

```
permit0-engine     | permit0 server listening on 0.0.0.0:9090
permit0-engine     |   API mounted at /api/v1/
permit0-engine     |   admin dashboard at http://0.0.0.0:9090/ui/
permit0-engine     |   audit signing pubkey: <64 hex chars>
permit0-engine     |   digest writer: dir=/var/lib/permit0/digests interval=300s batch_max=1000
```

**记住打印出来的 `audit signing pubkey`**——后面验证 audit chain 要用。

## 验证健康

```bash
curl http://localhost:9090/api/v1/health
# {"ok":true,"service":"permit0"}
```

打开 dashboard：<http://localhost:9090/ui/>

## 跑一个决策

```bash
curl -X POST http://localhost:9090/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{
    "tool_name": "gmail_send",
    "parameters": {
      "to": "alice@external.com",
      "subject": "test",
      "body": "hi"
    }
  }'
```

返回的 JSON 里 `permission` 是 `allow` / `deny` / `human` 之一，`tier` 是
`Minimal` / `Low` / `Medium` / `High` / `Critical`。给外部域发邮件通常会落到
`human`（HITL 评审）。

## 看 audit chain

每次决策都会写一条签名的 audit entry。dashboard 的 **Recent Decisions** 标签
能看到。也可以直接查 audit DB：

```bash
docker compose exec permit0-audit-db \
  psql -U permit0 -d permit0_audit \
  -c "SELECT sequence, action_type, decision, timestamp FROM audit_entries ORDER BY sequence DESC LIMIT 5"
```

或者导出整个 chain 成 JSONL：

```bash
curl -s 'http://localhost:9090/api/v1/audit/export?format=jsonl' -o audit.jsonl
wc -l audit.jsonl
```

## 离线验证 audit chain（CloudTrail 风格摘要）

引擎每 5 分钟（`PERMIT0_DIGEST_INTERVAL_SECS=300`）会输出一个签名摘要到
`/var/lib/permit0/digests`。该目录是 `audit-key` 命名卷，可以从外面读到：

```bash
docker compose exec permit0-engine ls -la /var/lib/permit0/digests
```

把摘要目录拷出来本地验证：

```bash
docker compose cp permit0-engine:/var/lib/permit0/digests ./digests
docker compose cp permit0-engine:/var/lib/permit0/audit_signing.key ./audit_signing.key

# audit_signing.key 是 hex 编码的 ed25519 seed；公钥对应启动时打印的 pubkey
PUBKEY=$(grep -oE '[0-9a-f]{64}' <(docker compose logs permit0-engine | grep pubkey) | head -1)

# 用本地 cargo 装的 permit0 binary（或者从容器拷出来）跑验证
cargo run --release -- digest verify \
  --digests-dir ./digests \
  --audit-jsonl ./audit.jsonl \
  --public-key "$PUBKEY"
```

通过会打印 `OK`。任何篡改（改 audit_entries 表里的字段、删摘要文件、改文件
内容）都会让验证失败。

## 自定义规则包

容器自带 `packs/` 里的默认规则。要用自己的规则包：

```yaml
# docker-compose.yml
services:
  permit0-engine:
    volumes:
      - audit-key:/var/lib/permit0
      - ./my-packs:/etc/permit0/packs:ro    # 解开这行
```

重启 engine：`docker compose up -d permit0-engine`。

## 启用 OTel 离线导出（S3 / Datadog / Splunk）

audit 数据可以同时往 OpenTelemetry collector 推一份，collector 再转发到
S3 / Datadog 等。Postgres 仍然是 source of truth，collector 挂了不会卡引擎。

1. 编辑 `otel-collector-config.yaml`，启用你需要的 exporter
   （`awss3`、`datadog`、`splunk_hec` 三个 stub 已经写好了）
2. 在 `docker-compose.yml` 里取消 `otel-collector` 服务的注释
3. 把 engine 的 `PERMIT0_OTLP_ENDPOINT: http://otel-collector:4318` 取消注释
4. `docker compose up -d`

## 重启 / 停掉 / 清理

```bash
docker compose restart permit0-engine    # 只重启引擎；audit chain 续上之前的 sequence
docker compose down                      # 停所有容器（数据卷保留）
docker compose down -v                   # 停所有容器 + 删数据卷（重置一切）
```

**重要**：audit 签名密钥在 `audit-key` 卷里。备份请 `audit-key` + `audit-db-data`
**一起备份**——丢了密钥，老的 entry 就再也验证不了。

## 端口和环境变量速查

| 端口 | 干嘛的 |
|---|---|
| `9090` | engine HTTP API + dashboard |
| `4318` | OTel collector OTLP/HTTP（仅启用时） |

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `PERMIT0_STATE_URL` | (compose 已设) | policy state Postgres 连接串 |
| `PERMIT0_AUDIT_URL` | (compose 已设) | audit log Postgres 连接串 |
| `PERMIT0_AUDIT_KEY_PATH` | `/var/lib/permit0/audit_signing.key` | ed25519 签名密钥路径 |
| `PERMIT0_PACKS_DIR` | `/etc/permit0/packs` | 规则包目录 |
| `PERMIT0_DIGEST_DIR` | `/var/lib/permit0/digests` | 摘要文件目录；不设就关闭摘要 |
| `PERMIT0_DIGEST_INTERVAL_SECS` | `300` | 摘要发布间隔 |
| `PERMIT0_DIGEST_BATCH_MAX` | `1000` | 单个摘要最多覆盖多少条 entry |
| `PERMIT0_OTLP_ENDPOINT` | (未设) | OTel collector 的 OTLP/HTTP 端点；设了才启用 tee |
| `RUST_LOG` | `info` | 日志级别 |

## 生产部署提醒

`docker-compose.yml` 是 **dev 默认配置**，照搬到生产之前一定要：

1. 改 `POSTGRES_PASSWORD` 和连接串里的密码（用 `.env` 或 secrets manager）
2. 给 `permit0-engine` 加 reverse proxy（nginx / caddy / traefik）做 TLS
3. 在 ui 路由前加 auth（OIDC，permit0-ui 已经有基础支持）
4. `audit-key` 卷做异地备份（搭配 `audit-db-data` 一起）
5. 把 Postgres 改成托管服务（RDS / Cloud SQL）以减少自己的运维负担
