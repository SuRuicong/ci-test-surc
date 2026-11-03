# AgentOS License 运行时（Rust 版）使用与联调手册

> 适用范围：`tools/license-rt/` 下的两个 Rust 可执行文件——`agentos-license-daemon`（现场指纹 HTTP 服务）与 `agentos-license-checker`（运行时校验/心跳，stdio 契约）。
> 契约与 TypeScript 版（`tools/license-daemon`、`tools/license-checker`）**完全兼容**，可无缝替换；签发端 `tools/license-issuer` 不在本手册范围内（仍是 TypeScript）。
> 最近验证：2026-10-30，Windows 11 x86_64，cargo 1.98.0。

---

## 1. 产物与构建

### 1.1 目录结构

```
tools/license-rt/
├── Cargo.toml                     # workspace（release: lto + strip + codegen-units=1）
├── crates/license-core/           # 共享库：验签/指纹/schema/canonical JSON/密钥策略/时间
├── crates/license-daemon/         # agentos-license-daemon（bin）
└── crates/license-checker/        # agentos-license-checker（bin）
```

### 1.2 编译

```powershell
Set-Location tools/license-rt
cargo build --release
```

产物（Windows）：

| 文件 | 用途 |
|---|---|
| `target/release/agentos-license-daemon.exe` | 现场部署：指纹采集页 + license 激活 HTTP 服务 |
| `target/release/agentos-license-checker.exe` | 现场部署：被应用进程 spawn-per-call 调用的无状态校验程序 |

单文件、无外部依赖（不依赖 Node、不依赖 .NET），可直接拷贝到客户机器。Linux/macOS 用同样的 `cargo build --release` 交叉编译即可。

### 1.3 单元测试

```powershell
Set-Location tools/license-rt
cargo test      # core 36 + daemon 5 + checker 8 = 49 个测试
```

---

## 2. 现场部署使用流程（客户侧）

完整生命周期分四步：**采集指纹 → 供应商签发 → 现场激活 → 运行时校验/心跳**。

```
客户机器                          供应商内网
┌──────────────────┐             ┌────────────────────┐
│ agentos-license- │  fingerprint│ agentos-license    │
│   daemon         │ ──────────> │   (issuer, TS CLI) │
│ (HTTP 8471)      │             │  keys generate     │
└──────────────────┘             │  issue             │
        ▲                        └────────────────────┘
        │  license.lic (.lic)             │
        └─────────────────────────────────┘
        ▼
agentos-license-checker（被业务进程周期性调用）
```

### 2.1 启动 daemon（采集指纹 + 激活）

```powershell
agentos-license-daemon serve `
  --state-dir <状态目录> `
  --public-key-file <公钥文件> `
  [--port 8471] [--bind 127.0.0.1] [--kid <kid>] [--instance-id <id>]
```

| 参数 | 必填 | 说明 |
|---|---|---|
| `--state-dir` | 是 | 激活状态目录（`active.lic`、`runtime-base.json`、账本都写在这里） |
| `--public-key-file` | 是 | 公钥：可以是 PEM，也可以是 issuer 生成的 `*.public.json` 元数据文件 |
| `--port` | 否 | 默认 `8471` |
| `--bind` | 否 | 默认 `127.0.0.1`（只监听本机回环；要开放给局域网需显式改） |
| `--kid` | 否 | 公钥文件是 PEM 且不带 kid 时指定；与文件内 kid 冲突会报错 |
| `--instance-id` | 否 | 多实例部署时参与指纹计算的实例标识 |

启动成功后 stdout 打一行：

```
[license-daemon] serving http://127.0.0.1:8471 stateDir=<dir> anchor=ok
```

`anchor=MISSING(c1)` 表示必选锚点分量（代号 c1）不可用——**此时仍可启动，但签发时指纹不可用，需先解决机器锚点问题**（stderr 会有 WARN 行）。分量名以代号（c1..c5）对外展示，真实采集来源不出现在任何交付物（ADR-20261102）。

### 2.2 采集指纹（交付给供应商签发用）

**方式一：浏览器**（推荐现场人员操作）

打开 `http://127.0.0.1:8471/`，页面展示：
- 分组大写指纹（如 `9CEE-35B3-617F-E178-...`）；
- 采集状态；锚点分量（c1）缺失时展示联系供应商的指引（不点名分量来源）。

> 页面不再展示分量明细表：分量名对外一律使用代号（c1=必选锚点，c2..c5=可选分量）。

**方式二：接口**（推荐自动化）

```powershell
Invoke-RestMethod 'http://127.0.0.1:8471/fingerprint.json' | ConvertTo-Json | Out-File fingerprint.json -Encoding utf8
```

响应体（紧凑 JSON，无尾换行，键序固定 `schema, fingerprint, components`）：

```json
{"schema":"agentos-fingerprint/v1","fingerprint":"sha256:9cee...","components":{"c1":"sha256:...","c2":"sha256:...","c3":"sha256:...","c4":"sha256:...","c5":"unavailable"}}
```

`components` 键为分量代号（c1..c5，槽位顺序固定）；旧版旧名格式的 fingerprint.json 仍被签发端兼容接受。

把这个 JSON 文件交给供应商签发 license。

> 注意：daemon 只实现了 `GET /`、`GET /fingerprint.json`、`POST /activate` 三个路由。HEAD/其他方法/其他路径一律 404（与 TS 版行为一致）。

### 2.3 激活 license

拿到供应商签发的 `.lic` 文件后：

```powershell
$body = [System.IO.File]::ReadAllBytes('license.lic')
Invoke-RestMethod -Uri 'http://127.0.0.1:8471/activate' -Method Post -ContentType 'application/json; charset=utf-8' -Body $body
```

成功响应（200）：

```json
{"ok":true,"licenseId":"lic-e2e-0001","customer":"E2E交叉验证客户","expiresAt":"2027-12-31T15:59:59.000Z"}
```

激活做了三件事：
1. 验签 + 校验 license envelope（schema、时间窗、kid 策略）；
2. **现场指纹比对**：license 里绑定的锚点分量 `c1` 必须与本机一致，不一致报 `ERR_FINGERPRINT_MISMATCH`（422）；
3. 原子写入 `<state-dir>/active.lic`（重建 envelope，byte 级与 TS 激活一致）和 `<state-dir>/runtime-base.json`。

错误响应：

| HTTP | 场景 | 响应体 |
|---|---|---|
| 400 | 请求体不是合法 JSON（或超 1 MiB） | `{"ok":false,"code":"ERR_INVALID_LICENSE","message":"Request body is not valid JSON license."}` |
| 422 | 验签失败/过期/指纹不匹配等 | `{"ok":false,"code":"<ERR_*>","message":"..."}` |
| 404 | 路径/方法不对 | `{"ok":false,"code":"ERR_NOT_FOUND"}`（无 message 键） |

### 2.4 运行时校验与心跳（checker）

业务进程（或 AgentOS 运行时）以 **spawn-per-call** 方式调用，两个子命令：

```powershell
# 只读校验：不写账本
agentos-license-checker status `
  --state-dir <状态目录> --public-key-file <公钥文件> [--kid <kid>] [--instance-id <id>]

# 心跳：累加运行时长、追加账本（含 PG 双写，见 2.5）
agentos-license-checker heartbeat --tick-monotonic-ms 60000 `
  --state-dir <状态目录> --public-key-file <公钥文件> [...同上]
```

**stdout 契约**（exit 0 时唯一一行，紧凑 JSON + `\n`，键序固定）：

```json
{"status":"valid","licenseId":"lic-e2e-0001","customer":"...","expiresAt":"2027-12-31T15:59:59.000Z","runtimeRemainingSeconds":31622400,"ledgerTipHash":"sha256:0000..."}
```

非 0 退出时 **stdout 为空**，诊断信息只写 stderr，格式：

```
[license-checker] exit=<code> <脱敏消息>
```

**退出码**：

| 码 | 含义 | 典型原因 |
|---|---|---|
| 0 | valid | 校验通过 |
| 1 | 系统错误 | `ERR_PG_LEDGER`（PG 账本失败）、参数用法错误 |
| 2 | expired | 超过 `expiresAt`，或运行配额耗尽（`runtime quota exhausted`） |
| 3 | tampered | 账本 hash 链断裂 / HMAC 不匹配（`ledger chain broken: line N: ...`） |
| 4 | unlicensed | `<state-dir>/active.lic` 不存在 |
| 5 | clock_rollback | 系统时钟回拨超过 10 分钟容忍窗口 |
| 6 | fingerprint_mismatch | 本机指纹与 license 绑定不一致（换机器/换主板） |

调用方建议：周期性（如每 60s）调用 `heartbeat --tick-monotonic-ms 60000`，按退出码决定是否继续提供服务；`status` 用于启动时和展示。

### 2.5 PostgreSQL 账本双写（可选）

设置环境变量后，heartbeat 会双写 PG 账本表并做链尾交叉验证：

```powershell
$env:AGENTOS_LICENSE_PG_URL = 'postgres://user:pass@host:5432/dbname'
agentos-license-checker heartbeat --tick-monotonic-ms 60000 --state-dir ... --public-key-file ...
```

- 表：`license_runtime_ledger`（`seq` 主键，`tick_monotonic_ms`/`cumulative_seconds` 为 double precision）；
- PG 连接失败立即报 `ERR_PG_LEDGER` → **exit 1**（业务侧应走宽限策略，不要直接停服）；
- PG 链尾与文件链尾不一致视为篡改 → exit 3。

---

## 3. 联调测试指南

以下流程是本次交付前实际跑通的完整验证路径，可作为验收/回归脚本蓝本。假设工作目录为仓库根，准备一个临时目录（下文 `$scratch`）。

### 3.1 准备：密钥与本机指纹

```powershell
$scratch = '<临时目录>'
New-Item -ItemType Directory -Force "$scratch/keys" | Out-Null

# 1) 供应商侧：生成 Ed25519 密钥对（dev 环境，TS issuer）
node --import tsx tools/license-issuer/src/cli.ts keys generate --env dev --out-dir "$scratch/keys"
#   → 得到 agentos-dev-<年>-q<季>.private.pem 和 .public.json

# 2) 客户侧：后台启动 Rust daemon
New-Item -ItemType Directory -Force "$scratch/state-rs" | Out-Null
Start-Process -NoNewWindow -FilePath 'tools/license-rt/target/release/agentos-license-daemon.exe' `
  -ArgumentList 'serve','--state-dir',"$scratch/state-rs",'--public-key-file',"$scratch/keys/agentos-dev-2026-q4.public.json",'--port','8471' `
  -RedirectStandardOutput "$scratch/daemon.log"

# 3) 取指纹文件（签发的输入）
Invoke-RestMethod 'http://127.0.0.1:8471/fingerprint.json' | ConvertTo-Json | Out-File "$scratch/fingerprint.json" -Encoding utf8
```

### 3.2 签发（供应商侧）

```powershell
node --import tsx tools/license-issuer/src/cli.ts issue `
  --fingerprint-file "$scratch/fingerprint.json" `
  --customer '联调客户' `
  --not-after 2027-12-31 `
  --max-runtime-hours 8784 `
  --key-id agentos-dev-2026-q4 `
  --private-key-file "$scratch/keys/agentos-dev-2026-q4.private.pem" `
  --out "$scratch/license.lic" `
  --license-id lic-test-0001
```

### 3.3 激活（客户侧）

```powershell
$body = [System.IO.File]::ReadAllBytes("$scratch/license.lic")
Invoke-RestMethod -Uri 'http://127.0.0.1:8471/activate' -Method Post -ContentType 'application/json; charset=utf-8' -Body $body
# 期望: {"ok":true,"licenseId":"lic-test-0001","customer":"联调客户","expiresAt":"..."}
```

### 3.4 正向验证（status / heartbeat）

```powershell
$pub = "$scratch/keys/agentos-dev-2026-q4.public.json"
$state = "$scratch/state-rs"

# status → 期望 exit 0 + 契约 JSON，runtimeRemainingSeconds = maxRuntimeSeconds，tip 为创世 hash
tools/license-rt/target/release/agentos-license-checker.exe status --state-dir $state --public-key-file $pub
Write-Output "exit=$LASTEXITCODE"

# heartbeat 60s → runtimeRemainingSeconds 应减 60
tools/license-rt/target/release/agentos-license-checker.exe heartbeat --tick-monotonic-ms 60000 --state-dir $state --public-key-file $pub
Write-Output "exit=$LASTEXITCODE"

# 再 status → 剩余时长与 ledgerTipHash 应为心跳后的新值
```

### 3.5 负向验证（退出码）

| 场景 | 操作 | 期望 |
|---|---|---|
| 未激活 | 对空 state-dir 跑 status | exit 4，stderr `no active license at ...` |
| 账本篡改 | 改 `ledger.jsonl` 任意行的 `cumulative_seconds` 数值 | exit 3，`ledger chain broken: line N: entry_hash mismatch` |
| 配额耗尽 | 签发 1 小时 license（`--max-runtime-hours 1`），激活后 `heartbeat --tick-monotonic-ms 3700000` | exit 2，`runtime quota exhausted (maxRuntimeSeconds=3600)` |
| 用法错误 | 不带参数运行 / `bogus` 子命令 | 打 USAGE，exit 1；`--help` exit 0 |
| 激活错机器 | 用 A 机指纹签发的 license 在 B 机激活 | POST /activate → 422 `ERR_FINGERPRINT_MISMATCH` |
| 非 JSON 激活 | `curl -X POST -d 'not json' .../activate` | 400 `Request body is not valid JSON license.` |
| 无效 envelope | POST `{"schema":"wrong"}` | 422 `License envelope is invalid.` |
| 未知路径 | `curl .../nope` | 404 `{"ok":false,"code":"ERR_NOT_FOUND"}` |

### 3.6 TS ↔ Rust 交叉互操作验证（回归必跑）

这是"无缝替换"的核心证据链，任何一侧改动后都应重跑：

1. **Rust 心跳 → TS 读取**：Rust `heartbeat` 后运行 TS checker `status`（`node --import tsx tools/license-checker/src/cli.ts status ...`），期望 exit 0 且 `runtimeRemainingSeconds`、`ledgerTipHash` 与 Rust 输出**逐字节一致**（证明 HKDF/HMAC/canonical JSON 账本编码互操作）。
2. **TS 心跳 → Rust 读取**：反向同理。
3. **TS 激活 → Rust 校验**：用 TS daemon 的 `activateLicense` 写状态，Rust checker `status` 应 exit 0。
4. **Rust 激活 → 字节比对**：Rust 激活出的 `active.lic`、`runtime-base.json` 与 TS 激活产物**逐字节相等**。
5. **指纹一致性**：Rust `/fingerprint.json` 与 TS `collectFingerprint` 输出字节相等。

### 3.7 验收 checklist

- [ ] `cargo build --release` 通过，两个 exe 生成
- [ ] `cargo test` 49 个测试全绿
- [ ] daemon 启动行 `anchor=ok`
- [ ] `/fingerprint.json` 与 TS 版输出一致
- [ ] 激活 200，`active.lic` 与 TS 产物字节一致
- [ ] checker status/heartbeat 正向 exit 0，stdout 契约 JSON
- [ ] 负向矩阵（3.5）全部符合退出码预期
- [ ] 交叉互操作（3.6）双向一致

---

## 4. 与 TypeScript 版的已知偏差（均不影响契约）

| 偏差 | TS 行为 | Rust 行为 |
|---|---|---|
| `--port` 非法值 | `listen(NaN)` 抛 Node 栈 | stderr `invalid --port value: <v>` + exit 1 |
| 非 AgentosError 路径（文件读失败等） | 抛 Node 栈 | 打印错误消息 + exit 1（io 错误文案随 OS 本地化） |
| 500 `ERR_UNEXPECTED` 分支 | 类型上可达 | 类型层不可达（`activate_license` 只返回 AgentosError） |
| metadata JSON 中 kid 为非字符串 truthy（如 `123`） | `ERR_INVALID_KEY_ID` | `ERR_USAGE` |

---

## 5. 故障排查

| 现象 | 排查 |
|---|---|
| 激活报指纹不匹配 | 确认签发用的 fingerprint.json 就是本机 daemon 输出的；`--instance-id` 两侧是否一致 |
| status 突然 exit 3 | 账本被改动或磁盘写损坏；看 stderr 的 `line N` 定位 |
| status exit 5 | 系统时间被回拨超过 10 分钟（账本水印是墙钟最大值） |
| heartbeat exit 1 且提到 PG | PG 不可达：检查 `AGENTOS_LICENSE_PG_URL`、网络、表是否存在；业务侧走宽限 |
| 换硬件后全部失效 | 锚点分量（`c1`）变化属于设计行为，需重新采集指纹、重新签发 |
| daemon 页面指纹与签发不一致 | 签发后机器换过 `--instance-id` 或锚点来源变化 |

---

## 6. 安全边界提醒

- `agentos-license-daemon` / `agentos-license-checker` 是**部署侧**产物，只含验签公钥路径，**不含任何签发能力**；私钥只在供应商内网的 `tools/license-issuer`（TS）中使用，绝不随部署包交付。
- 篡改本地账本只能触发 exit 3（拒绝服务自己），不能伪造运行时长：账本 HMAC 密钥由 `HKDF(license 签名, salt=机器指纹)` 派生，没有原始 license 文件无法重算。
