# GitHub Actions CI 参考说明

> 本文档为 CI 配置的参考材料（路径参考说明），不代表本仓库当前 CI 的实施范围。
> 当前生效的 workflow 为 `.github/workflows/ci.yml`；任何改动以实际沟通确认的需求为准。

下面以 GitHub Actions（GitHub 自带的 CI/CD 服务）为主线，从「怎么配 CI」到「怎么编译多环境、多 CPU 架构」分层说明。示例偏向 Linux x86_64 + aarch64（ARM64）双架构的场景。

---

## 一、GitHub CI 的基本配置方式

GitHub Actions 的配置就是仓库里的一个 YAML 文件，放在固定路径 `.github/workflows/` 下，例如 `.github/workflows/build.yml`。最小骨架：

```yaml
name: build

on:                      # 触发条件（trigger）
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:     # 允许手动触发

jobs:
  build:
    runs-on: ubuntu-latest   # 运行器（runner）：GitHub 提供的虚拟机
    steps:
      - uses: actions/checkout@v4        # 拉取代码
      - name: Build
        run: make build                  # 你的编译命令
      - uses: actions/upload-artifact@v4 # 把产物存为构件（artifact）
        with:
          name: my-binary
          path: dist/
```

要点：

- **`on`** 决定什么时候跑：推送（push）、合并请求（pull_request）、打标签（tag）、定时（schedule）、手动（workflow_dispatch）。
- **`runs-on`** 决定跑在什么机器上，这是多架构适配的关键，下面详述。
- **`steps`** 里 `uses` 调社区动作（action），`run` 直接执行 shell 命令。

---

## 二、不同环境的编译：matrix（矩阵）策略

要同时在多个 OS / 编译器版本 / 架构上编译，不要复制粘贴多个 job，用 `strategy.matrix`：

```yaml
jobs:
  build:
    strategy:
      fail-fast: false        # 一个组合失败不取消其他组合，便于看全结果
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [18, 20, 22]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm ci && npm run build
```

GitHub 会为矩阵的每个组合生成一个并行 job，互不干扰。矩阵变量用 `${{ matrix.xxx }}` 引用，也可以注入到环境变量或产物名里。

---

## 三、不同 CPU 架构的适配（重点）

有四条路线，按推荐程度排序：

### 路线 1：使用原生 ARM 运行器（native runner，最推荐）

GitHub 已提供 **ARM64 的 Linux 和 Windows 运行器**，公开仓库免费：

```yaml
jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - { runs-on: ubuntu-24.04,      arch: x64 }    # x86_64
          - { runs-on: ubuntu-24.04-arm,  arch: arm64 }  # aarch64 原生
    runs-on: ${{ matrix.runs-on }}
    steps:
      - uses: actions/checkout@v4
      - run: uname -m    # 验证：x64 输出 x86_64，arm runner 输出 aarch64
      - run: ./build.sh
      - uses: actions/upload-artifact@v4
        with:
          name: dist-${{ matrix.arch }}   # 产物名带架构后缀，避免互相覆盖
          path: dist/
```

原生编译速度最快、行为最真实（测试也是真机执行），能用就优先用。常见标签：

| 标签 | 架构 |
|---|---|
| `ubuntu-latest` / `ubuntu-24.04` | x86_64 |
| `ubuntu-24.04-arm` | ARM64 (aarch64) |
| `windows-11-arm` | Windows on ARM |
| `macos-latest`（macos-14 及以后） | Apple Silicon (ARM64) |
| `macos-13` | Intel x86_64 |

### 路线 2：交叉编译（cross-compilation，x86 机器上产出 ARM 产物）

当原生 ARM runner 不可用（如私有 runner 限制），或工具链本身就是交叉编译友好的时候用。

**C/C++（以 aarch64 为例）：**

```yaml
steps:
  - name: 安装交叉工具链
    run: sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
  - name: 交叉编译
    run: |
      aarch64-linux-gnu-gcc -o dist/myapp-arm64 src/main.c
      aarch64-linux-gnu-strip dist/myapp-arm64   # 可选：裁剪符号减小体积
```

用 CMake 时配 toolchain 文件指定 `CMAKE_SYSTEM_PROCESSOR=aarch64` 和交叉编译器前缀。

**Go（原生支持交叉编译，最简单）：**

```yaml
- run: GOOS=linux GOARCH=arm64 go build -o dist/myapp-linux-arm64 ./cmd/myapp
- run: GOOS=linux GOARCH=amd64 go build -o dist/myapp-linux-amd64 ./cmd/myapp
```

**Rust：**

```yaml
- uses: dtolnay/rust-toolchain@stable
  with:
    targets: aarch64-unknown-linux-gnu
- run: sudo apt-get install -y gcc-aarch64-linux-gnu
- run: cargo build --release --target aarch64-unknown-linux-gnu
  env:
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: aarch64-linux-gnu-gcc
```

注意交叉编译的坑：依赖系统库的 C 扩展（如 Node 的 node-gyp 原生模块、Python 的 cp312 轮子 wheel）需要**目标架构的 sysroot（系统根目录）和依赖库**，只换编译器往往不够。这也是要预先下载 arm64 版 `.deb`/`.rpm`/`.whl` 的原因之一——离线环境装不了，编译期链接的库版本也要对齐。

**Node.js / Python 这类"纯 JS/纯 Python + 少量原生模块"的项目**：纯代码本身跨架构，主要是把对应架构的原生依赖（如 `sharp`、`better-sqlite3`）装对。做法是按架构分 job 各自 `npm ci`，或交叉下载目标平台的预编译二进制。

### 路线 3：QEMU 模拟（emulation）+ Docker Buildx 多架构镜像

如果最终交付物是 Docker 镜像，标准做法是用 QEMU（CPU 指令模拟）+ Buildx（Docker 的多平台构建器）一次出多架构镜像：

```yaml
steps:
  - uses: docker/setup-qemu-action@v3      # 注册 arm64 等模拟器
  - uses: docker/setup-buildx-action@v3    # 启用 buildx
  - uses: docker/login-action@v3
    with:
      registry: ghcr.io
      username: ${{ github.actor }}
      password: ${{ secrets.GITHUB_TOKEN }}
  - uses: docker/build-push-action@v6
    with:
      platforms: linux/amd64,linux/arm64   # 一次构建两种架构
      push: true
      tags: ghcr.io/${{ github.repository }}:latest
```

推送后是一个 **manifest list（清单列表）**，用户 `docker pull` 时 Docker 自动按本机架构取对应镜像。

注意：QEMU 模拟比原生慢 5–20 倍，且个别指令集（如 AVX 相关）模拟可能出错。慢的缓解办法是**每个架构在原生 runner 上分别构建、再用 `docker buildx imagetools create` 合并 manifest**——即路线 1 和路线 3 的组合。

### 路线 4：自托管运行器（self-hosted runner）

如果目标环境特殊（比如要编译特定发行版的 rpm、要访问内网、要用你已有的 ARM 服务器），可以在自己的机器上装 GitHub 的 runner agent，然后用标签调度：

```yaml
runs-on: [self-hosted, linux, arm64]   # 只有打了这些标签的自有机器会接活
```

代价是自己维护机器和安全性（公开仓库慎用，fork 的 PR 可能在你的机器上跑恶意代码，建议只在私有仓库用）。

---

## 四、一个相对完整的实战示例

下面这个 workflow 模拟"Node 项目 + 双 Linux 架构打包 + 校验"的完整形态：

```yaml
name: multi-arch-release

on:
  push:
    tags: ['v*']          # 打 tag 才发版
  workflow_dispatch:

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - { runs-on: ubuntu-24.04,     arch: x64,   pkg: deb }
          - { runs-on: ubuntu-24.04-arm, arch: arm64, pkg: deb }
    runs-on: ${{ matrix.runs-on }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm

      - run: npm ci
      - run: npm run build
      - run: npm test                       # 原生 runner 上跑测试，结果可信

      - name: 打包并生成校验和
        run: |
          tar -czf dist/app-linux-${{ matrix.arch }}.tar.gz -C build .
          cd dist && sha256sum app-linux-${{ matrix.arch }}.tar.gz > app-linux-${{ matrix.arch }}.sha256

      - uses: actions/upload-artifact@v4
        with:
          name: app-linux-${{ matrix.arch }}
          path: dist/

  release:
    needs: build                            # 等全部架构构建完
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4  # 汇总所有架构的产物
        with:
          pattern: app-linux-*
          merge-multiple: true
          path: release/
      - uses: softprops/action-gh-release@v2
        with:
          files: release/*                  # 挂到 GitHub Release 页面
```

关键点回顾：

1. **矩阵 + `include`** 把"运行器 ↔ 架构"绑定起来，产物名带架构后缀防止覆盖。
2. **能原生就原生**（`ubuntu-24.04-arm`），交叉编译和 QEMU 是补充手段。
3. **测试要在目标架构上真跑**，交叉编译出的产物如果没在 ARM 机器上验证过，CI 绿了也可能在用户机器上崩。
4. **`needs` + artifact 传递** 组织"并行构建 → 汇总发布"的两阶段结构。
5. 如果交付物是容器镜像，改用 **Buildx 多平台构建**，或"原生构建 + manifest 合并"。
