# syntax=docker/dockerfile:1
# AgentOS License 运行时镜像（多架构：linux/amd64 + linux/arm64）
#
# 构建方式：本 Dockerfile 不编译 Rust。CI（.github/workflows/ci.yml 的 build job）
# 已在原生 runner 上为各架构编译好二进制并打包成 tar.gz，docker job 将其解压到
# 本目录的 bin/ 后，这里只做 COPY。因此同一个 Dockerfile 对两种架构通用：
# 架构差异由 CI 的构建矩阵保证，基础镜像会按构建机架构自动取对应变体。
#
# 本地手动构建：
#   cargo build --release
#   mkdir -p docker/bin && cp target/release/agentos-license-{daemon,checker} docker/bin/
#   docker build -t agentos-license:dev docker/
#
# 基础镜像选 ubuntu:24.04 而非 distroless/alpine：二进制是在 ubuntu-24.04 上用
# glibc 工具链编译的，发行版与 glibc 版本必须对齐（alpine 的 musl 直接不兼容，
# distroless 基于 Debian 12，glibc 比 24.04 旧，可能起不来）。
FROM ubuntu:24.04

# 预编译产物（CI 解压 tar.gz 得到；本地构建见上方注释）
COPY bin/agentos-license-daemon /usr/local/bin/agentos-license-daemon
COPY bin/agentos-license-checker /usr/local/bin/agentos-license-checker

# 默认入口为 daemon（指纹采集 + license 激活 HTTP 服务），参数按 README 2.1 节追加：
#   docker run --rm -p 8471:8471 <image> serve \
#     --state-dir /state --public-key-file /keys/xxx.public.json
#
# checker 用 --entrypoint 覆盖：
#   docker run --rm --entrypoint agentos-license-checker <image> status \
#     --state-dir /state --public-key-file /keys/xxx.public.json
#
# 指纹绑定要求（当前约定）：必选锚点 c1 = sha256(/etc/machine-id 内容)，采集点见
# crates/license-core/src/fingerprint.rs 的 probe_linux()——读的是容器内自己文件
# 系统的 /etc/machine-id。容器内该文件与宿主机不同（或不存在，导致 c1 unavailable），
# 直接激活会报 ERR_FINGERPRINT_MISMATCH。因此运行时**必须**把宿主机的 machine-id
# 只读挂载进来，保证"同一台机器上容器内外指纹一致、都能认证"：
#   docker run --rm -v /etc/machine-id:/etc/machine-id:ro ...
# 其余分量（dmi-* 等）均为可选，容器内通常显示 unavailable，不影响只绑定 c1 的 license。
ENTRYPOINT ["/usr/local/bin/agentos-license-daemon"]
CMD ["--help"]
