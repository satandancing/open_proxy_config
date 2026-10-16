# open_proxy_config

将 **VPN Gate**、**Cloudflare WARP（个人免费）** 与 **公开免费节点订阅** 聚合为一份适用于 **Clash Verge Rev / Mihomo** 的统一配置，并通过 GitHub Actions 定时构建发布到 `dist` 分支。

## 功能

- 可插拔数据源（`config.yaml` 中单独启用/禁用）：
  - **VPN Gate**：抓取 [官方 CSV API](https://www.vpngate.net/api/iphone/)，解析 OpenVPN 配置，生成 Mihomo `type: openvpn` 节点；同时在 `dist/ovpn/` 导出原始 `.ovpn` 备用（部分客户端不支持 OpenVPN 出站）。
  - **WARP**：通过 Cloudflare 公开注册 API 生成 `type: wireguard` 节点；私钥与设备令牌**绝不写入仓库**（见下文安全说明）。
  - **聚合源**：可配置多个公开订阅 URL（Base64 列表 / Clash YAML / `ss`/`vmess`/`vless`/`trojan`/`hysteria2` URI），解析后去重。
- **校验**：L1 字段语法检查；L3 使用固定版本 Mihomo 二进制，通过 REST API 对节点做真实 HTTPS 延迟探测（`generate_204`）。
- **失败保护**：若本轮无可用节点，**保留上一份** `.state.json` 快照，不会用空配置覆盖。
- **安全**：请求超时、响应大小上限、按主机限速、**禁止跟随重定向到内网/保留地址**（SSRF 防护）。

## 快速开始

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp config.example.yaml config.yaml   # 按需修改
python -m open_proxy_config build -c config.yaml
```

输出目录（默认 `./dist`）：

| 文件 | 说明 |
|------|------|
| `mihomo.yaml` | 完整 Mihomo 配置（分组、规则） |
| `provider.yaml` | 仅 `proxies` 列表，可作 Proxy Provider |
| `ovpn/*.ovpn` | VPN Gate 原始配置（可选） |

## 导入 Clash Verge Rev

1. 将本仓库 **`dist` 分支**设为可访问（公开仓库任何人可读；**私有仓库仅授权成员**可拉取 raw 链接）。
2. 在 Clash Verge Rev 中添加**配置订阅**或**远程配置**，URL 形如：

   `https://raw.githubusercontent.com/<owner>/open_proxy_config/dist/mihomo.yaml`

3. 更新间隔建议 ≥ 6 小时（与 Actions 计划任务一致）。

## WARP 凭据（必读）

以下敏感信息**不得提交到 Git**：

| 变量 | 说明 |
|------|------|
| `WARP_PRIVATE_KEY` | WireGuard 私钥（Base64） |
| `WARP_DEVICE_ID` | 注册返回的设备 ID |
| `WARP_ACCESS_TOKEN` | 注册返回的访问令牌 |

- **本地**：写入环境变量；或在 `output_dir` 下自动生成 `.warp-account.json`（已在 `.gitignore` 中忽略）。
- **GitHub Actions**：在仓库 **Secrets** 中配置上述三项；若未配置且 `register_if_missing: true`，工作流会在 runner 上临时注册（凭据仅存在于该次构建产物目录，不会进入 git 历史）。

> WARP 为 **个人免费 WARP** 注册流程，**不是** Cloudflare One / Zero Trust 企业设备自动发现。
>
> 注册 API 需使用当前客户端版本（本项目对齐 **wgcf v2 / API `v0a5641`**：`tos` 为 RFC3339 时间戳，并包含 `os_version` / `key_type` / `tunnel_type`）。旧版 `v0a2158` + 固定 `tos: 2022-11-02` 会返回 **HTTP 400 Invalid registration request**。

## 限制与兼容性

- **Shadowrocket** 等不支持 Mihomo `openvpn` 出站的客户端，请仅使用聚合源中的 SS/VMess 等节点，或单独导入 `ovpn` 文件到支持 OpenVPN 的应用。
- **公开免费节点**由第三方运营，可能存在窃听、劫持、恶意日志；**不要**用于银行、工作账号或任何敏感业务。
- VPN Gate 节点可用率波动大；OpenVPN 在 CI 中默认仅做 L1/L3 跳过（`skip_openvpn_l3`），以免超时。
- Mihomo OpenVPN 需要较新版本核心（本项目 CI 固定 **v1.19.32+**）；更旧二进制会报 `unsupport proxy type: openvpn`，请升级 Clash Verge Rev 内置 Mihomo。
- Mihomo OpenVPN 字段以 [官方文档](https://wiki.metacubex.one/en/config/proxies/openvpn/) 为准；本项目内联 PEM，不依赖本地证书路径。

## 开发与测试

```bash
pytest tests -m "not integration" -v          # 单元测试
pytest tests/test_integration_build.py -v   # 联网 + Mihomo 集成测试
```

## 许可证

MIT — 参考了社区项目的思路（如 VPNGate 订阅生成、WARP 注册、订阅解析与 Mihomo 测速流程），实现为本仓库独立代码，请同时遵守各上游项目许可证。

## 自动化

`.github/workflows/build-subscription.yml`：每 6 小时与手动 `workflow_dispatch` 触发，将 `dist/*` 推送到 **`dist` 分支**（非 `main`）。
