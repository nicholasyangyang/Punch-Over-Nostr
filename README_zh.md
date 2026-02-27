# Punch Over Nostr

[English](README.md)

一个基于 Nostr 网络进行 UDP 打洞并建立 SSH 隧道的工具。使用 Nostr 加密私信进行信令交换，并实现 ARQ（自动重传请求）机制保证 UDP 可靠传输。

## 功能特性

- **UDP 打洞**: 使用 STUN 协议实现 NAT 穿透
- **Nostr 信令**: 通过 Nostr 加密私信（NIP-04）交换连接信息
- **SSH 隧道**: 透明的 SSH 代理，通过打洞后的 UDP 隧道传输
- **ARQ 可靠传输**: 自动重传、确认机制、乱序重排
- **代理支持**: 支持通过环境变量配置 HTTPS/SOCKS 代理

## 系统要求

- Python 3.7+
- 依赖安装:
  ```bash
  pip install aiohttp secp256k1 cryptography
  ```

## 使用方法

### 服务端

在有 SSH 服务的主机上运行：

```bash
python main.py server [--nsec nsec1...] [--ssh-host 127.0.0.1] [--ssh-port 22]
```

参数说明：
- `--nsec`: Nostr 私钥（nsec1... 格式）。如不提供，将自动生成新密钥对
- `--ssh-host`: SSH 服务器地址（默认：127.0.0.1）
- `--ssh-port`: SSH 服务器端口（默认：22）

服务端启动后会显示 `npub`（公钥），需要将其分享给客户端。

### 客户端

在本地主机上运行：

```bash
python main.py client --peer <server_npub> [--nsec nsec1...] [--listen-port 2222]
```

参数说明：
- `--peer`: 服务端的 npub（必填）
- `--nsec`: Nostr 私钥（可选，不提供则自动生成）
- `--listen-port`: 本地监听端口（默认：2222）

### SSH 连接

隧道建立成功后，通过以下命令连接远程 SSH：

```bash
ssh -p 2222 用户名@localhost
```

### 调试模式

添加 `--debug` 参数查看详细日志：

```bash
python main.py server --debug
python main.py client --peer <server_npub> --debug
```

## 工作原理

1. **STUN 探测**: 客户端和服务端通过 STUN 服务器获取各自的公网 IP:端口
2. **Nostr 信令**: 客户端通过 Nostr 私信发送 `hp_init` 消息（包含候选地址）；服务端回复 `hp_reply`（包含候选地址和打洞时间）
3. **UDP 打洞**: 双方在约定时间向对方的公网地址发送保活包
4. **隧道建立**: 打洞成功后，建立双向 UDP 隧道
5. **SSH 代理**: 客户端监听本地端口， incoming SSH 连接通过 ARQ 可靠传输的 UDP 隧道转发

## 协议说明

### UDP 数据包类型

| 类型 | 值 | 格式 |
|------|-------|--------|
| START | 0x00 | `[0x00][sid:4B LE]` |
| DATA | 0x01 | `[0x01][sid:4B LE][seq:4B LE][payload...]` |
| KA (保活) | 0x02 | `[0x02]` |
| CLOSE | 0x03 | `[0x03][sid:4B LE]` |
| ACK | 0x04 | `[0x04][sid:4B LE][seq:4B LE]` |

### ARQ 机制

- **发送方**: 缓存未确认的数据包，150ms 未收到 ACK 则重传
- **接收方**: 每收到 DATA 包发送 ACK，支持乱序重排
- **流量控制**: 最多允许 128 个数据包在途（发送窗口）

## Nostr 中继

默认使用的中继服务器：
- wss://relay.damus.io
- wss://nos.lol
- wss://nostr.oxtr.dev
- wss://relay.primal.net

## 密钥管理

密钥存储在 `.punch_key` 文件中，JSON 格式：

```json
{
  "nsec": "nsec1...",
  "npub": "npub1..."
}
```

**重要提示**: 请安全备份您的 nsec 私钥！

## 代理配置

通过环境变量配置代理：

```bash
export HTTPS_PROXY=http://127.0.0.1:7890
# 或
export ALL_PROXY=socks5://127.0.0.1:1080
```

## 许可证

[MIT](LICENSE)
