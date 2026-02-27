# Punch Over Nostr

[中文文档](README_zh.md)

A UDP hole punching tool that creates SSH tunnels over the Nostr network. It uses Nostr encrypted direct messages for signaling and implements ARQ (Automatic Repeat reQuest) for reliable UDP transmission.

## Features

- **UDP Hole Punching**: NAT traversal using STUN protocol
- **Nostr Signaling**: Exchange connection info via Nostr encrypted DMs (NIP-04)
- **SSH Tunneling**: Transparent SSH proxy through the punched UDP tunnel
- **ARQ Reliable Delivery**: Automatic retransmission, acknowledgment, and out-of-order packet reordering
- **Proxy Support**: Works with HTTPS/SOCKS proxies via environment variables

## Requirements

- Python 3.7+
- Dependencies:
  ```bash
  pip install aiohttp secp256k1 cryptography
  ```

## Usage

### Server Side

Run the server on the machine that has SSH access:

```bash
python main.py server [--nsec nsec1...] [--ssh-host 127.0.0.1] [--ssh-port 22]
```

Options:
- `--nsec`: Nostr private key (nsec1...). If not provided, a new keypair will be generated
- `--ssh-host`: SSH server host (default: 127.0.0.1)
- `--ssh-port`: SSH server port (default: 22)

The server will display its `npub` (public key) which needs to be shared with the client.

### Client Side

Run the client on your local machine:

```bash
python main.py client --peer <server_npub> [--nsec nsec1...] [--listen-port 2222]
```

Options:
- `--peer`: Server's npub (required)
- `--nsec`: Nostr private key (optional, auto-generated if not provided)
- `--listen-port`: Local port for SSH connection (default: 2222)

### Connect via SSH

Once the tunnel is established, connect to the remote SSH server:

```bash
ssh -p 2222 user@localhost
```

### Debug Mode

Add `--debug` flag for verbose output:

```bash
python main.py server --debug
python main.py client --peer <server_npub> --debug
```

## How It Works

1. **STUN Discovery**: Both client and server discover their public IP:port using STUN servers
2. **Nostr Signaling**: Client sends `hp_init` message with its candidates via Nostr DM; Server replies with `hp_reply` containing its candidates and punch timing
3. **UDP Hole Punching**: Both sides send keepalive packets to each other's public address at the agreed time
4. **Tunnel Establishment**: Once punching succeeds, a bidirectional UDP tunnel is formed
5. **SSH Proxy**: Client listens on localhost; incoming SSH connections are proxied through the UDP tunnel with ARQ reliability

## Protocol

### UDP Packet Types

| Type | Value | Format |
|------|-------|--------|
| START | 0x00 | `[0x00][sid:4B LE]` |
| DATA | 0x01 | `[0x01][sid:4B LE][seq:4B LE][payload...]` |
| KA (Keepalive) | 0x02 | `[0x02]` |
| CLOSE | 0x03 | `[0x03][sid:4B LE]` |
| ACK | 0x04 | `[0x04][sid:4B LE][seq:4B LE]` |

### ARQ Mechanism

- **Sender**: Buffers unacknowledged packets, retransmits after 150ms if no ACK received
- **Receiver**: Sends ACK for each DATA packet, reorders out-of-sequence packets
- **Flow Control**: Maximum 128 packets in flight (send window)

## Nostr Relays

Default relays:
- wss://relay.damus.io
- wss://nos.lol
- wss://nostr.oxtr.dev
- wss://relay.primal.net

## Key Management

Keys are stored in `.punch_key` file in JSON format:

```json
{
  "nsec": "nsec1...",
  "npub": "npub1..."
}
```

**Important**: Backup your nsec key securely!

## Proxy Configuration

Set environment variables for proxy support:

```bash
export HTTPS_PROXY=http://127.0.0.1:7890
# or
export ALL_PROXY=socks5://127.0.0.1:1080
```

## License

[MIT](LICENSE)
