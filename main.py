#!/usr/bin/env python3
"""
Nostr UDP Hole Punch → SSH Tunnel  (ARQ reliable delivery)
pip install aiohttp secp256k1 cryptography

服务端:  python punch.py server [--nsec nsec1…] [--ssh-host 127.0.0.1] [--ssh-port 22]
客户端:  python punch.py client --peer <server_npub> [--nsec nsec1…] [--listen-port 2222]
         然后: ssh -p 2222 user@localhost

调试:    加 --debug
"""

import argparse, asyncio, base64, hashlib, json, os, secrets
import socket, ssl, struct, sys, time
from datetime import datetime

for _pkg in ["aiohttp", "secp256k1", "cryptography"]:
    try: __import__(_pkg)
    except ImportError: sys.exit(f"pip install {_pkg}")

import aiohttp, secp256k1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ── 日志 ──────────────────────────────────────────────────────────────────────

DEBUG = False

def log(msg): print(f"  [{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}", flush=True)
def dbg(msg):
    if DEBUG: log(f"DBG {msg}")

# ── bech32 ────────────────────────────────────────────────────────────────────

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CMAP    = {c: i for i, c in enumerate(_CHARSET)}
_GEN     = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

def _polymod(vals):
    c = 1
    for v in vals:
        b = c >> 25; c = (c & 0x1ffffff) << 5 ^ v
        for i in range(5): c ^= _GEN[i] if (b >> i) & 1 else 0
    return c

def _hrp_expand(h): return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]

def _convertbits(data, frm, to, pad=True):
    acc = bits = 0; out = []; maxv = (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v; bits += frm
        while bits >= to: bits -= to; out.append((acc >> bits) & maxv)
    if pad and bits: out.append((acc << (to - bits)) & maxv)
    return out

def bech32_encode(hrp, data):
    d = _convertbits(data, 8, 5)
    p = _polymod(_hrp_expand(hrp) + d + [0]*6) ^ 1
    return hrp + "1" + "".join(_CHARSET[x] for x in d + [(p >> 5*(5-i)) & 31 for i in range(6)])

def bech32_decode(s):
    s = s.lower(); p = s.rfind("1"); hrp = s[:p]
    d = [_CMAP[c] for c in s[p+1:]]
    assert _polymod(_hrp_expand(hrp) + d) == 1, "bad checksum"
    return hrp, bytes(_convertbits(d[:-6], 5, 8, pad=False))

def to_npub(h):  return bech32_encode("npub", bytes.fromhex(h))
def to_nsec(h):  return bech32_encode("nsec", bytes.fromhex(h))
def npub2hex(s): hrp, b = bech32_decode(s); assert hrp == "npub"; return b.hex()
def nsec2hex(s): hrp, b = bech32_decode(s); assert hrp == "nsec"; return b.hex()

# ── Nostr 密钥 / 签名 ─────────────────────────────────────────────────────────

def gen_keys():
    raw = secrets.token_bytes(32)
    return raw.hex(), secp256k1.PrivateKey(raw).pubkey.serialize()[1:].hex()

def derive_pub(priv_hex):
    return secp256k1.PrivateKey(bytes.fromhex(priv_hex)).pubkey.serialize()[1:].hex()

def schnorr_sign(eid_hex, priv_hex):
    return secp256k1.PrivateKey(bytes.fromhex(priv_hex)).schnorr_sign(
        bytes.fromhex(eid_hex), None, raw=True).hex()

def ecdh_shared(priv_hex, pub_hex):
    pk = secp256k1.PublicKey(bytes.fromhex("02" + pub_hex), raw=True)
    return pk.tweak_mul(
        secp256k1.PrivateKey(bytes.fromhex(priv_hex)).private_key
    ).serialize(compressed=True)[1:]

def nip04_encrypt(text, priv_hex, peer_pub_hex):
    key = ecdh_shared(priv_hex, peer_pub_hex); iv = secrets.token_bytes(16)
    d   = text.encode(); pad = 16 - len(d) % 16; d += bytes([pad] * pad)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    return base64.b64encode(enc.update(d) + enc.finalize()).decode() + \
           "?iv=" + base64.b64encode(iv).decode()

def nip04_decrypt(payload, priv_hex, peer_pub_hex):
    try:
        ct_b64, iv_b64 = payload.split("?iv=")
        key = ecdh_shared(priv_hex, peer_pub_hex)
        dec = Cipher(algorithms.AES(key), modes.CBC(base64.b64decode(iv_b64)),
                     backend=default_backend()).decryptor()
        d = dec.update(base64.b64decode(ct_b64)) + dec.finalize()
        return d[:-d[-1]].decode()
    except Exception: return None

def make_event(kind, content, priv_hex, pub_hex, tags=None):
    ev = {"pubkey": pub_hex, "created_at": int(time.time()),
          "kind": kind, "tags": tags or [], "content": content}
    s  = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"],
                     ev["tags"], ev["content"]],
                    separators=(",", ":"), ensure_ascii=False)
    ev["id"]  = hashlib.sha256(s.encode()).hexdigest()
    ev["sig"] = schnorr_sign(ev["id"], priv_hex)
    return ev

# ── STUN ──────────────────────────────────────────────────────────────────────

STUN_SERVERS = [
    ("stun.l.google.com",   19302),
    ("stun1.l.google.com",  19302),
    ("stun.cloudflare.com", 3478),
]
_STUN_MAGIC = 0x2112A442

def stun_discover(sock) -> tuple:
    tid = secrets.token_bytes(12)
    req = struct.pack(">HHI", 0x0001, 0, _STUN_MAGIC) + tid
    for host, port in STUN_SERVERS:
        try:
            addr = (socket.gethostbyname(host), port)
            sock.settimeout(3); sock.sendto(req, addr)
            data, _ = sock.recvfrom(1024); sock.settimeout(None)
            if len(data) < 20: continue
            mtype, _, magic = struct.unpack(">HHI", data[:8])
            if mtype != 0x0101 or magic != _STUN_MAGIC: continue
            off = 20
            while off + 4 <= len(data):
                atype, alen = struct.unpack(">HH", data[off:off+4])
                val = data[off+4:off+4+alen]
                if atype == 0x0020 and alen >= 8 and val[1] == 0x01:
                    xport = struct.unpack(">H", val[2:4])[0] ^ (_STUN_MAGIC >> 16)
                    xip   = struct.unpack(">I", val[4:8])[0] ^ _STUN_MAGIC
                    return socket.inet_ntoa(struct.pack(">I", xip)), xport
                off += 4 + alen + (4 - alen % 4) % 4
        except Exception as e: log(f"STUN {host} failed: {e}")
    raise RuntimeError("all STUN servers failed")

# ── Nostr 信令 ────────────────────────────────────────────────────────────────

RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
]
PROXY    = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or
            os.environ.get("ALL_PROXY")   or os.environ.get("all_proxy"))
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


class NostrSignal:
    def __init__(self, priv_hex, pub_hex):
        self._priv  = priv_hex; self._pub = pub_hex
        self._t0    = int(time.time())
        self._seen  : set  = set()
        self._ws    : list = []
        self._states: dict = {u: "connecting" for u in RELAYS}
        self._cb    = None; self._sess = None; self._tasks: list = []

    def on_message(self, cb): self._cb = cb

    async def start(self):
        kw = {"timeout": aiohttp.ClientTimeout(total=60, connect=10)}
        if PROXY: kw["connector"] = aiohttp.TCPConnector(ssl=_SSL_CTX)
        self._sess  = aiohttp.ClientSession(**kw)
        self._tasks = [asyncio.create_task(self._connect(u)) for u in RELAYS]
        await asyncio.sleep(2)
        ok = sum(1 for s in self._states.values() if s == "connected")
        log(f"relay {ok}/{len(RELAYS)} connected  ({'proxy=' + PROXY if PROXY else 'no proxy'})")

    async def stop(self):
        for t in self._tasks: t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for ws in self._ws:
            try: await ws.close()
            except Exception: pass
        if self._sess and not self._sess.closed:
            await self._sess.close()

    async def send_dm(self, to_pub_hex, data: dict) -> int:
        enc = nip04_encrypt(json.dumps(data), self._priv, to_pub_hex)
        ev  = make_event(4, enc, self._priv, self._pub, [["p", to_pub_hex]])
        msg = json.dumps(["EVENT", ev]); ok = 0
        for ws in list(self._ws):
            try: await ws.send_str(msg); ok += 1
            except Exception: pass
        return ok

    async def _connect(self, url):
        ws_kw = {"ssl": _SSL_CTX}
        if PROXY: ws_kw["proxy"] = PROXY
        backoff = 2
        while True:
            try:
                async with self._sess.ws_connect(url, **ws_kw) as ws:
                    self._ws.append(ws); self._states[url] = "connected"
                    log(f"relay connected    {url.replace('wss://','')}")
                    backoff = 2
                    sid = secrets.token_hex(8)
                    await ws.send_str(json.dumps(
                        ["REQ", sid, {"kinds": [4], "#p": [self._pub],
                                      "since": self._t0, "limit": 0}]))
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT: await self._handle(msg.data)
                        elif msg.type in (aiohttp.WSMsgType.ERROR,
                                          aiohttp.WSMsgType.CLOSED): break
            except asyncio.CancelledError:
                self._states[url] = "disconnected"; return
            except Exception as e:
                log(f"relay error        {url.replace('wss://','')}: {e}")
            finally:
                self._ws = [w for w in self._ws if not w.closed]
                self._states[url] = "disconnected"
            log(f"relay retry        {url.replace('wss://','')} in {backoff}s")
            await asyncio.sleep(backoff); backoff = min(backoff * 2, 60)

    async def _handle(self, raw):
        try: msg = json.loads(raw)
        except Exception: return
        if not (isinstance(msg, list) and len(msg) >= 3 and msg[0] == "EVENT"): return
        ev = msg[2]; eid = ev.get("id", "")
        if eid in self._seen: return
        self._seen.add(eid)
        if ev.get("kind") != 4: return
        sender = ev.get("pubkey", "")
        if sender == self._pub: return
        text = nip04_decrypt(ev.get("content", ""), self._priv, sender)
        if not text: return
        try: data = json.loads(text)
        except Exception: return
        if self._cb: await self._cb(sender, data)

# ── UDP 隧道协议 ───────────────────────────────────────────────────────────────
#
# 包格式:
#   START [0x00][sid:4B LE]
#   DATA  [0x01][sid:4B LE][seq:4B LE][payload…]
#   KA    [0x02]
#   CLOSE [0x03][sid:4B LE]
#   ACK   [0x04][sid:4B LE][seq:4B LE]   ← NEW: 确认收到 DATA(seq)
#
# ARQ 机制：
#   发送方：缓存所有未被 ACK 的包，每 RETX_DELAY 秒重传一次
#   接收方：每收到一个 DATA 包就发一个 ACK，支持乱序重排

PKT_START = 0
PKT_DATA  = 1
PKT_KA    = 2
PKT_CLOSE = 3
PKT_ACK   = 4

PKT_NAMES    = {0:"START", 1:"DATA", 2:"KA", 3:"CLOSE", 4:"ACK"}
MAX_CHUNK    = 16384
SEND_WINDOW  = 128    # 最多允许 128 个包未被 ACK
RETX_DELAY   = 0.15  # 150ms 未 ACK 就重传
REORDER_WIN  = 512   # 乱序缓冲区上限（有 ARQ 后基本不会触发）

def pkt_start(sid):              return struct.pack("<BI",  PKT_START, sid)
def pkt_data(sid, seq, payload): return struct.pack("<BII", PKT_DATA,  sid, seq) + payload
def pkt_ka():                    return bytes([PKT_KA])
def pkt_close(sid):              return struct.pack("<BI",  PKT_CLOSE, sid)
def pkt_ack(sid, seq):           return struct.pack("<BII", PKT_ACK,   sid, seq)

def pkt_parse(data):
    if not data: return None, 0, 0, b""
    t = data[0]
    if t == PKT_START and len(data) >= 5:
        return PKT_START, struct.unpack("<I",  data[1:5])[0], 0, b""
    if t == PKT_DATA  and len(data) >= 9:
        sid, seq = struct.unpack("<II", data[1:9])
        return PKT_DATA, sid, seq, data[9:]
    if t == PKT_KA:
        return PKT_KA, 0, 0, b""
    if t == PKT_CLOSE and len(data) >= 5:
        return PKT_CLOSE, struct.unpack("<I",  data[1:5])[0], 0, b""
    if t == PKT_ACK   and len(data) >= 9:
        sid, seq = struct.unpack("<II", data[1:9])
        return PKT_ACK, sid, seq, b""
    return None, 0, 0, b""


class UDPTunnel(asyncio.DatagramProtocol):

    def __init__(self, tag=""):
        self.transport = None
        self.peer      = None
        self._q        = asyncio.Queue()    # DATA / CLOSE / START / KA
        self._ack_q    = asyncio.Queue()    # ACK (sid, seq)
        self._punched  = asyncio.Event()
        self._tag      = tag
        self._rx = self._tx = 0

    def connection_made(self, t): self.transport = t

    def datagram_received(self, data, addr):
        t, sid, seq, payload = pkt_parse(data)
        self._rx += 1
        dbg(f"[{self._tag}] RX {PKT_NAMES.get(t,'?')} sid={sid} seq={seq} len={len(payload)}")
        if not self._punched.is_set() and t == PKT_KA:
            self.peer = addr; self._punched.set()
            log(f"punch success      {addr[0]}:{addr[1]}")
            return
        if t == PKT_ACK:
            self._ack_q.put_nowait((sid, seq))
        else:
            self._q.put_nowait((t, sid, seq, payload))

    def error_received(self, e): log(f"UDP error: {e}")
    def connection_lost(self, e): log(f"UDP connection lost: {e}")

    def _raw(self, data, lbl=""):
        if self.transport and self.peer:
            try:
                self.transport.sendto(data, self.peer)
                self._tx += 1
                dbg(f"[{self._tag}] TX {lbl}")
            except Exception as e: log(f"UDP send error: {e}")

    def send_start(self, sid):
        log(f"[{self._tag}] send START sid={sid}")
        self._raw(pkt_start(sid), f"START sid={sid}")

    def send_data(self, sid, seq, pl):
        dbg(f"[{self._tag}] send DATA sid={sid} seq={seq} len={len(pl)}")
        self._raw(pkt_data(sid, seq, pl), f"DATA sid={sid} seq={seq}")

    def send_ka(self):
        self._raw(pkt_ka(), "KA")

    def send_close(self, sid):
        log(f"[{self._tag}] send CLOSE sid={sid}")
        self._raw(pkt_close(sid), f"CLOSE sid={sid}")

    def send_ack(self, sid, seq):
        dbg(f"[{self._tag}] send ACK sid={sid} seq={seq}")
        self._raw(pkt_ack(sid, seq), f"ACK sid={sid} seq={seq}")

    async def recv(self):      return await self._q.get()
    async def recv_ack(self):  return await self._ack_q.get()

    def drain(self):
        n = 0
        while not self._q.empty():
            try: self._q.get_nowait(); n += 1
            except asyncio.QueueEmpty: break
        # also drain stale ACKs
        while not self._ack_q.empty():
            try: self._ack_q.get_nowait()
            except asyncio.QueueEmpty: break
        if n: log(f"[{self._tag}] drained {n} stale packet(s)")

    def stats(self):
        return f"rx={self._rx} tx={self._tx} q={self._q.qsize()}"

    async def punch(self, peer_ip, peer_port, punch_at) -> bool:
        self.peer = (peer_ip, peer_port)
        delay = punch_at - time.time()
        if delay > 0:
            log(f"waiting for punch  T-{delay:.1f}s"); await asyncio.sleep(delay)
        log(f"punching           {peer_ip}:{peer_port}")
        deadline = time.time() + 30
        while time.time() < deadline:
            try: self.transport.sendto(pkt_ka(), (peer_ip, peer_port))
            except Exception: pass
            try:
                await asyncio.wait_for(self._punched.wait(), timeout=0.15)
                return True
            except asyncio.TimeoutError: pass
        log("punch timeout"); return False


# ── ARQ 发送：TCP → UDP ────────────────────────────────────────────────────────
# 读 TCP → 发 UDP DATA → 等 ACK → 超时重传 → 收到 CLOSE 停止

async def pipe_tcp_to_udp(reader: asyncio.StreamReader,
                           tunnel: UDPTunnel,
                           sid: int,
                           stop: asyncio.Event,
                           label: str = ""):
    seq      = 0
    send_buf : dict = {}    # seq -> (payload, last_sent_time)
    win_ev   = asyncio.Event(); win_ev.set()

    async def retransmit_loop():
        while not stop.is_set():
            await asyncio.sleep(0.05)
            now = time.time(); retx = 0
            for s, (pl, t_sent) in list(send_buf.items()):
                if now - t_sent > RETX_DELAY:
                    tunnel.send_data(sid, s, pl)
                    send_buf[s] = (pl, now); retx += 1
            if retx: dbg(f"pipe_tcp_to_udp [{label}] retx {retx} pkts unacked={len(send_buf)}")

    async def ack_loop():
        while not stop.is_set():
            try: ack_sid, ack_seq = await asyncio.wait_for(tunnel.recv_ack(), 1.0)
            except asyncio.TimeoutError: continue
            if ack_sid != sid: continue
            send_buf.pop(ack_seq, None)
            if len(send_buf) < SEND_WINDOW: win_ev.set()

    retx_task = asyncio.create_task(retransmit_loop())
    ack_task  = asyncio.create_task(ack_loop())
    log(f"pipe_tcp_to_udp  start  [{label}] sid={sid}")
    try:
        while not stop.is_set():
            # 流量控制：窗口满时等待 ACK
            if len(send_buf) >= SEND_WINDOW:
                win_ev.clear()
                try: await asyncio.wait_for(win_ev.wait(), 5.0)
                except asyncio.TimeoutError:
                    log(f"pipe_tcp_to_udp [{label}] window stall — closing"); break

            try: data = await asyncio.wait_for(reader.read(MAX_CHUNK), 1.0)
            except asyncio.TimeoutError: continue
            if not data:
                log(f"pipe_tcp_to_udp  EOF   [{label}] sid={sid} seq={seq}"); break

            now = time.time()
            tunnel.send_data(sid, seq, data)
            send_buf[seq] = (data, now)
            seq = (seq + 1) & 0xFFFFFFFF

    except Exception as e:
        log(f"pipe_tcp_to_udp  error [{label}] sid={sid}: {e}")
    finally:
        retx_task.cancel(); ack_task.cancel()
        await asyncio.gather(retx_task, ack_task, return_exceptions=True)
        log(f"pipe_tcp_to_udp  end   [{label}] sid={sid} seq={seq}  setting stop")
        tunnel.send_close(sid); stop.set()


# ── ARQ 接收：UDP → TCP ────────────────────────────────────────────────────────
# 收 UDP DATA → 发 ACK → 乱序重排 → 按序写 TCP
# sid=None 时自动学习对端 sid（客户端使用）

async def pipe_udp_to_tcp(tunnel: UDPTunnel,
                           writer: asyncio.StreamWriter,
                           sid,           # int 或 None（自动学习）
                           stop: asyncio.Event,
                           label: str = ""):
    next_seq     = 0
    buf   : dict = {}
    expected_sid = sid    # None 表示待学习

    log(f"pipe_udp_to_tcp  start  [{label}] sid={sid if sid else 'auto'}")
    try:
        while not stop.is_set():
            try: t, pkt_sid, seq, payload = await asyncio.wait_for(tunnel.recv(), 1.0)
            except asyncio.TimeoutError: continue

            if t == PKT_KA: continue

            if t == PKT_CLOSE:
                if expected_sid and pkt_sid == expected_sid:
                    log(f"pipe_udp_to_tcp  CLOSE  [{label}]"); break
                dbg(f"pipe_udp_to_tcp [{label}] stale CLOSE pkt_sid={pkt_sid}, drop")
                continue

            if t != PKT_DATA: continue

            # 自动学习对端 sid
            if expected_sid is None:
                expected_sid = pkt_sid
                log(f"pipe_udp_to_tcp  [{label}] learned sid={expected_sid}")

            if pkt_sid != expected_sid:
                dbg(f"pipe_udp_to_tcp [{label}] stale DATA pkt_sid={pkt_sid} expected={expected_sid}, drop")
                continue

            # 发 ACK（立刻，无论是否乱序）
            tunnel.send_ack(pkt_sid, seq)

            # 重复包直接丢弃
            if seq < next_seq or seq in buf:
                dbg(f"pipe_udp_to_tcp [{label}] dup seq={seq} next={next_seq}, drop")
                continue

            buf[seq] = payload
            flushed = 0
            while next_seq in buf:
                writer.write(buf.pop(next_seq))
                next_seq = (next_seq + 1) & 0xFFFFFFFF
                flushed += 1
            if flushed: await writer.drain()

            if len(buf) > REORDER_WIN:
                # 有 ARQ 的情况下不应发生；若发生说明链路极差，关闭会话
                log(f"pipe_udp_to_tcp [{label}] reorder buf overflow ({len(buf)}) — closing session")
                break

    except Exception as e:
        log(f"pipe_udp_to_tcp  error [{label}]: {e}")
    finally:
        log(f"pipe_udp_to_tcp  end   [{label}] next_seq={next_seq} buf={len(buf)}  setting stop")
        stop.set()
        try: writer.close(); await writer.wait_closed()
        except Exception: pass


# ── 工具 ──────────────────────────────────────────────────────────────────────

def make_udp_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", 0))
    return s

async def create_tunnel(sock: socket.socket, tag="") -> UDPTunnel:
    sock.setblocking(False)
    tunnel = UDPTunnel(tag=tag)
    await asyncio.get_event_loop().create_datagram_endpoint(lambda: tunnel, sock=sock)
    return tunnel

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: return "127.0.0.1"

def new_sid() -> int: return secrets.randbelow(0xFFFFFFFE) + 1


# ── 服务端 ────────────────────────────────────────────────────────────────────

async def run_server(priv, pub, ssh_host, ssh_port):
    print(f"\n⚡ Punch Server")
    print(f"   npub   : {to_npub(pub)}")
    print(f"   SSH    : {ssh_host}:{ssh_port}")
    print(f"   proxy  : {PROXY or 'none'}")
    print(f"   debug  : {'on' if DEBUG else 'off'}\n")

    sock = make_udp_socket()
    log(f"UDP local port     {sock.getsockname()[1]}")
    log("STUN discovering…")
    pub_ip, pub_port = stun_discover(sock)
    log(f"public address     {pub_ip}:{pub_port}")

    tunnel = await create_tunnel(sock, tag="server")

    sig = NostrSignal(priv, pub)
    await sig.start()

    punch_done = asyncio.Event()

    async def on_signal(sender, data):
        if data.get("type") != "hp_init": return
        nostr_sid = data.get("session_id", "")
        cands = data.get("candidates", [])
        if not cands: return
        cand = next((c for c in cands if c.get("ctype") == "srflx"), cands[0])
        peer_ip, peer_port_c = cand["ip"], int(cand["port"])
        log(f"client             {to_npub(sender)[:32]}…")
        log(f"client candidate   {peer_ip}:{peer_port_c}")
        punch_at = time.time() + 6
        sent = await sig.send_dm(sender, {
            "type": "hp_reply", "session_id": nostr_sid,
            "candidates": [{"ip": pub_ip, "port": pub_port, "ctype": "srflx"}],
            "punch_at": punch_at,
        })
        log(f"hp_reply sent      ({sent} relays)")
        ok = await tunnel.punch(peer_ip, peer_port_c, punch_at)
        if ok: punch_done.set()

    sig.on_message(on_signal)
    log("waiting for client…  share npub:")
    print(f"\n  {to_npub(pub)}\n")

    try: await asyncio.wait_for(punch_done.wait(), timeout=300)
    except asyncio.TimeoutError:
        log("timeout waiting for client"); await sig.stop(); return

    await sig.stop()
    log("tunnel up — ready for SSH sessions")

    session_n = 0
    while True:
        log(f"waiting for START…  {tunnel.stats()}")
        tunnel.drain()

        cli_sid = None
        while True:
            t, pkt_sid, _, _ = await tunnel.recv()
            if t == PKT_START: cli_sid = pkt_sid; log(f"got START cli_sid={cli_sid}"); break
            dbg(f"pre-session: {PKT_NAMES.get(t,'?')} sid={pkt_sid}, waiting for START")

        session_n += 1
        log(f"SSH session #{session_n} start  cli_sid={cli_sid}")

        try: reader, writer = await asyncio.open_connection(ssh_host, ssh_port)
        except Exception as e:
            log(f"SSH connect failed: {e}"); tunnel.send_close(cli_sid); continue

        srv_sid = new_sid()
        log(f"SSH session #{session_n} sids   cli_sid={cli_sid} srv_sid={srv_sid}")
        stop = asyncio.Event()
        await asyncio.gather(
            pipe_tcp_to_udp(reader, tunnel, srv_sid, stop, label=f"srv#{session_n}"),
            pipe_udp_to_tcp(tunnel, writer,  cli_sid, stop, label=f"srv#{session_n}"),
        )
        log(f"SSH session #{session_n} end    {tunnel.stats()}")


# ── 客户端 ────────────────────────────────────────────────────────────────────

async def run_client(priv, pub, server_npub, listen_port):
    server_pub = npub2hex(server_npub)
    print(f"\n⚡ Punch Client")
    print(f"   npub   : {to_npub(pub)}")
    print(f"   server : {server_npub[:40]}…")
    print(f"   listen : localhost:{listen_port}")
    print(f"   proxy  : {PROXY or 'none'}")
    print(f"   debug  : {'on' if DEBUG else 'off'}\n")

    sock = make_udp_socket()
    log(f"UDP local port     {sock.getsockname()[1]}")
    log("STUN discovering…")
    pub_ip, pub_port = stun_discover(sock)
    log(f"public address     {pub_ip}:{pub_port}")

    tunnel = await create_tunnel(sock, tag="client")

    sig = NostrSignal(priv, pub)
    await sig.start()

    nostr_sid = secrets.token_hex(8)
    #wait realy connected
    time.sleep(5)
    sent = await sig.send_dm(server_pub, {
        "type": "hp_init", "session_id": nostr_sid,
        "candidates": [
            {"ip": pub_ip,        "port": pub_port,             "ctype": "srflx"},
            {"ip": get_local_ip(), "port": sock.getsockname()[1], "ctype": "host"},
        ],
    })
    log(f"hp_init sent       ({sent} relays), waiting for reply…")

    punch_done = asyncio.Event()

    async def on_signal(sender, data):
        if sender != server_pub:                return
        if data.get("type") != "hp_reply":      return
        if data.get("session_id") != nostr_sid: return
        cands = data.get("candidates", [])
        if not cands: return
        cand = next((c for c in cands if c.get("ctype") == "srflx"), cands[0])
        peer_ip, peer_port_s = cand["ip"], int(cand["port"])
        punch_at = max(float(data.get("punch_at", 0)), time.time() + 1)
        log(f"server candidate   {peer_ip}:{peer_port_s}")
        ok = await tunnel.punch(peer_ip, peer_port_s, punch_at)
        if ok: punch_done.set()

    sig.on_message(on_signal)

    try: await asyncio.wait_for(punch_done.wait(), timeout=60)
    except asyncio.TimeoutError:
        log("punch failed"); await sig.stop(); return

    await sig.stop()
    log("tunnel up")
    print(f"\n  ssh -p {listen_port} user@localhost\n")

    _lock    = asyncio.Lock()
    session_n = 0

    async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        nonlocal session_n
        async with _lock:
            session_n += 1; snum = session_n
            addr    = writer.get_extra_info("peername")
            cli_sid = new_sid()
            log(f"SSH session #{snum} start  {addr[0]}:{addr[1]}  cli_sid={cli_sid}")
            log(f"tunnel stats before drain: {tunnel.stats()}")
            tunnel.drain()

            # 通知服务端新会话开始（服务端收到后连接 SSH，SSH server 发 banner）
            tunnel.send_start(cli_sid)

            stop = asyncio.Event()
            await asyncio.gather(
                pipe_tcp_to_udp(reader, tunnel, cli_sid, stop, label=f"cli#{snum}"),
                # sid=None：自动学习服务端 srv_sid
                pipe_udp_to_tcp(tunnel, writer,  None,    stop, label=f"cli#{snum}"),
            )
            log(f"SSH session #{snum} end    {addr[0]}:{addr[1]}  {tunnel.stats()}")

    async def keepalive():
        while True:
            await asyncio.sleep(15); tunnel.send_ka()

    ka  = asyncio.create_task(keepalive())
    srv = await asyncio.start_server(handle_ssh, "127.0.0.1", listen_port)
    try:
        async with srv: await srv.serve_forever()
    except asyncio.CancelledError: pass
    finally:
        ka.cancel()
        try: await ka
        except asyncio.CancelledError: pass


# ── 密钥管理 ──────────────────────────────────────────────────────────────────

KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".punch_key")

def load_key(nsec_arg=None):
    if nsec_arg:
        try:
            priv = nsec2hex(nsec_arg) if nsec_arg.startswith("nsec1") else nsec_arg
            assert len(bytes.fromhex(priv)) == 32
            return priv, derive_pub(priv)
        except Exception as e: sys.exit(f"invalid key: {e}")
    if os.path.exists(KEY_FILE):
        try:
            d = json.load(open(KEY_FILE))
            priv = nsec2hex(d["nsec"]); pub = derive_pub(priv)
            log(f"key loaded         {to_npub(pub)[:32]}…"); return priv, pub
        except Exception: pass
    priv, pub = gen_keys()
    json.dump({"nsec": to_nsec(priv), "npub": to_npub(pub)}, open(KEY_FILE, "w"))
    log(f"new keypair        {to_npub(pub)}")
    log(f"nsec (backup!)     {to_nsec(priv)}")
    return priv, pub


# ── 入口 ──────────────────────────────────────────────────────────────────────

def main():
    global DEBUG
    ap  = argparse.ArgumentParser(description="Nostr UDP punch → SSH tunnel")
    ap.add_argument("--debug", action="store_true")
    sub = ap.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("server")
    sp.add_argument("--nsec",     default=None)
    sp.add_argument("--ssh-host", default="127.0.0.1")
    sp.add_argument("--ssh-port", type=int, default=22)

    cp = sub.add_parser("client")
    cp.add_argument("--peer",        required=True)
    cp.add_argument("--nsec",        default=None)
    cp.add_argument("--listen-port", type=int, default=2222)

    args = ap.parse_args()
    DEBUG = args.debug
    priv, pub = load_key(getattr(args, "nsec", None))

    try:
        if args.mode == "server":
            asyncio.run(run_server(priv, pub, args.ssh_host, args.ssh_port))
        else:
            asyncio.run(run_client(priv, pub, args.peer, args.listen_port))
    except KeyboardInterrupt:
        print("\n  bye")

if __name__ == "__main__":
    main()