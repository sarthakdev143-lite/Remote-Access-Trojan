"""
tunnel.py - Portmap.io global access via SSH reverse tunnel
Uses paramiko (pure Python SSH) instead of subprocess to avoid
Windows path/permission issues with the SSH binary.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import threading
from dataclasses import dataclass

log = logging.getLogger("tls_server.tunnel")


@dataclass
class TunnelConfig:
    enabled: bool = False
    key_file: str = ""
    username: str = ""
    remote_host: str = ""
    remote_port: int = 0
    local_port: int = 6767
    restart_delay: float = 10.0

    @classmethod
    def from_dict(cls, raw: dict) -> "TunnelConfig":
        c = cls()
        c.enabled       = raw.get("enabled",       c.enabled)
        c.key_file      = raw.get("key_file",       c.key_file)
        c.username      = raw.get("username",       c.username)
        c.remote_host   = raw.get("remote_host",    c.remote_host)
        c.remote_port   = raw.get("remote_port",    c.remote_port)
        c.local_port    = raw.get("local_port",     c.local_port)
        c.restart_delay = raw.get("restart_delay",  c.restart_delay)
        return c

    def validate(self) -> list[str]:
        errors = []
        if not self.key_file:
            errors.append("tunnel.key_file is empty")
        elif not os.path.exists(os.path.expanduser(self.key_file)):
            errors.append(f"tunnel.key_file not found: {self.key_file}")
        if not self.username:
            errors.append("tunnel.username is empty")
        if not self.remote_host:
            errors.append("tunnel.remote_host is empty")
        if not self.remote_port:
            errors.append("tunnel.remote_port is 0")
        return errors


class PortmapTunnel:
    def __init__(self, cfg: TunnelConfig) -> None:
        self.cfg = cfg
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()

    def _run_tunnel(self) -> None:
        try:
            import paramiko
        except ImportError:
            log.error("[tunnel] paramiko not installed. Run: pip install paramiko")
            return

        key_path = os.path.expanduser(self.cfg.key_file)

        while not self._stop_event.is_set():
            transport = None
            try:
                log.info(f"[tunnel] Connecting to {self.cfg.remote_host}:22 ...")

                # Load private key - try multiple formats
                key = None
                for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
                    try:
                        key = key_class.from_private_key_file(key_path)
                        break
                    except Exception:
                        continue

                if key is None:
                    log.error(f"[tunnel] Could not load key from {key_path}")
                    break

                # Connect SSH
                sock = socket.create_connection((self.cfg.remote_host, 22), timeout=15)
                transport = paramiko.Transport(sock)
                transport.connect(username=self.cfg.username, pkey=key)

                if not transport.is_authenticated():
                    log.error("[tunnel] Authentication failed")
                    break

                # Request reverse port forwarding
                transport.request_port_forward("", self.cfg.remote_port)
                log.info(f"[tunnel] [OK] Tunnel active: "
                         f"{self.cfg.remote_host}:{self.cfg.remote_port} -> localhost:{self.cfg.local_port}")

                # Accept and forward incoming channels
                while not self._stop_event.is_set() and transport.is_active():
                    chan = transport.accept(timeout=1)
                    if chan is None:
                        continue
                    threading.Thread(
                        target=self._forward_channel,
                        args=(chan,),
                        daemon=True
                    ).start()

                if not transport.is_active():
                    log.warning("[tunnel] Transport disconnected")

            except Exception as exc:
                log.warning(f"[tunnel] Error: {exc}")
            finally:
                if transport:
                    try:
                        transport.close()
                    except Exception:
                        pass

            if not self._stop_event.is_set():
                log.info(f"[tunnel] Restarting in {self.cfg.restart_delay}s ...")
                self._stop_event.wait(timeout=self.cfg.restart_delay)

    def _forward_channel(self, chan) -> None:
        try:
            local_sock = socket.create_connection(("127.0.0.1", self.cfg.local_port), timeout=5)
            local_sock.settimeout(None) 
            log.info(f"[tunnel] Forwarding channel to local:{self.cfg.local_port}")
        except Exception as exc:
            log.warning(f"[tunnel] Cannot connect to local:{self.cfg.local_port}: {exc}")
            chan.close()
            return

        chan.setblocking(True)

        def pump(src, dst, label):
            total = 0
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        log.debug(f"[tunnel/{label}] EOF after {total} bytes")
                        break
                    dst.sendall(data)
                    total += len(data)
            except Exception as e:
                log.debug(f"[tunnel/{label}] Error after {total} bytes: {e}")
            finally:
                try: src.close()
                except Exception: pass
                try: dst.close()
                except Exception: pass

        threading.Thread(target=pump, args=(chan, local_sock, "remote->local"), daemon=True).start()
        threading.Thread(target=pump, args=(local_sock, chan, "local->remote"), daemon=True).start()

    async def start(self) -> None:
        errors = self.cfg.validate()
        if errors:
            for e in errors:
                log.error(f"[tunnel] Config error: {e}")
            return

        self._stop_event.clear()
        self._running = True
        log.info(f"[tunnel] Starting Portmap.io tunnel via paramiko")
        log.info(f"[tunnel] Public endpoint -> {self.cfg.remote_host}:{self.cfg.remote_port}")

        self._thread = threading.Thread(target=self._run_tunnel, daemon=True)
        self._thread.start()

    async def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("[tunnel] Stopped")


async def start_tunnel(cfg: TunnelConfig) -> PortmapTunnel:
    tunnel = PortmapTunnel(cfg)
    await tunnel.start()
    return tunnel
