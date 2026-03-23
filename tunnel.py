"""
tunnel.py — Portmap.io global access via SSH reverse tunnel

How Portmap.io works:
  ssh -R <remote_port>:localhost:<local_port> <key>@portmap.io -N

This module:
  1. Reads tunnel config from ServerConfig
  2. Opens the SSH reverse tunnel as an asyncio subprocess
  3. Monitors it and restarts on failure
  4. Logs the public address so clients know where to connect
  5. Gracefully tears down on server exit

Requirements:
  - ssh must be on PATH (it is on all modern Windows/Linux/macOS)
  - A Portmap.io account + API key (free tier works)

Config in config.yaml:
  tunnel:
    enabled: true
    provider: portmap        # only portmap supported here
    api_key: "YOUR_KEY"      # from portmap.io dashboard
    remote_port: 6767        # public port on portmap.io
    local_port: 6767         # your local TLS server port
    restart_delay: 10        # seconds before restart on failure
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass

log = logging.getLogger("tls_server.tunnel")

PORTMAP_HOST = "portmap.io"
PORTMAP_USER = "portmap"   # fixed username for portmap.io


@dataclass
class TunnelConfig:
    enabled: bool = False
    provider: str = "portmap"
    api_key: str = ""
    remote_port: int = 6767
    local_port: int = 6767
    restart_delay: float = 10.0

    @classmethod
    def from_dict(cls, raw: dict) -> "TunnelConfig":
        c = cls()
        c.enabled = raw.get("enabled", c.enabled)
        c.provider = raw.get("provider", c.provider)
        c.api_key = raw.get("api_key", c.api_key)
        c.remote_port = raw.get("remote_port", c.remote_port)
        c.local_port = raw.get("local_port", c.local_port)
        c.restart_delay = raw.get("restart_delay", c.restart_delay)
        return c


class PortmapTunnel:
    """
    Manages a persistent SSH reverse tunnel to Portmap.io.

    The SSH command used:
      ssh -R <remote_port>:localhost:<local_port> \\
          -o StrictHostKeyChecking=no \\
          -o ServerAliveInterval=30 \\
          -o ExitOnForwardFailure=yes \\
          <api_key>@portmap.io -N
    """

    def __init__(self, cfg: TunnelConfig) -> None:
        self.cfg = cfg
        self._proc: asyncio.subprocess.Process | None = None
        self._running = False

    def _build_cmd(self) -> list[str]:
        c = self.cfg
        return [
            "ssh",
            "-R", f"{c.remote_port}:localhost:{c.local_port}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "BatchMode=yes",          # no interactive prompts
            f"{c.api_key}@{PORTMAP_HOST}",
            "-N",                            # no remote command, just forward
        ]

    async def start(self) -> None:
        if not shutil.which("ssh"):
            log.error("ssh not found on PATH — tunnel disabled")
            return

        if not self.cfg.api_key:
            log.error("tunnel.api_key is empty — set it in config.yaml")
            return

        self._running = True
        log.info(
            f"[tunnel] Starting Portmap.io tunnel: "
            f"portmap.io:{self.cfg.remote_port} → localhost:{self.cfg.local_port}"
        )
        log.info(
            f"[tunnel] Public address for clients: {PORTMAP_HOST}:{self.cfg.remote_port}"
        )

        while self._running:
            cmd = self._build_cmd()
            log.debug(f"[tunnel] Running: {' '.join(cmd)}")

            try:
                self._proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                # Stream stderr in background (portmap prints status there)
                async def _drain_stderr():
                    assert self._proc and self._proc.stderr
                    async for line in self._proc.stderr:
                        decoded = line.decode(errors="replace").strip()
                        if decoded:
                            log.info(f"[tunnel] {decoded}")

                asyncio.create_task(_drain_stderr())

                returncode = await self._proc.wait()

                if not self._running:
                    break

                log.warning(
                    f"[tunnel] SSH exited with code {returncode} — "
                    f"restarting in {self.cfg.restart_delay}s"
                )

            except Exception as exc:
                log.error(f"[tunnel] Error: {exc} — restarting in {self.cfg.restart_delay}s")

            if self._running:
                await asyncio.sleep(self.cfg.restart_delay)

    async def stop(self) -> None:
        self._running = False
        if self._proc and self._proc.returncode is None:
            log.info("[tunnel] Shutting down SSH tunnel")
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass


async def start_tunnel(cfg: TunnelConfig) -> PortmapTunnel:
    """Create and start tunnel; returns the instance for later cleanup."""
    tunnel = PortmapTunnel(cfg)
    asyncio.create_task(tunnel.start())
    return tunnel
