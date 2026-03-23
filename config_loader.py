"""config_loader.py — #7 Config files (YAML with CLI override)"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
    _YAML = True
except ImportError:
    _YAML = False


def _load_yaml(path: str) -> dict:
    if not _YAML:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    with open(p) as f:
        return yaml.safe_load(f) or {}


@dataclass
class ServerConfig:
    # server
    host: str = "127.0.0.1"
    port: int = 6767
    cert_file: str = "server.crt"
    key_file: str = "server.key"
    ca_file: str = "ca.crt"
    require_client_cert: bool = False
    # auth
    auth_token: str = "changeme-token-1234"
    # dashboard
    dashboard_port: int = 8080
    # heartbeat
    heartbeat_interval: float = 30.0
    heartbeat_timeout: float = 10.0
    # protocol
    compression: bool = True
    compress_threshold: int = 512
    # logging
    log_level: str = "INFO"
    log_file: str = "server.log"
    # tunnel (portmap.io)
    tunnel_enabled: bool = False
    tunnel_api_key: str = ""
    tunnel_remote_port: int = 6767
    tunnel_local_port: int = 6767
    tunnel_restart_delay: float = 10.0

    @classmethod
    def from_yaml(cls, path: str = "config.yaml") -> "ServerConfig":
        raw = _load_yaml(path)
        c = cls()
        s = raw.get("server", {})
        c.host = s.get("host", c.host)
        c.port = s.get("port", c.port)
        c.cert_file = s.get("cert_file", c.cert_file)
        c.key_file = s.get("key_file", c.key_file)
        c.ca_file = s.get("ca_file", c.ca_file)
        c.require_client_cert = s.get("require_client_cert", c.require_client_cert)
        c.auth_token = raw.get("auth", {}).get("token", c.auth_token)
        c.dashboard_port = raw.get("dashboard", {}).get("port", c.dashboard_port)
        hb = raw.get("heartbeat", {})
        c.heartbeat_interval = hb.get("interval", c.heartbeat_interval)
        c.heartbeat_timeout = hb.get("timeout", c.heartbeat_timeout)
        proto = raw.get("protocol", {})
        c.compression = proto.get("compression", c.compression)
        c.compress_threshold = proto.get("compress_threshold", c.compress_threshold)
        lg = raw.get("logging", {})
        c.log_level = lg.get("level", c.log_level)
        c.log_file = lg.get("file", c.log_file)
        t = raw.get("tunnel", {})
        c.tunnel_enabled = t.get("enabled", c.tunnel_enabled)
        c.tunnel_api_key = t.get("api_key", c.tunnel_api_key)
        c.tunnel_remote_port = t.get("remote_port", c.tunnel_remote_port)
        c.tunnel_local_port = t.get("local_port", c.tunnel_local_port)
        c.tunnel_restart_delay = t.get("restart_delay", c.tunnel_restart_delay)
        return c

    def apply_args(self, args) -> None:
        """Override with CLI args if explicitly provided."""
        for attr in vars(self):
            cli_attr = attr.replace("_", "-") if "-" in attr else attr
            if hasattr(args, attr) and getattr(args, attr) is not None:
                setattr(self, attr, getattr(args, attr))


@dataclass
class ClientConfig:
    host: str = "127.0.0.1"
    port: int = 6767
    server_name: str = "localhost"
    ca_file: str = "ca.crt"
    auth_token: str = "changeme-token-1234"
    use_client_cert: bool = False
    client_cert: str = "client.crt"
    client_key: str = "client.key"
    group: str = "default"
    # reconnect backoff
    initial_delay: float = 1.0
    max_delay: float = 60.0
    multiplier: float = 2.0
    jitter: float = 0.3
    # protocol
    compression: bool = True
    compress_threshold: int = 512

    @classmethod
    def from_yaml(cls, path: str = "client_config.yaml") -> "ClientConfig":
        raw = _load_yaml(path)
        c = cls()
        s = raw.get("server", {})
        c.host = s.get("host", c.host)
        c.port = s.get("port", c.port)
        c.server_name = s.get("server_name", c.server_name)
        c.ca_file = s.get("ca_file", c.ca_file)
        c.auth_token = raw.get("auth", {}).get("token", c.auth_token)
        tls = raw.get("tls", {})
        c.use_client_cert = tls.get("use_client_cert", c.use_client_cert)
        c.client_cert = tls.get("client_cert", c.client_cert)
        c.client_key = tls.get("client_key", c.client_key)
        c.group = raw.get("client", {}).get("group", c.group)
        rb = raw.get("reconnect", {})
        c.initial_delay = rb.get("initial_delay", c.initial_delay)
        c.max_delay = rb.get("max_delay", c.max_delay)
        c.multiplier = rb.get("multiplier", c.multiplier)
        c.jitter = rb.get("jitter", c.jitter)
        proto = raw.get("protocol", {})
        c.compression = proto.get("compression", c.compression)
        c.compress_threshold = proto.get("compress_threshold", c.compress_threshold)
        return c
