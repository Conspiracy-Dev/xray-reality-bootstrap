"""Exercise the release Compose service locally with disposable test data."""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import render_config

CONFIG = "/run/conspiracy-ray/server.json"
PORTS = (443, 34241)


def docker(args, env, *, expect_success=True):
    result = subprocess.run(["docker", *args], env=env, capture_output=True, text=True, timeout=120)
    if expect_success and result.returncode:
        # In particular, never echo inspect output or a failed Xray config.
        raise RuntimeError(f"docker {args[0]} failed with status {result.returncode}")
    return result


def fixture():
    manifest = json.loads((ROOT / "config/manifest.example.json").read_text())
    manifest["endpoint"] = "node.example.org"
    keys = {}
    for name in ("tcp", "grpc"):
        # Only the private key is consumed by this server-only smoke.
        keys[name] = {
            "uuid": str(uuid.uuid4()),
            "short_id": secrets.token_hex(8),
            "private_key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
            "public_key": "unused-by-server",
        }
    return render_config.render_all(manifest, keys)["xray-server.json"], keys


def check_ports(name, env):
    ports = []
    for container_port in PORTS:
        address = docker(["port", name, f"{container_port}/tcp"], env).stdout.strip()
        host, port = address.rsplit(":", 1)
        if host != "127.0.0.1":
            raise RuntimeError("unexpected port publication")
        ports.append(int(port))
    deadline = time.monotonic() + 15
    for port in ports:
        while True:
            if docker(["inspect", "-f", "{{.State.Running}}", name], env).stdout.strip() != "true":
                raise RuntimeError("Xray stopped before the port check")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Xray port check timed out") from None
                time.sleep(0.2)


def smoke(base):
    project = f"conspiracy-ray-smoke-{uuid.uuid4().hex}"
    name = f"{project}-server"
    config_file = base / "server.json"
    logs = base / "logs"
    logs.mkdir()
    # Disposable files only. The parent temporary directory is private (0700).
    logs.chmod(0o777)
    env = dict(os.environ, VPN_CONFIG_FILE=str(config_file), VPN_LOG_DIR=str(logs),
               CONSPIRACY_RAY_SMOKE_CANARY=secrets.token_hex(24))
    deploy = ROOT / "deploy/docker"
    compose = ["compose", "--project-directory", str(deploy), "--env-file", os.devnull,
               "-p", project, "-f", str(deploy / "compose.yaml")]
    validate = [*compose, "run", "--rm", "--no-deps", "xray", "run", "-test", "-config", CONFIG]
    config, keys = fixture()
    try:
        # A failed volume mount must not create an empty directory as a config.
        if docker(validate, env, expect_success=False).returncode == 0 or config_file.exists():
            raise RuntimeError("missing config was accepted or created")
        invalid = base / "invalid.json"
        invalid.write_text('{"inbounds": [')
        invalid.chmod(0o444)
        if docker(validate, dict(env, VPN_CONFIG_FILE=str(invalid)), expect_success=False).returncode == 0:
            raise RuntimeError("Xray accepted an invalid config")
        config_file.write_text(json.dumps(config))
        config_file.chmod(0o444)
        docker(validate, env)
        # Compose run ignores the service ports; publish ephemeral loopback ports only.
        docker([*compose, "run", "-d", "--no-deps", "--name", name,
                "-p", "127.0.0.1::443", "-p", "127.0.0.1::34241", "xray"], env)
        check_ports(name, env)
        metadata = docker(["inspect", name], env).stdout
        container = json.loads(metadata)[0]
        if not container["State"]["Running"]:
            raise RuntimeError("Xray exited during the smoke test")
        mount = next(m for m in container["Mounts"] if m["Destination"] == CONFIG)
        if mount["Type"] != "bind" or mount["RW"]:
            raise RuntimeError("server config must be a read-only bind mount")
        image = container["Image"]
        metadata += docker(["image", "inspect", image], env).stdout
        metadata += docker(["history", "--no-trunc", image], env).stdout
        markers = [env["CONSPIRACY_RAY_SMOKE_CANARY"]]
        for key in keys.values():
            markers.extend([key["private_key"], key["uuid"]])
        if any(marker in metadata for marker in markers):
            raise RuntimeError("test credential or environment canary in Docker metadata")
    finally:
        docker(["rm", "-fv", name], env, expect_success=False)
        docker([*compose, "down", "--volumes", "--remove-orphans"], env)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="conspiracy-ray-compose-") as temp:
        smoke(Path(temp).resolve())
    print("PASS: Xray config validation, startup, TCP ports, read-only mount and metadata")
