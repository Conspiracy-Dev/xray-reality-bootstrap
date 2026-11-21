"""Create a new node's local credentials and profiles without printing them."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import uuid

from render_config import ROOT, ConfigError, render_all, validate_manifest, write_runtime


def keypair(image):
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--pull", "never", image, "x25519"],
        check=True, capture_output=True, text=True,
    )
    fields = dict(line.split(": ", 1) for line in result.stdout.splitlines() if ": " in line)
    return {
        "uuid": str(uuid.uuid4()), "short_id": secrets.token_hex(8),
        "private_key": fields["PrivateKey"], "public_key": fields["Password (PublicKey)"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--target", required=True, help="HTTPS hostname for REALITY on port 443")
    parser.add_argument("--state", required=True, type=Path, help="New private directory outside the clone")
    args = parser.parse_args()
    state = args.state.expanduser().resolve()
    if state.is_relative_to(ROOT) or state.exists():
        parser.error("choose a new state directory outside the repository")
    manifest = json.loads((ROOT / "config/manifest.example.json").read_text())
    manifest.update(endpoint=args.endpoint, reality={"target": args.target + ":443", "server_name": args.target})
    validate_manifest(manifest)
    reserved = ("example.org", "example.net", "example.com")
    for domain in (args.endpoint.lower(), args.target.lower()):
        if any(domain == suffix or domain.endswith("." + suffix) for suffix in reserved):
            parser.error("replace documentation hostnames with actual DNS names")
    os.umask(0o077)
    compose = ["docker", "compose", "-f", str(ROOT / "deploy/docker/compose.yaml")]
    env = dict(os.environ, VPN_CONFIG_FILE=str(state / "runtime/xray-server.json"), VPN_LOG_DIR=str(state / "logs"))
    image = subprocess.check_output([*compose, "config", "--images"], env=env, text=True).strip()
    subprocess.run([*compose, "pull", "xray"], env=env, check=True)
    credentials = {transport: keypair(image) for transport in ("tcp", "grpc")}
    rendered = render_all(manifest, credentials)
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for filename, data in (("node.json", manifest), ("node-secrets.json", credentials)):
            (state / filename).write_text(json.dumps(data, indent=2) + "\n")
        write_runtime(state / "runtime", rendered)
    except Exception:
        shutil.rmtree(state)
        raise
    print("Node configuration and client profiles are ready in the requested directory.")


if __name__ == "__main__":
    try:
        main()
    except (ConfigError, subprocess.CalledProcessError, OSError, KeyError) as exc:
        raise SystemExit("Node initialization failed: " + str(exc)) from None
