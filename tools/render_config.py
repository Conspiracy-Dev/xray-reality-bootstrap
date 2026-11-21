#!/usr/bin/env python3
"""Render Xray node configs without storing runtime credentials in Git."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, quote


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "templates"
PLACEHOLDER = re.compile(r"\{\{[A-Z0-9_]+\}\}")
HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z")
SHORT_ID = re.compile(r"[0-9a-f]{2,16}\Z")


class ConfigError(ValueError):
    """An input would produce an unsafe or incompatible configuration."""


def fail(message: str) -> None:
    raise ConfigError(message)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"{label} not found")
    except json.JSONDecodeError:
        fail(f"{label} is not valid JSON")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def required(mapping: dict[str, Any], key: str, label: str) -> Any:
    if key not in mapping:
        fail(f"missing {label}.{key}")
    return mapping[key]


def only_keys(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        fail(f"unsupported field in {label}")


def nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or PLACEHOLDER.search(value):
        fail(f"invalid {label}")
    return value


def hostname(value: Any, label: str) -> str:
    candidate = nonempty_string(value, label).lower()
    if not HOSTNAME.fullmatch(candidate):
        fail(f"invalid hostname for {label}")
    return candidate


def port(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        fail(f"invalid port for {label}")
    return value


def target(value: Any) -> tuple[str, int]:
    candidate = nonempty_string(value, "reality.target")
    host, separator, raw_port = candidate.rpartition(":")
    if not separator:
        fail("reality.target must be host:port")
    return hostname(host, "reality.target host"), port(int_or_error(raw_port, "reality.target"), "reality.target")


def int_or_error(value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError:
        fail(f"invalid port for {label}")


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    only_keys(manifest, {"schema_version", "endpoint", "reality", "tcp", "grpc"}, "manifest")
    if manifest.get("schema_version") != 1:
        fail("unsupported schema_version")
    endpoint = hostname(required(manifest, "endpoint", "manifest"), "endpoint")
    reality = required(manifest, "reality", "manifest")
    tcp = required(manifest, "tcp", "manifest")
    grpc = required(manifest, "grpc", "manifest")
    if not all(isinstance(item, dict) for item in (reality, tcp, grpc)):
        fail("reality, tcp and grpc must be objects")
    only_keys(reality, {"target", "server_name"}, "reality")
    only_keys(tcp, {"tag", "port", "flow", "fingerprint"}, "tcp")
    only_keys(grpc, {"tag", "port", "service_name", "fingerprint"}, "grpc")

    target_host, target_port = target(required(reality, "target", "reality"))
    server_name = hostname(required(reality, "server_name", "reality"), "reality.server_name")
    if target_host == endpoint:
        fail("REALITY target must not be the VPN endpoint")
    if target_port != 443:
        fail("this lab accepts a 443 REALITY target only")
    if server_name != target_host:
        fail("reality.server_name must match target host")

    tcp_port = port(required(tcp, "port", "tcp"), "tcp.port")
    grpc_port = port(required(grpc, "port", "grpc"), "grpc.port")
    if tcp_port == grpc_port:
        fail("TCP and gRPC ports must differ")
    if tcp_port != 443 or grpc_port != 34241:
        fail("lab ports must be TCP 443 and gRPC 34241")
    if required(tcp, "flow", "tcp") != "xtls-rprx-vision":
        fail("TCP flow must be xtls-rprx-vision")
    if required(grpc, "service_name", "grpc") != "auth":
        fail("gRPC service_name must be auth")
    for section, expected in ((tcp, "chrome"), (grpc, "firefox")):
        if required(section, "fingerprint", "transport") != expected:
            fail("unexpected uTLS fingerprint")
        nonempty_string(required(section, "tag", "transport"), "transport.tag")

    return {
        "endpoint": endpoint,
        "reality_target": f"{target_host}:{target_port}",
        "reality_server_name": server_name,
        "tcp": tcp,
        "grpc": grpc,
    }


def validate_secret_pair(value: Any, name: str) -> str:
    material = nonempty_string(value, name)
    if any(character.isspace() for character in material):
        fail(f"invalid {name}")
    return material


def validate_secrets(secrets: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for transport in ("tcp", "grpc"):
        section = required(secrets, transport, "secrets")
        if not isinstance(section, dict):
            fail(f"secrets.{transport} must be an object")
        only_keys(section, {"uuid", "short_id", "private_key", "public_key"}, f"secrets.{transport}")
        raw_uuid = nonempty_string(required(section, "uuid", f"secrets.{transport}"), f"secrets.{transport}.uuid")
        try:
            if str(uuid.UUID(raw_uuid)) != raw_uuid.lower():
                fail(f"invalid secrets.{transport}.uuid")
        except ValueError:
            fail(f"invalid secrets.{transport}.uuid")
        short_id = nonempty_string(required(section, "short_id", f"secrets.{transport}"), f"secrets.{transport}.short_id")
        if not SHORT_ID.fullmatch(short_id):
            fail(f"invalid secrets.{transport}.short_id")
        result[transport] = {
            "uuid": raw_uuid,
            "short_id": short_id,
            "private_key": validate_secret_pair(required(section, "private_key", f"secrets.{transport}"), f"secrets.{transport}.private_key"),
            "public_key": validate_secret_pair(required(section, "public_key", f"secrets.{transport}"), f"secrets.{transport}.public_key"),
        }
    if result["tcp"]["uuid"] == result["grpc"]["uuid"]:
        fail("TCP and gRPC UUIDs must differ")
    if result["tcp"]["private_key"] == result["grpc"]["private_key"]:
        fail("TCP and gRPC REALITY private keys must differ")
    return result


def assert_private_file(path: Path) -> None:
    if not path.is_absolute():
        fail("secrets path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        fail("secrets file not found")
    if resolved.is_relative_to(ROOT):
        fail("secrets file must be outside the repository")
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        fail("secrets file permissions must be owner-only")


def render_template(name: str, values: dict[str, str]) -> dict[str, Any]:
    text = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    tokens = set(PLACEHOLDER.findall(text))
    expected = {f"{{{{{key}}}}}" for key in values}
    if tokens - expected:
        fail(f"template {name} has unsupported placeholder")
    for token, value in ((token, values[token[2:-2]]) for token in tokens):
        text = text.replace(token, value)
    if PLACEHOLDER.search(text):
        fail(f"template {name} has unresolved placeholder")
    try:
        rendered = json.loads(text)
    except json.JSONDecodeError:
        fail(f"template {name} rendered invalid JSON")
    reject_disallowed(rendered)
    return rendered


def reject_disallowed(value: Any, parent: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"fragment", "leastPing", "leastLoad"}:
                fail(f"unsupported field {key}")
            if parent == "grpcSettings" and key == "mode":
                fail("use grpcSettings.multiMode, not mode")
            if key == "network" and child == "tcp" and parent == "transport":
                fail("sing-box transport.network tcp is unsupported")
            if key == "flow" and parent == "grpc":
                fail("gRPC must not use Vision flow")
            reject_disallowed(child, key)
    elif isinstance(value, list):
        for child in value:
            reject_disallowed(child, parent)


def render_all(manifest: dict[str, Any], secrets: dict[str, Any]) -> dict[str, Any]:
    public = validate_manifest(manifest)
    private = validate_secrets(secrets)
    tcp = public["tcp"]
    grpc = public["grpc"]
    values = {
        "ENDPOINT": public["endpoint"],
        "REALITY_TARGET": public["reality_target"],
        "REALITY_SERVER_NAME": public["reality_server_name"],
        "TCP_TAG": str(tcp["tag"]), "TCP_PORT": str(tcp["port"]), "TCP_UUID": private["tcp"]["uuid"],
        "TCP_PRIVATE_KEY": private["tcp"]["private_key"], "TCP_PUBLIC_KEY": private["tcp"]["public_key"],
        "TCP_SHORT_ID": private["tcp"]["short_id"], "TCP_FINGERPRINT": str(tcp["fingerprint"]),
        "GRPC_TAG": str(grpc["tag"]), "GRPC_PORT": str(grpc["port"]), "GRPC_UUID": private["grpc"]["uuid"],
        "GRPC_PRIVATE_KEY": private["grpc"]["private_key"], "GRPC_PUBLIC_KEY": private["grpc"]["public_key"],
        "GRPC_SHORT_ID": private["grpc"]["short_id"], "GRPC_FINGERPRINT": str(grpc["fingerprint"]),
        "GRPC_SERVICE_NAME": str(grpc["service_name"]),
    }
    tcp_server = render_template("xray-tcp-vision.json.template", values)
    grpc_server = render_template("xray-grpc.json.template", values)
    tcp_client = render_template("sing-box-tcp.json.template", values)
    grpc_client = render_template("sing-box-grpc.json.template", values)
    # JSON scalars are valid YAML scalars and preserve string types (including short IDs).
    yaml_values = {**values, "TCP_PORT": tcp["port"], "GRPC_PORT": grpc["port"], "TCP_FLOW": tcp["flow"]}

    def rabbithole_yaml(transport: str) -> str:
        template = (TEMPLATE_DIR / f"rabbithole-{transport}.yaml.template").read_text(encoding="utf-8")
        return PLACEHOLDER.sub(lambda m: json.dumps(yaml_values[m[0][2:-2]]), template).rstrip("\n")

    combined = {
        "log": tcp_server["log"],
        "inbounds": tcp_server["inbounds"] + grpc_server["inbounds"],
        "outbounds": tcp_server["outbounds"],
    }
    def share_uri(transport: str, options: dict[str, str]) -> str:
        profile = public[transport]
        access = private[transport]
        query = urlencode({
            "encryption": "none", "security": "reality", "sni": public["reality_server_name"],
            "fp": profile["fingerprint"], "pbk": access["public_key"], "sid": access["short_id"],
            "type": transport, **options,
        }, quote_via=quote)
        return f"vless://{access['uuid']}@{public['endpoint']}:{profile['port']}?{query}#conspiracy-ray-{transport.upper()}"

    return {
        "xray-tcp.json": tcp_server,
        "xray-grpc.json": grpc_server,
        "xray-server.json": combined,
        "sing-box-tcp.json": tcp_client,
        "sing-box-grpc.json": grpc_client,
        "vless-tcp.uri": share_uri("tcp", {"flow": tcp["flow"]}),
        "vless-grpc.uri": share_uri("grpc", {"serviceName": grpc["service_name"]}),
        "rabbithole-tcp.yaml": rabbithole_yaml("tcp"),
        "rabbithole-grpc.yaml": rabbithole_yaml("grpc"),
    }


def write_runtime(output: Path, rendered: dict[str, Any]) -> None:
    if not output.is_absolute():
        fail("output path must be absolute")
    resolved = output.resolve()
    if resolved.is_relative_to(ROOT):
        fail("output path must be outside the repository")
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(resolved, 0o700)
    for name, content in rendered.items():
        path = resolved / name
        if isinstance(content, str):
            payload = content + "\n"
        else:
            payload = json.dumps(content, indent=2, sort_keys=True) + "\n"
        path.write_text(payload, encoding="utf-8")
        os.chmod(path, 0o600)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "render"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--secrets", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    try:
        assert_private_file(args.secrets)
        rendered = render_all(load_json(args.manifest, "manifest"), load_json(args.secrets, "secrets"))
        if args.command == "render":
            if args.output is None:
                fail("render requires --output")
            write_runtime(args.output, rendered)
        print(f"{args.command}: PASS")
        return 0
    except ConfigError as error:
        print(f"{args.command}: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
