from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import render_config  # noqa: E402


MANIFEST = json.loads((ROOT / "config" / "manifest.example.json").read_text())
SECRETS = {
    "tcp": {
        "uuid": "11111111-1111-4111-8111-111111111111",
        "short_id": "a1b2c3d4",
        "private_key": "test_tcp_private_key",
        "public_key": "test_tcp_public_key"
    },
    "grpc": {
        "uuid": "22222222-2222-4222-8222-222222222222",
        "short_id": "b1c2d3e4",
        "private_key": "test_grpc_private_key",
        "public_key": "test_grpc_public_key"
    }
}


class RenderConfigTests(unittest.TestCase):
    def test_renders_expected_transports(self) -> None:
        rendered = render_config.render_all(copy.deepcopy(MANIFEST), copy.deepcopy(SECRETS))
        tcp = rendered["xray-tcp.json"]["inbounds"][0]
        grpc = rendered["xray-grpc.json"]["inbounds"][0]
        tcp_client = rendered["sing-box-tcp.json"]
        grpc_client = rendered["sing-box-grpc.json"]
        self.assertEqual(tcp["streamSettings"]["network"], "tcp")
        self.assertEqual(tcp["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(grpc["streamSettings"]["network"], "grpc")
        self.assertNotIn("flow", grpc["settings"]["clients"][0])
        self.assertNotIn("transport", tcp_client)
        self.assertEqual(grpc_client["transport"], {"type": "grpc", "service_name": "auth"})
        self.assertIn("pbk=test_tcp_public_key", rendered["vless-tcp.uri"])

    def test_share_links_match_pilot_profiles(self) -> None:
        manifest = dict(MANIFEST, endpoint="pilot.example.org")
        rendered = render_config.render_all(manifest, SECRETS)
        for transport in ("tcp", "grpc"):
            with self.subTest(transport=transport):
                link = urlsplit(rendered[f"vless-{transport}.uri"])
                profile = rendered[f"sing-box-{transport}.json"]
                self.assertEqual((link.scheme, link.hostname, link.port, link.username),
                                 ("vless", manifest["endpoint"], profile["server_port"], profile["uuid"]))
                tls = profile["tls"]
                expected = {
                    "type": transport, "encryption": "none", "security": "reality",
                    "sni": tls["server_name"], "fp": tls["utls"]["fingerprint"],
                    "pbk": tls["reality"]["public_key"], "sid": tls["reality"]["short_id"],
                }
                if transport == "grpc":
                    expected["serviceName"] = profile["transport"]["service_name"]
                else:
                    expected["flow"] = profile["flow"]
                self.assertCountEqual(parse_qsl(link.query), expected.items())

    def test_rejects_same_ports(self) -> None:
        manifest = copy.deepcopy(MANIFEST)
        manifest["grpc"]["port"] = 443
        with self.assertRaisesRegex(render_config.ConfigError, "ports must differ"):
            render_config.render_all(manifest, copy.deepcopy(SECRETS))

    def test_rabbithole_uses_each_transports_client_credentials(self) -> None:
        secrets = copy.deepcopy(SECRETS)
        secrets["tcp"]["short_id"] = "00001234"
        rendered = render_config.render_all(dict(MANIFEST, endpoint="pilot.example.org"), secrets)
        for transport in ("tcp", "grpc"):
            with self.subTest(transport=transport):
                yaml = rendered[f"rabbithole-{transport}.yaml"]
                self.assertIn('server: "pilot.example.org"', yaml)
                for field, key in (("uuid", "uuid"), ("short-id", "short_id"), ("public-key", "public_key")):
                    self.assertIn(f"{field}: {json.dumps(secrets[transport][key])}\n", yaml)
                for pair in secrets.values():
                    self.assertNotIn(pair["private_key"], yaml)
                self.assertNotIn("{{", yaml)
        self.assertIn('flow: "xtls-rprx-vision"', rendered["rabbithole-tcp.yaml"])
        self.assertNotIn("flow:", rendered["rabbithole-grpc.yaml"])
        self.assertIn('grpc-service-name: "auth"', rendered["rabbithole-grpc.yaml"])

    def test_rejects_target_that_is_endpoint(self) -> None:
        manifest = copy.deepcopy(MANIFEST)
        manifest["reality"]["target"] = MANIFEST["endpoint"] + ":443"
        manifest["reality"]["server_name"] = MANIFEST["endpoint"]
        with self.assertRaisesRegex(render_config.ConfigError, "must not be the VPN endpoint"):
            render_config.render_all(manifest, copy.deepcopy(SECRETS))

    def test_rejects_invalid_short_id(self) -> None:
        secrets = copy.deepcopy(SECRETS)
        secrets["tcp"]["short_id"] = "not-hex"
        with self.assertRaisesRegex(render_config.ConfigError, "short_id"):
            render_config.render_all(copy.deepcopy(MANIFEST), secrets)

    def test_rejects_missing_secret(self) -> None:
        secrets = copy.deepcopy(SECRETS)
        del secrets["grpc"]["private_key"]
        with self.assertRaisesRegex(render_config.ConfigError, "private_key"):
            render_config.render_all(copy.deepcopy(MANIFEST), secrets)

    def test_rejects_reused_reality_private_key(self) -> None:
        secrets = copy.deepcopy(SECRETS)
        secrets["grpc"]["private_key"] = secrets["tcp"]["private_key"]
        with self.assertRaisesRegex(render_config.ConfigError, "private keys must differ"):
            render_config.render_all(copy.deepcopy(MANIFEST), secrets)

    def test_rejects_unsupported_conspiracy_ray_fields(self) -> None:
        manifest = copy.deepcopy(MANIFEST)
        manifest["fragment"] = {"packets": "tlshello"}
        with self.assertRaisesRegex(render_config.ConfigError, "unsupported field"):
            render_config.render_all(manifest, copy.deepcopy(SECRETS))

    def test_rejects_vision_flow_for_grpc(self) -> None:
        manifest = copy.deepcopy(MANIFEST)
        manifest["grpc"]["flow"] = "xtls-rprx-vision"
        with self.assertRaisesRegex(render_config.ConfigError, "unsupported field"):
            render_config.render_all(manifest, copy.deepcopy(SECRETS))

    def test_rejects_obsolete_grpc_mode(self) -> None:
        with self.assertRaisesRegex(render_config.ConfigError, "multiMode"):
            render_config.reject_disallowed({"grpcSettings": {"mode": False}})

    def test_writes_only_outside_repository_with_private_permissions(self) -> None:
        rendered = render_config.render_all(copy.deepcopy(MANIFEST), copy.deepcopy(SECRETS))
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "runtime"
            render_config.write_runtime(output, rendered)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(output / "xray-server.json").st_mode & 0o777, 0o600)
            self.assertTrue((output / "vless-tcp.uri").read_text().startswith("vless://"))

    def test_rejects_runtime_inside_repository(self) -> None:
        rendered = render_config.render_all(copy.deepcopy(MANIFEST), copy.deepcopy(SECRETS))
        with self.assertRaisesRegex(render_config.ConfigError, "outside the repository"):
            render_config.write_runtime(ROOT / "runtime", rendered)

    def test_cli_render_and_check_keep_secrets_out_of_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            secret_file = base / "secrets.json"
            runtime = base / "runtime"
            secret_file.write_text(json.dumps(SECRETS), encoding="utf-8")
            os.chmod(secret_file, 0o600)
            render = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "render_config.py"), "render", "--manifest", str(ROOT / "config" / "manifest.example.json"), "--secrets", str(secret_file), "--output", str(runtime)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(render.returncode, 0, render.stderr)
            self.assertNotIn(SECRETS["tcp"]["private_key"], render.stdout)
            self.assertTrue((runtime / "xray-server.json").is_file())


if __name__ == "__main__":
    unittest.main()
