import sys
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import interop_shadowsocksr as interop


class SharedConfiguration(unittest.TestCase):
    def assert_valid(self, config):
        binary = os.environ["KERLICO_TEST_CLI"]
        with tempfile.TemporaryDirectory(prefix="ssr-config-v2-") as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = subprocess.run([binary, "check", "--config", str(path)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_authenticated_multiuser_keeps_distinct_native_members(self):
        config = interop.server_config("127.0.0.1", 24001, "none", "auth_chain_a", "plain", True)
        self.assert_valid(config)
        self.assertEqual(config["version"], 2)
        node = config["nodes"][0]
        self.assertNotIn("password", node["options"])
        self.assertNotIn("users", node["options"])
        self.assertEqual(len(config["accounts"]), 2)
        members = node["members"]
        self.assertNotEqual(members[0]["user_id"], members[1]["user_id"])
        self.assertEqual([row["native_credential"]["user"]["id"] for row in members], [7, 8])
        self.assertTrue(all(row["native_credential"]["password"] == interop.BASE_PASSWORD for row in members))

    def test_single_authenticated_member_retains_group_password(self):
        config = interop.server_config("::1", 24002, "aes-128-cfb", "auth_aes128_md5", "random_head", False)
        self.assert_valid(config)
        self.assertEqual(config["nodes"][0]["members"][0]["native_credential"], {"password": interop.BASE_PASSWORD})

    def test_unauthenticated_udp_combination_stays_explicitly_local(self):
        config = interop.server_config("127.0.0.1", 24003, "aes-128-cfb", "origin", "plain", False)
        self.assert_valid(config)
        self.assertEqual(config["nodes"], [])
        self.assertNotIn("accounts", config)
        self.assertEqual(config["local_inbounds"][0]["options"]["password"], interop.BASE_PASSWORD)

    def test_client_forward_keeps_remote_proxy_and_original_target(self):
        config = interop.client_config(24004, "::1", 24005, "::1", 24006, "none", "auth_chain_a", "plain", True)
        self.assert_valid(config)
        self.assertEqual(config["version"], 2)
        self.assertEqual(config["outbounds"][0]["options"]["user"]["id"], 7)
        self.assertEqual({row["type"] for row in config["inbounds"]}, {"tcp-forward", "udp-forward"})
        self.assertTrue(all(row["target"] == {"host": "::1", "port": 24006} for row in config["inbounds"]))


if __name__ == "__main__":
    unittest.main()
