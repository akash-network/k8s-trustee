from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from scripts.provision_canary import (
    CurlAdminClient,
    ProvisioningError,
    load_bundle,
    provision_bundle,
    read_private_token,
)


class RecordingClient:
    def __init__(self, policy_responses: dict[str, bytes] | None = None) -> None:
        self.calls: list[tuple[str, str, bytes | Path | None]] = []
        self.policy_responses = policy_responses or {}

    def post_bytes(self, path: str, body: bytes, content_type: str) -> None:
        self.calls.append(("POST", path, body))

    def get_bytes(self, path: str) -> bytes:
        self.calls.append(("GET", path, None))
        return self.policy_responses[path]


class CanaryProvisionerTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.bundle = self.root / "bundle"
        self.resources = self.root / "resources"
        self.bundle.mkdir(mode=0o700)
        self.resources.mkdir(mode=0o700)

    def write_fixture(self) -> tuple[bytes, bytes]:
        policy = b"package policy\nimport rego.v1\ndefault allow := false\n"
        resource = b"private-resource-body"
        policy_file = "registry.rego"
        (self.bundle / policy_file).write_bytes(policy)
        resource_path = self.resources / "lease-42" / "registry-auth"
        resource_path.mkdir(parents=True)
        resource_file = resource_path / "private-image"
        resource_file.write_bytes(resource)
        resource_file.chmod(0o600)
        index = {
            "version": "v1",
            "grantSha256": "a" * 64,
            "workload": {
                "owner": "akash1synthetic",
                "dseq": "42",
                "gseq": 1,
                "oseq": 1,
                "service": "proof",
                "replica": 0,
            },
            "expiresAt": "2030-01-01T00:00:00Z",
            "expiresAtEpoch": 1893456000,
            "policies": [
                {
                    "repository": "lease-42",
                    "type": "registry-auth",
                    "file": policy_file,
                    "policySha256": hashlib.sha256(policy).hexdigest(),
                    "resources": [
                        {
                            "tag": "private-image",
                            "sha256": hashlib.sha256(resource).hexdigest(),
                        }
                    ],
                }
            ],
        }
        (self.bundle / "index.json").write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n"
        )
        return policy, resource

    def test_bundle_is_validated_before_network_access(self) -> None:
        self.write_fixture()
        resource_path = self.resources / "lease-42/registry-auth/private-image"
        resource_path.write_bytes(b"wrong")
        client = RecordingClient()

        with self.assertRaisesRegex(ProvisioningError, "resource digest"):
            provision_bundle(load_bundle(self.bundle, self.resources), client)

        self.assertEqual(client.calls, [])

    def test_policies_are_read_back_before_resources_are_written(self) -> None:
        policy, _ = self.write_fixture()
        policy_path = "/kbs/v0/resource-policy/lease-42/registry-auth"
        client = RecordingClient({policy_path: policy})

        receipt = provision_bundle(load_bundle(self.bundle, self.resources), client)

        self.assertEqual(
            [(method, path) for method, path, _ in client.calls],
            [
                ("POST", policy_path),
                ("GET", policy_path),
                ("POST", "/kbs/v0/resource/lease-42/registry-auth/private-image"),
            ],
        )
        self.assertEqual(receipt["version"], "v1")
        self.assertNotIn("body", json.dumps(receipt))

    def test_policy_readback_mismatch_stops_before_secret_write(self) -> None:
        self.write_fixture()
        policy_path = "/kbs/v0/resource-policy/lease-42/registry-auth"
        client = RecordingClient({policy_path: b"different"})

        with self.assertRaisesRegex(ProvisioningError, "policy readback"):
            provision_bundle(load_bundle(self.bundle, self.resources), client)

        self.assertEqual(
            [(method, path) for method, path, _ in client.calls],
            [("POST", policy_path), ("GET", policy_path)],
        )

    def test_validated_resource_bytes_cannot_change_before_upload(self) -> None:
        policy, resource = self.write_fixture()
        bundle = load_bundle(self.bundle, self.resources)
        resource_path = self.resources / "lease-42/registry-auth/private-image"
        resource_path.write_bytes(b"replaced after validation")
        policy_path = "/kbs/v0/resource-policy/lease-42/registry-auth"
        client = RecordingClient({policy_path: policy})

        provision_bundle(bundle, client)

        self.assertEqual(client.calls[-1][2], resource)

    def test_resource_tree_rejects_unindexed_files(self) -> None:
        self.write_fixture()
        extra = self.resources / "lease-42/registry-auth/extra"
        extra.write_bytes(b"not indexed")

        with self.assertRaisesRegex(ProvisioningError, "unindexed resource"):
            load_bundle(self.bundle, self.resources)

    def test_admin_token_must_be_a_private_regular_file(self) -> None:
        token_file = self.root / "token"
        token_file.write_text("header.payload.signature\n")
        token_file.chmod(0o600)
        self.assertEqual(read_private_token(token_file), "header.payload.signature")

        token_file.chmod(0o640)
        with self.assertRaisesRegex(ProvisioningError, "permissions"):
            read_private_token(token_file)

        token_file.chmod(0o600)
        link = self.root / "token-link"
        link.symlink_to(token_file)
        with self.assertRaisesRegex(ProvisioningError, "regular file"):
            read_private_token(link)

    def test_curl_keeps_the_admin_token_out_of_process_arguments(self) -> None:
        ca_certificate = self.root / "ca.pem"
        ca_certificate.write_text("public certificate")
        token = "header.payload.signature"
        client = CurlAdminClient(
            "https://trustee-backend.example:18443",
            ca_certificate,
            token,
            "127.0.0.1",
            18443,
        )
        with patch(
            "scripts.provision_canary.subprocess.run",
            return_value=CompletedProcess([], 0, b"policy", b""),
        ) as run:
            self.assertEqual(client.get_bytes("/kbs/v0/resource-policy/repo/type"), b"policy")

        arguments = run.call_args.args[0]
        self.assertFalse(any(token in argument for argument in arguments))
        self.assertIn("--noproxy", arguments)
        self.assertIn("--http1.1", arguments)
        self.assertIn(token, run.call_args.kwargs["input"].decode())


if __name__ == "__main__":
    unittest.main()
