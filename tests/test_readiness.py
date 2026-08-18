from __future__ import annotations

import json
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts.readiness import (
    REQUIRED_KEYS,
    ValidationError,
    parse_release,
    qualification_result_blockers,
    release_blockers,
)
from scripts.render_resource_policies import (
    GrantValidationError,
    parse_grant,
    render_scoped_policies,
    write_policy_bundle,
)


class ReleaseParserTests(unittest.TestCase):
    def write_release(self, text: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "release.env"
        path.write_text(text)
        return path

    def complete_release(self) -> dict[str, str]:
        release = {key: "true" for key in REQUIRED_KEYS}
        release.update(
            {
                "TRUSTEE_IMAGE_REPOSITORY": "ghcr.io/ocl/trustee",
                "TRUSTEE_IMAGE_DIGEST": "sha256:" + ("a" * 64),
                "TRUSTEE_IMAGE_BUILD_REVISION": "c" * 40,
                "TRUSTEE_SOURCE_REPOSITORY": (
                    "https://github.com/confidential-containers/trustee"
                ),
                "TRUSTEE_SOURCE_REVISION": "b" * 40,
                "TRUSTEE_UPSTREAM_REPOSITORY": (
                    "https://github.com/confidential-containers/trustee"
                ),
                "TRUSTEE_UPSTREAM_BASE_REVISION": "b" * 40,
                "PUBLIC_HOSTNAME": "kbs.example.com",
                "BACKEND_TLS_HOSTNAME": "trustee-backend.example.com",
            }
        )
        return release

    def test_complete_release_has_no_capability_blockers(self) -> None:
        self.assertEqual(release_blockers(self.complete_release(), "production"), [])

    def test_qualification_release_accepts_akash_fork_provenance(self) -> None:
        release = self.complete_release()
        release["TRUSTEE_SOURCE_REPOSITORY"] = (
            "https://github.com/akash-network/trustee"
        )
        release["TRUSTEE_SOURCE_REVISION"] = "a" * 40
        release["TRUSTEE_UPSTREAM_BASE_REVISION"] = "b" * 40
        self.assertEqual(release_blockers(release, "qualification"), [])

    def test_qualification_deploy_does_not_require_post_run_results(self) -> None:
        release = self.complete_release()
        release["TRUSTEE_SOURCE_REPOSITORY"] = (
            "https://github.com/akash-network/trustee"
        )
        release["TRUSTEE_SOURCE_REVISION"] = "a" * 40
        release["PROVISIONING_CONTROL_PLANE"] = "false"
        for key in ("DATABASE_RECOVERY_TEST", "ISOLATION_TESTS", "EXTERNAL_E2E"):
            release[key] = "false"

        self.assertEqual(release_blockers(release, "qualification"), [])
        result_blockers = qualification_result_blockers(release)
        self.assertEqual(len(result_blockers), 3)
        self.assertFalse(
            any("PROVISIONING_CONTROL_PLANE" in blocker for blocker in result_blockers)
        )

    def test_qualification_does_not_claim_database_tls_from_the_locked_source(
        self,
    ) -> None:
        release = self.complete_release()
        release["TRUSTEE_SOURCE_REPOSITORY"] = (
            "https://github.com/akash-network/trustee"
        )
        release["TRUSTEE_SOURCE_REVISION"] = "a" * 40
        release["DATABASE_TLS"] = "false"

        self.assertEqual(release_blockers(release, "qualification"), [])
        self.assertTrue(
            any(
                "DATABASE_TLS" in blocker
                for blocker in release_blockers(release, "production")
            )
        )

    def test_qualification_core_can_start_before_policy_provisioning(self) -> None:
        release = self.complete_release()
        release["TRUSTEE_SOURCE_REPOSITORY"] = (
            "https://github.com/akash-network/trustee"
        )
        release["TRUSTEE_SOURCE_REVISION"] = "a" * 40
        for key in (
            "AUDIT_OBSERVABILITY",
            "ATTESTATION_POLICY",
            "REFERENCE_VALUES",
            "GATEWAY_CONFORMANCE",
            "PROVISIONING_CONTROL_PLANE",
            "DATABASE_RECOVERY_TEST",
            "ISOLATION_TESTS",
            "EXTERNAL_E2E",
        ):
            release[key] = "false"

        self.assertEqual(
            release_blockers(release, "qualification", phase="core"), []
        )
        route_blockers = release_blockers(release, "qualification")
        self.assertTrue(any("AUDIT_OBSERVABILITY" in item for item in route_blockers))
        self.assertTrue(any("ATTESTATION_POLICY" in item for item in route_blockers))
        self.assertTrue(any("REFERENCE_VALUES" in item for item in route_blockers))

    def test_non_qualification_release_rejects_fork_source(self) -> None:
        release = self.complete_release()
        release["TRUSTEE_SOURCE_REPOSITORY"] = (
            "https://github.com/akash-network/trustee"
        )
        release["TRUSTEE_SOURCE_REVISION"] = "a" * 40
        blockers = release_blockers(release, "production")
        self.assertTrue(any("canonical upstream" in blocker for blocker in blockers))

    def test_upstream_release_requires_matching_upstream_base(self) -> None:
        release = self.complete_release()
        release["TRUSTEE_UPSTREAM_BASE_REVISION"] = "c" * 40
        blockers = release_blockers(release, "production")
        self.assertTrue(any("upstream base" in blocker for blocker in blockers))

    def test_placeholder_release_is_blocked(self) -> None:
        release = self.complete_release()
        release["TRUSTEE_IMAGE_DIGEST"] = "sha256:" + ("0" * 64)
        release["TRUSTEE_IMAGE_BUILD_REVISION"] = "0" * 40
        release["LOCAL_BLACKWELL"] = "false"
        blockers = release_blockers(release, "production")
        self.assertTrue(any("digest" in blocker for blocker in blockers))
        self.assertTrue(any("build revision" in blocker for blocker in blockers))
        self.assertTrue(any("LOCAL_BLACKWELL" in blocker for blocker in blockers))

    def test_duplicate_key_is_rejected(self) -> None:
        path = self.write_release("A=one\nA=two\n")
        with self.assertRaisesRegex(ValidationError, "duplicate key"):
            parse_release(path)

    def test_unknown_key_is_rejected(self) -> None:
        release = self.complete_release()
        release["SURPRISE"] = "true"
        path = self.write_release(
            "\n".join(f"{key}={value}" for key, value in release.items()) + "\n"
        )
        with self.assertRaisesRegex(ValidationError, "unknown keys"):
            parse_release(path)


class QualificationOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parent.parent

    def test_release_lock_names_the_fork_commit_and_upstream_base(self) -> None:
        release = parse_release(self.root / "releases/qualification.env")
        self.assertEqual(
            release["TRUSTEE_IMAGE_REPOSITORY"],
            "ghcr.io/akash-network/trustee",
        )
        self.assertEqual(
            release["TRUSTEE_SOURCE_REPOSITORY"],
            "https://github.com/akash-network/trustee",
        )
        self.assertEqual(
            release["TRUSTEE_SOURCE_REVISION"],
            "a9be1a25bccd6ec1bd5ee1f849d00332b9be9a2a",
        )
        self.assertEqual(
            release["TRUSTEE_UPSTREAM_REPOSITORY"],
            "https://github.com/confidential-containers/trustee",
        )
        self.assertEqual(
            release["TRUSTEE_UPSTREAM_BASE_REVISION"],
            "8db724e019e3a1d44d104713a340661e09f7dc40",
        )

    def test_qualification_records_only_completed_offline_gates(self) -> None:
        release = parse_release(self.root / "releases/qualification.env")
        for gate in (
            "LOCAL_BLACKWELL",
            "POSTGRES_URL_REDACTED",
            "SCOPED_RESOURCE_POLICIES",
            "CONTAINER_HARDENING",
        ):
            self.assertEqual(release[gate], "true")
        for gate in (
            "ATTESTATION_POLICY",
            "REFERENCE_VALUES",
            "GATEWAY_CONFORMANCE",
            "AUDIT_OBSERVABILITY",
            "DATABASE_RECOVERY_TEST",
            "ISOLATION_TESTS",
            "EXTERNAL_E2E",
        ):
            self.assertEqual(release[gate], "false")

    def test_config_uses_compact_local_composite_verification(self) -> None:
        config_path = (
            self.root
            / "deploy/overlays/qualification/config/kbs-config.toml"
        )
        config = tomllib.loads(config_path.read_text())
        service = config["attestation_service"]

        self.assertEqual(service["type"], "coco_as_builtin")
        self.assertEqual(service["rvps_config"]["type"], "BuiltIn")
        self.assertFalse(service["attestation_token_broker"]["verbose_token"])
        self.assertEqual(
            service["verifier_config"]["nvidia_verifier"], {"type": "Local"}
        )
        self.assertEqual(
            service["verifier_config"]["snp_verifier"],
            {"vcek_sources": [{"type": "KDS"}]},
        )

    def test_admin_service_is_private_and_absent_from_public_route(self) -> None:
        admin_service = (
            self.root / "deploy/base/service-trustee-admin.yaml"
        ).read_text()
        qualification = (
            self.root / "deploy/overlays/qualification/kustomization.yaml"
        ).read_text()
        route = (
            self.root
            / "deploy/routes/qualification/httproute-trustee-guest.yaml"
        ).read_text()

        self.assertIn("type: ClusterIP", admin_service)
        self.assertIn("name: trustee-allow-provisioner", qualification)
        self.assertIn("$patch: delete", qualification)
        self.assertNotIn("resource-policy", route)
        self.assertNotIn("attestation-policy", route)
        self.assertNotIn("reference-value", route)
        self.assertNotIn("/metrics", route)

    def test_canary_admin_runbook_uses_port_forward(self) -> None:
        runbook = (
            self.root / "docs/runbooks/qualification-deploy.md"
        ).read_text()
        self.assertIn("port-forward service/trustee-admin", runbook)

    def test_postgres_schema_provisions_every_trustee_namespace(self) -> None:
        schema = (self.root / "database/schema.sql").read_text()
        tables = set(
            re.findall(
                r"CREATE TABLE IF NOT EXISTS ([a-z_]+)\s*\(",
                schema,
            )
        )
        self.assertEqual(
            tables,
            {
                "attestation_service_policy",
                "kbs",
                "kbs_protocol_session",
                "reference_value",
                "repository",
            },
        )
        for table in tables:
            self.assertRegex(
                schema,
                rf"CREATE TABLE IF NOT EXISTS {table}\s*\(\s*"
                r"value BYTEA,\s*key TEXT PRIMARY KEY\s*\);",
            )

    def test_qualification_does_not_mount_an_unused_postgres_ca(self) -> None:
        output = subprocess.run(
            ["kubectl", "kustomize", "deploy/overlays/qualification"],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout
        self.assertNotIn("POSTGRES_CA_CERT", output)
        self.assertNotIn("mountPath: /run/trustee/postgres", output)

    def test_public_smoke_checks_admin_gets_and_metrics(self) -> None:
        smoke = (self.root / "scripts/smoke.sh").read_text()
        for probe in (
            "GET /kbs/v0/attestation-policy",
            "GET /kbs/v0/reference-value",
            "GET /kbs/v0/resource-policy",
            "GET /metrics",
        ):
            self.assertIn(probe, smoke)

    def test_qualification_image_publish_is_manual_and_attested(self) -> None:
        workflow = (
            self.root / ".github/workflows/build-qualification-image.yaml"
        ).read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s{2}push:")
        self.assertIn("scripts/verify-source-lock.sh qualification", workflow)
        self.assertIn("scripts/image-smoke.sh", workflow)
        self.assertIn("Exercise the published digest", workflow)
        self.assertIn('TRUSTEE_IMAGE="$IMAGE_REPOSITORY@$DIGEST"', workflow)
        self.assertIn(
            'io.akash.trustee.deployment-revision="$GITHUB_SHA"', workflow
        )
        self.assertIn(
            'qualification-$GITHUB_SHA-$SOURCE_REVISION', workflow
        )
        self.assertIn("Deployment source:", workflow)
        self.assertIn("--provenance=mode=max", workflow)
        self.assertIn("--sbom=true", workflow)
        self.assertNotIn(":latest", workflow)

    def test_local_operator_material_is_ignored(self) -> None:
        ignored = set((self.root / ".gitignore").read_text().splitlines())
        for pattern in (
            ".env",
            ".env.*",
            "private/",
            "artifacts/",
            "run/",
            "*.token",
        ):
            self.assertIn(pattern, ignored)

    def test_qualification_image_contains_only_builtin_kbs_features(self) -> None:
        dockerfile = (self.root / "images/trustee/Dockerfile").read_text()
        workflow = (
            self.root / ".github/workflows/build-qualification-image.yaml"
        ).read_text()
        self.assertIn("deployment/images/trustee/Dockerfile", workflow)
        self.assertIn("--no-default-features", dockerfile)
        self.assertIn("--features coco-as-builtin", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertNotIn("pkcs11", dockerfile.lower())
        self.assertNotIn("vault", dockerfile.lower())

    def test_image_smoke_proves_postgres_state_and_admin_denial(self) -> None:
        smoke = (self.root / "scripts/image-smoke.sh").read_text()
        for table in (
            "repository",
            "kbs",
            "attestation_service_policy",
            "reference_value",
            "kbs_protocol_session",
        ):
            self.assertIn(table, smoke)
        for endpoint in (
            "/kbs/v0/attestation-policy",
            "/kbs/v0/reference-value",
            "/kbs/v0/auth",
        ):
            self.assertIn(endpoint, smoke)
        self.assertNotIn("sslmode=verify-full", smoke)
        self.assertNotIn("pg_stat_ssl", smoke)
        self.assertIn("--read-only", smoke)
        self.assertIn("unauthenticated_admin_status", smoke)
        self.assertIn("PostgreSQL connection URL", smoke)
        self.assertIn("admin-curl.conf", smoke)
        self.assertIn("scripts/provision_canary.py", smoke)
        self.assertIn("--admin-token-file", smoke)
        self.assertIn("--http1.1", smoke)
        self.assertNotIn("--header \"Authorization: Bearer $admin_token\"", smoke)
        for counter in (
            "kbs_policy_approvals_total",
            "kbs_policy_violations_total",
        ):
            self.assertIn(counter, smoke)


class BootstrapPolicyTests(unittest.TestCase):
    def test_bootstrap_policy_is_exactly_deny_all(self) -> None:
        root = Path(__file__).resolve().parent.parent
        policy = (root / "policies/resource/deny-all.rego").read_text()
        self.assertEqual(
            policy,
            "package policy\n\nimport rego.v1\n\ndefault allow := false\n",
        )


class ScopedResourcePolicyCompilerTests(unittest.TestCase):
    def grant(self) -> dict[str, object]:
        return {
            "version": "v1",
            "workload": {
                "owner": "akash1synthetic000000000000000000000000000000",
                "dseq": "42",
                "gseq": 1,
                "oseq": 1,
                "service": "proof",
                "replica": 0,
            },
            "expectation": {
                "initdataSha256": "a" * 64,
                "cpuTee": "snp",
                "gpu": {"architecture": "blackwell", "count": 2},
            },
            "resources": [
                {
                    "repository": "lease-42",
                    "type": "registry-auth",
                    "tag": "private-image",
                    "sha256": "b" * 64,
                },
                {
                    "repository": "lease-42",
                    "type": "volume-key",
                    "tag": "data-v1",
                    "sha256": "c" * 64,
                },
            ],
            "expiresAt": "2030-01-01T00:00:00Z",
        }

    def test_compiler_binds_claims_and_exact_resource_path(self) -> None:
        policies = render_scoped_policies(parse_grant(self.grant()))

        self.assertEqual(
            set(policies),
            {("lease-42", "registry-auth"), ("lease-42", "volume-key")},
        )
        registry_policy = policies[("lease-42", "registry-auth")]
        self.assertIn('["lease-42", "registry-auth", "private-image"]', registry_policy)
        self.assertNotIn('"data-v1"', registry_policy)
        self.assertIn('annotated_evidence["snp"]', registry_policy)
        self.assertIn(
            'annotated_evidence["init_data"] == "' + ("a" * 64) + '"',
            registry_policy,
        )
        self.assertIn("time.now_ns() < 1893456000000000000", registry_policy)
        self.assertIn('input["submods"]["nvidia-blackwell-0"]', registry_policy)
        self.assertIn('input["submods"]["nvidia-blackwell-1"]', registry_policy)
        self.assertIn('attestation_key_id', registry_policy)
        self.assertIn('!=', registry_policy)

    def test_compiler_rejects_duplicate_resource_paths(self) -> None:
        document = self.grant()
        resources = document["resources"]
        assert isinstance(resources, list)
        resources.append(dict(resources[0]))

        with self.assertRaisesRegex(GrantValidationError, "duplicate resource path"):
            parse_grant(document)

    def test_compiler_rejects_unbound_replica(self) -> None:
        document = self.grant()
        workload = document["workload"]
        assert isinstance(workload, dict)
        workload["replica"] = 1

        with self.assertRaisesRegex(GrantValidationError, "replica"):
            parse_grant(document)

    def test_example_grant_compiles(self) -> None:
        root = Path(__file__).resolve().parent.parent
        document = json.loads(
            (root / "contracts/examples/resource-grant.synthetic.json").read_text()
        )
        policies = render_scoped_policies(parse_grant(document))
        self.assertEqual(set(policies), {("synthetic-lease", "volume-key")})

    def test_bundle_is_deterministic_and_records_expiration(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        grant_path = root / "grant.json"
        grant_path.write_text(json.dumps(self.grant(), sort_keys=True) + "\n")

        first = root / "first"
        second = root / "second"
        write_policy_bundle(grant_path, first)
        write_policy_bundle(grant_path, second)

        first_files = {
            path.name: path.read_bytes() for path in first.iterdir() if path.is_file()
        }
        second_files = {
            path.name: path.read_bytes() for path in second.iterdir() if path.is_file()
        }
        self.assertEqual(first_files, second_files)
        index = json.loads(first_files["index.json"])
        self.assertEqual(index["expiresAtEpoch"], 1893456000)
        self.assertEqual(len(index["policies"]), 2)

    def test_compiler_rejects_more_than_eight_gpus(self) -> None:
        document = self.grant()
        expectation = document["expectation"]
        assert isinstance(expectation, dict)
        gpu = expectation["gpu"]
        assert isinstance(gpu, dict)
        gpu["count"] = 9

        with self.assertRaisesRegex(GrantValidationError, "must not exceed 8"):
            parse_grant(document)

    def test_compiler_accepts_resources_needed_for_guest_bootstrap(self) -> None:
        document = self.grant()
        resources = document["resources"]
        assert isinstance(resources, list)
        resources.extend(
            [
                {
                    "repository": "lease-42",
                    "type": "security-policy",
                    "tag": "sha256-" + ("d" * 64),
                    "sha256": "e" * 64,
                },
                {
                    "repository": "lease-42",
                    "type": "signing-key",
                    "tag": "volume-v1",
                    "sha256": "f" * 64,
                },
            ]
        )

        policies = render_scoped_policies(parse_grant(document))

        self.assertIn(("lease-42", "security-policy"), policies)
        self.assertIn(("lease-42", "signing-key"), policies)


if __name__ == "__main__":
    unittest.main()
