from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class ClusterPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parent.parent
        cls.script = cls.root / "scripts/cluster-preflight.sh"

    def run_preflight(
        self,
        *,
        gateway_namespace: str | None,
        gateway_role: str = "edge",
        gateway_pod: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        fake_bin = Path(directory.name)
        python = fake_bin / "python3"
        python.write_text("#!/usr/bin/env bash\nexit 0\n")
        python.chmod(0o755)
        kubectl = fake_bin / "kubectl"
        kubectl.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "config get-contexts sandbox --output=name")
    printf 'sandbox\\n'
    ;;
  *"get namespace edge --output=jsonpath="*)
    printf '%s' "${FAKE_GATEWAY_ROLE:-edge}"
    ;;
  *"get pods --namespace edge --selector=ocl.network/trustee-ingress=true --field-selector=status.phase=Running --output=name"*)
    if [[ ${FAKE_GATEWAY_POD:-present} == present ]]; then
      printf 'pod/gateway-ready\\n'
    fi
    ;;
  *)
    printf 'object/test\\n'
    ;;
esac
"""
        )
        kubectl.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "KUBE_CONTEXT": "sandbox",
                "FAKE_GATEWAY_ROLE": gateway_role,
                "FAKE_GATEWAY_POD": "present" if gateway_pod else "missing",
            }
        )
        if gateway_namespace is not None:
            environment["TRUSTEE_GATEWAY_NAMESPACE"] = gateway_namespace
        else:
            environment.pop("TRUSTEE_GATEWAY_NAMESPACE", None)
        return subprocess.run(
            [str(self.script), "qualification"],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_gateway_namespace_is_required(self) -> None:
        result = self.run_preflight(gateway_namespace=None)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TRUSTEE_GATEWAY_NAMESPACE is required", result.stderr)

    def test_gateway_namespace_must_carry_the_network_policy_role(self) -> None:
        result = self.run_preflight(
            gateway_namespace="edge", gateway_role="not-edge"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ocl.network/role=edge", result.stderr)

    def test_matching_gateway_namespace_and_pod_pass(self) -> None:
        result = self.run_preflight(gateway_namespace="edge")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cluster preflight passed", result.stdout)

    def test_gateway_data_plane_pod_must_be_running(self) -> None:
        result = self.run_preflight(gateway_namespace="edge", gateway_pod=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no running pod", result.stderr)


if __name__ == "__main__":
    unittest.main()
