#!/usr/bin/env python3
"""Validate repository structure and fail closed on incomplete releases."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path


REQUIRED_KEYS = {
    "TRUSTEE_IMAGE_REPOSITORY",
    "TRUSTEE_IMAGE_DIGEST",
    "TRUSTEE_IMAGE_BUILD_REVISION",
    "TRUSTEE_SOURCE_REPOSITORY",
    "TRUSTEE_SOURCE_REVISION",
    "TRUSTEE_UPSTREAM_REPOSITORY",
    "TRUSTEE_UPSTREAM_BASE_REVISION",
    "PUBLIC_HOSTNAME",
    "BACKEND_TLS_HOSTNAME",
    "LOCAL_BLACKWELL",
    "POSTGRES_URL_REDACTED",
    "SCOPED_RESOURCE_POLICIES",
    "PROVISIONING_CONTROL_PLANE",
    "ATTESTATION_POLICY",
    "REFERENCE_VALUES",
    "GATEWAY_CONFORMANCE",
    "CONTAINER_HARDENING",
    "AUDIT_OBSERVABILITY",
    "DATABASE_TLS",
    "DATABASE_RECOVERY_TEST",
    "ISOLATION_TESTS",
    "EXTERNAL_E2E",
}

CAPABILITY_KEYS = {
    "LOCAL_BLACKWELL",
    "POSTGRES_URL_REDACTED",
    "SCOPED_RESOURCE_POLICIES",
    "PROVISIONING_CONTROL_PLANE",
    "ATTESTATION_POLICY",
    "REFERENCE_VALUES",
    "GATEWAY_CONFORMANCE",
    "CONTAINER_HARDENING",
    "AUDIT_OBSERVABILITY",
    "DATABASE_TLS",
    "DATABASE_RECOVERY_TEST",
    "ISOLATION_TESTS",
    "EXTERNAL_E2E",
}

QUALIFICATION_RESULT_KEYS = {
    "DATABASE_RECOVERY_TEST",
    "ISOLATION_TESTS",
    "EXTERNAL_E2E",
}

QUALIFICATION_SOURCE_LIMITATIONS = {
    "DATABASE_TLS",
}

QUALIFICATION_CORE_DEFERRED_KEYS = {
    "AUDIT_OBSERVABILITY",
    "ATTESTATION_POLICY",
    "REFERENCE_VALUES",
    "GATEWAY_CONFORMANCE",
}

ZERO_DIGEST = "sha256:" + ("0" * 64)
ZERO_REVISION = "0" * 40
UPSTREAM_REPOSITORY = "https://github.com/confidential-containers/trustee"
QUALIFICATION_REPOSITORY = "https://github.com/akash-network/trustee"


class ValidationError(ValueError):
    pass


def parse_release(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValidationError(f"{path}:{number}: expected KEY=value")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValidationError(f"{path}:{number}: invalid key {key!r}")
        if key in result:
            raise ValidationError(f"{path}:{number}: duplicate key {key}")
        if not value or any(character.isspace() for character in value):
            raise ValidationError(f"{path}:{number}: {key} has an invalid value")
        result[key] = value

    missing = REQUIRED_KEYS - result.keys()
    extra = result.keys() - REQUIRED_KEYS
    if missing:
        raise ValidationError(f"{path}: missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ValidationError(f"{path}: unknown keys: {', '.join(sorted(extra))}")
    return result


def release_blockers(
    release: dict[str, str], environment: str, *, phase: str = "route"
) -> list[str]:
    if phase not in {"core", "route"}:
        raise ValidationError(f"unknown readiness phase: {phase}")
    blockers: list[str] = []
    repository = release["TRUSTEE_IMAGE_REPOSITORY"]
    digest = release["TRUSTEE_IMAGE_DIGEST"]
    image_build_revision = release["TRUSTEE_IMAGE_BUILD_REVISION"]
    revision = release["TRUSTEE_SOURCE_REVISION"]
    upstream_revision = release["TRUSTEE_UPSTREAM_BASE_REVISION"]

    if ".invalid" in repository or repository.startswith("REPLACE_"):
        blockers.append("Trustee image repository is still a placeholder")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or digest == ZERO_DIGEST:
        blockers.append("Trustee image is not locked to a real SHA-256 digest")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", image_build_revision)
        or image_build_revision == ZERO_REVISION
    ):
        blockers.append("Trustee image build revision is not a real commit")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or revision == ZERO_REVISION:
        blockers.append("Trustee source revision is not a real 40-character commit")
    if release["TRUSTEE_UPSTREAM_REPOSITORY"] != UPSTREAM_REPOSITORY:
        blockers.append("Trustee upstream repository is not canonical upstream")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", upstream_revision)
        or upstream_revision == ZERO_REVISION
    ):
        blockers.append("Trustee upstream base is not a real 40-character commit")

    source_repository = release["TRUSTEE_SOURCE_REPOSITORY"]
    if environment == "qualification":
        if source_repository != QUALIFICATION_REPOSITORY:
            blockers.append("Qualification Trustee source is not the Akash fork")
    elif source_repository != UPSTREAM_REPOSITORY:
        blockers.append("Trustee source is not canonical upstream")
    elif revision != upstream_revision:
        blockers.append("Canonical Trustee revision and upstream base differ")
    required_capabilities = CAPABILITY_KEYS
    if environment == "qualification":
        required_capabilities = required_capabilities - {
            "PROVISIONING_CONTROL_PLANE",
            *QUALIFICATION_SOURCE_LIMITATIONS,
            *QUALIFICATION_RESULT_KEYS,
        }
        if phase == "core":
            required_capabilities -= QUALIFICATION_CORE_DEFERRED_KEYS
    for key in sorted(required_capabilities):
        if release[key] != "true":
            blockers.append(f"{key} has not been qualified")
    for key in ("PUBLIC_HOSTNAME", "BACKEND_TLS_HOSTNAME"):
        if release[key].endswith(".invalid") or release[key].startswith("REPLACE_"):
            blockers.append(f"{key} is still a placeholder")
    return blockers


def qualification_result_blockers(release: dict[str, str]) -> list[str]:
    return [
        f"{key} has not been qualified"
        for key in sorted(QUALIFICATION_RESULT_KEYS)
        if release[key] != "true"
    ]


def _load_kbs_config(path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as error:
        raise ValidationError(f"{path}: invalid TOML: {error}") from error


def validate_environment(root: Path, environment: str) -> dict[str, str]:
    overlay = root / "deploy" / "overlays" / environment
    release_path = root / "releases" / f"{environment}.env"
    release = parse_release(release_path)
    config = _load_kbs_config(overlay / "config" / "kbs-config.toml")

    expected = {
        "session_storage_type": "Postgres",
        "require_scoped_resource_policy": True,
    }
    for key, value in expected.items():
        if config.get(key) != value:
            raise ValidationError(f"{environment}: KBS config must set {key}={value!r}")

    http = config.get("http_server", {})
    token = config.get("attestation_token", {})
    service = config.get("attestation_service", {})
    admin = config.get("admin", {})
    storage = config.get("storage_backend", {})
    if not isinstance(http, dict) or http.get("insecure_http") is not False:
        raise ValidationError(f"{environment}: KBS native TLS must be enabled")
    if not http.get("private_key") or not http.get("certificate"):
        raise ValidationError(f"{environment}: KBS TLS paths are required")
    if not isinstance(token, dict) or token.get("insecure_header_jwk") is not False:
        raise ValidationError(f"{environment}: insecure attestation token JWK is forbidden")
    if not token.get("trusted_certs_paths"):
        raise ValidationError(f"{environment}: attestation token roots are required")
    if not isinstance(service, dict) or service.get("type") != "coco_as_builtin":
        raise ValidationError(f"{environment}: built-in CoCo AS is required")
    token_broker = service.get("attestation_token_broker", {})
    if token_broker.get("verbose_token") is not False:
        raise ValidationError(f"{environment}: verbose attestation tokens are forbidden")
    rvps = service.get("rvps_config", {})
    if rvps.get("type") != "BuiltIn" or rvps.get("storage_type") is not None:
        raise ValidationError(
            f"{environment}: built-in RVPS must inherit PostgreSQL storage"
        )
    nvidia = service.get("verifier_config", {}).get("nvidia_verifier", {})
    if nvidia.get("type") != "Local":
        raise ValidationError(f"{environment}: NVIDIA verification must be local")
    snp = service.get("verifier_config", {}).get("snp_verifier", {})
    if snp.get("vcek_sources") != [{"type": "KDS"}]:
        raise ValidationError(f"{environment}: SNP VCEK source must be AMD KDS")
    if not isinstance(admin, dict) or admin.get("authorization_mode") != (
        "AuthenticatedAuthorization"
    ):
        raise ValidationError(f"{environment}: authenticated admin mode is required")
    if not admin.get("authentication", {}).get("bearer_jwt", {}).get(
        "identity_providers"
    ):
        raise ValidationError(f"{environment}: an admin identity provider is required")
    if not admin.get("authorization", {}).get("regex_acl", {}).get("acls"):
        raise ValidationError(f"{environment}: an admin ACL is required")
    if not isinstance(storage, dict) or storage.get("storage_type") != "Postgres":
        raise ValidationError(f"{environment}: PostgreSQL storage is required")

    kustomization = (overlay / "kustomization.yaml").read_text()
    image_names = re.findall(r"^\s*newName:\s*(\S+)\s*$", kustomization, re.MULTILINE)
    image_digests = re.findall(
        r"^\s*digest:\s*(sha256:[0-9a-f]+)\s*$", kustomization, re.MULTILINE
    )
    if image_names != [release["TRUSTEE_IMAGE_REPOSITORY"]]:
        raise ValidationError(f"{environment}: image repository and release lock differ")
    if image_digests != [release["TRUSTEE_IMAGE_DIGEST"]]:
        raise ValidationError(f"{environment}: image digest and release lock differ")

    route = (
        root
        / "deploy"
        / "routes"
        / environment
        / "httproute-trustee-guest.yaml"
    ).read_text()
    allowed_paths = {
        "/healthz",
        "/kbs/v0/attest",
        "/kbs/v0/auth",
        "/kbs/v0/resource/",
    }
    route_paths = set(re.findall(r"^\s*value:\s*(/\S+)\s*$", route, re.MULTILINE))
    if route_paths != allowed_paths:
        raise ValidationError(f"{environment}: public route path allowlist changed")
    if re.search(r"resource-policy|attestation-policy|reference-value|/metrics", route):
        raise ValidationError(f"{environment}: public route contains an admin path")
    if route.count("method: POST") != 2 or route.count("method: GET") != 2:
        raise ValidationError(f"{environment}: public route method allowlist changed")

    all_yaml = "\n".join(path.read_text() for path in root.rglob("*.yaml"))
    if ("-----BEGIN " + "PRIVATE KEY-----") in all_yaml or re.search(
        r"^kind:\s*Secret\s*$", all_yaml, re.MULTILINE
    ):
        raise ValidationError("literal Kubernetes Secrets or private keys are forbidden")
    if re.search(r"postgres(?:ql)?://[^\s]+:[^\s]+@", all_yaml, re.IGNORECASE):
        raise ValidationError("a PostgreSQL credential appears in a manifest")
    return release


def validate_render(path: Path) -> None:
    rendered = path.read_text()
    required = (
        "kind: Deployment",
        "replicas: 1",
        "type: Recreate",
        "runAsNonRoot: true",
        "readOnlyRootFilesystem: true",
        "authorization_mode = \"AuthenticatedAuthorization\"",
        "require_scoped_resource_policy = true",
        "type = \"Local\"",
        "verbose_token = false",
        'vcek_sources = [{ type = "KDS" }]',
        "storage_type = \"Postgres\"",
    )
    for item in required:
        if item not in rendered:
            raise ValidationError(f"rendered manifest is missing {item!r}")
    image_refs = re.findall(r"^\s*image:\s*(\S+)\s*$", rendered, re.MULTILINE)
    if len(image_refs) != 1 or not re.fullmatch(
        r"[^\s@]+@sha256:[0-9a-f]{64}", image_refs[0]
    ):
        raise ValidationError("rendered Trustee image is not digest-pinned")
    forbidden = (
        "authorization_mode = \"InsecureAllowAll\"",
        "insecure_header_jwk = true",
        "storage_type = \"LocalFs\"",
        "type = \"Remote\"",
    )
    for item in forbidden:
        if item in rendered:
            raise ValidationError(f"rendered manifest contains forbidden setting {item!r}")
    if re.search(r"^kind:\s*(Gateway|HTTPRoute)\s*$", rendered, re.MULTILINE):
        raise ValidationError("core deployment must not activate a public route")


def validate_route_render(path: Path) -> None:
    rendered = path.read_text()
    kinds = re.findall(r"^kind:\s*(\S+)\s*$", rendered, re.MULTILINE)
    expected = ["BackendTLSPolicy", "Certificate", "Gateway", "HTTPRoute"]
    if sorted(kinds) != sorted(expected):
        raise ValidationError(
            f"route activation must contain exactly {', '.join(expected)}"
        )
    if "resource-policy" in rendered or "attestation-policy" in rendered:
        raise ValidationError("route activation contains an admin path")
    if "reference-value" in rendered or "value: /metrics" in rendered:
        raise ValidationError("route activation contains an admin or metrics path")
    required_tls = (
        "protocol: HTTPS",
        "mode: Terminate",
        "kind: BackendTLSPolicy",
        "wellKnownCACertificates: System",
    )
    for item in required_tls:
        if item not in rendered:
            raise ValidationError(f"route activation is missing TLS setting {item!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "validate",
            "core-readiness",
            "readiness",
            "qualification-status",
            "render",
            "route-render",
        ),
    )
    parser.add_argument("target")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    args = parser.parse_args()
    try:
        if args.mode == "render":
            validate_render(Path(args.target))
            print(f"{args.target}: rendered invariants valid")
            return 0
        if args.mode == "route-render":
            validate_route_render(Path(args.target))
            print(f"{args.target}: route activation invariants valid")
            return 0
        release = validate_environment(args.root, args.target)
        if args.mode == "validate":
            print(f"{args.target}: repository structure valid")
            return 0
        if args.mode == "core-readiness" and args.target != "qualification":
            raise ValidationError(
                "core-readiness is only valid for the qualification environment"
            )
        readiness_phase = "core" if args.mode == "core-readiness" else "route"
        blockers = release_blockers(release, args.target, phase=readiness_phase)
        if args.mode == "qualification-status":
            if args.target != "qualification":
                raise ValidationError(
                    "qualification-status is only valid for the qualification environment"
                )
            blockers.extend(qualification_result_blockers(release))
        overlay = args.root / "deploy" / "overlays" / args.target
        route_dir = args.root / "deploy" / "routes" / args.target
        placeholder_files = [
            str(path.relative_to(args.root))
            for path in (*overlay.rglob("*"), *route_dir.rglob("*"))
            if path.is_file()
            and ("REPLACE_ME" in path.read_text() or ".invalid" in path.read_text())
        ]
        if placeholder_files:
            blockers.append(
                "environment manifests still contain placeholders: "
                + ", ".join(placeholder_files)
            )
        postgres_policy = (overlay / "networkpolicy-allow-postgres.yaml").read_text()
        if "192.0.2." in postgres_policy:
            blockers.append("PostgreSQL egress still uses the TEST-NET placeholder")
        if blockers:
            print(f"{args.target}: not ready", file=sys.stderr)
            for blocker in blockers:
                print(f"- {blocker}", file=sys.stderr)
            return 1
        print(f"{args.target}: release gates satisfied")
        return 0
    except (OSError, ValidationError, KeyError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
