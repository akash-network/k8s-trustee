#!/usr/bin/env python3
"""Provision one validated canary grant through Trustee's private admin API."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit


SHA256 = re.compile(r"^[0-9a-f]{64}$")
PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]*$")
POLICY_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
MAX_RESOURCE_BYTES = 2 * 1024 * 1024
MAX_POLICY_BYTES = 2 * 1024 * 1024


class ProvisioningError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyRecord:
    repository: str
    resource_type: str
    source: bytes
    sha256: str

    @property
    def endpoint(self) -> str:
        return f"/kbs/v0/resource-policy/{self.repository}/{self.resource_type}"


@dataclass(frozen=True)
class ResourceRecord:
    repository: str
    resource_type: str
    tag: str
    body: bytes
    sha256: str

    @property
    def endpoint(self) -> str:
        return f"/kbs/v0/resource/{self.repository}/{self.resource_type}/{self.tag}"


@dataclass(frozen=True)
class ProvisioningBundle:
    grant_sha256: str
    policies: tuple[PolicyRecord, ...]
    resources: tuple[ResourceRecord, ...]


class AdminClient(Protocol):
    def post_bytes(self, path: str, body: bytes, content_type: str) -> None: ...

    def get_bytes(self, path: str) -> bytes: ...


def _object(value: object, name: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProvisioningError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProvisioningError(f"{name} must be a non-empty string")
    return value


def _digest(value: object, name: str) -> str:
    digest = _string(value, name)
    if SHA256.fullmatch(digest) is None:
        raise ProvisioningError(f"{name} must be lowercase SHA-256")
    return digest


def _segment(value: object, name: str) -> str:
    segment = _string(value, name)
    if PATH_SEGMENT.fullmatch(segment) is None:
        raise ProvisioningError(f"{name} is not a valid KBS path segment")
    return segment


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProvisioningError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _regular_file(path: Path, name: str, private: bool = False) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProvisioningError(f"{name} is not readable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ProvisioningError(f"{name} must be a regular file")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProvisioningError(f"{name} permissions must not allow group or other access")
    return metadata


def _read_bounded(path: Path, name: str, limit: int, private: bool = False) -> bytes:
    metadata = _regular_file(path, name, private=private)
    if metadata.st_size < 1 or metadata.st_size > limit:
        raise ProvisioningError(f"{name} size must be between 1 and {limit} bytes")
    value = path.read_bytes()
    if len(value) != metadata.st_size:
        raise ProvisioningError(f"{name} changed while it was being read")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_bundle(bundle_dir: Path, resource_dir: Path) -> ProvisioningBundle:
    if bundle_dir.is_symlink() or not bundle_dir.is_dir():
        raise ProvisioningError("policy bundle must be a directory, not a symlink")
    if resource_dir.is_symlink() or not resource_dir.is_dir():
        raise ProvisioningError("resource root must be a directory, not a symlink")

    index_path = bundle_dir / "index.json"
    index_raw = _read_bounded(index_path, "policy index", MAX_POLICY_BYTES)
    try:
        document = json.loads(index_raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisioningError(f"policy index is invalid JSON: {error}") from error
    root = _object(
        document,
        "policy index",
        {
            "version",
            "grantSha256",
            "workload",
            "expiresAt",
            "expiresAtEpoch",
            "policies",
        },
    )
    if root["version"] != "v1":
        raise ProvisioningError("policy index version must be v1")
    grant_sha256 = _digest(root["grantSha256"], "grantSha256")
    if not isinstance(root["policies"], list) or not root["policies"]:
        raise ProvisioningError("policy index must contain policies")

    policies: list[PolicyRecord] = []
    resources: list[ResourceRecord] = []
    seen_scopes: set[tuple[str, str]] = set()
    seen_resources: set[tuple[str, str, str]] = set()
    expected_resource_files: set[Path] = set()

    for policy_index, raw_policy in enumerate(root["policies"]):
        policy = _object(
            raw_policy,
            f"policies[{policy_index}]",
            {"repository", "type", "file", "policySha256", "resources"},
        )
        repository = _segment(
            policy["repository"], f"policies[{policy_index}].repository"
        )
        resource_type = _segment(policy["type"], f"policies[{policy_index}].type")
        scope = (repository, resource_type)
        if scope in seen_scopes:
            raise ProvisioningError("policy index contains a duplicate scope")
        seen_scopes.add(scope)

        filename = _string(policy["file"], f"policies[{policy_index}].file")
        if POLICY_FILENAME.fullmatch(filename) is None:
            raise ProvisioningError(f"policies[{policy_index}].file is unsafe")
        source = _read_bounded(
            bundle_dir / filename,
            f"policy file {filename}",
            MAX_POLICY_BYTES,
        )
        policy_sha256 = _digest(
            policy["policySha256"], f"policies[{policy_index}].policySha256"
        )
        if _sha256(source) != policy_sha256:
            raise ProvisioningError(f"policy digest does not match {filename}")
        policies.append(
            PolicyRecord(repository, resource_type, source, policy_sha256)
        )

        raw_resources = policy["resources"]
        if not isinstance(raw_resources, list) or not raw_resources:
            raise ProvisioningError(f"policies[{policy_index}].resources must not be empty")
        for resource_index, raw_resource in enumerate(raw_resources):
            resource = _object(
                raw_resource,
                f"policies[{policy_index}].resources[{resource_index}]",
                {"tag", "sha256"},
            )
            tag = _segment(
                resource["tag"],
                f"policies[{policy_index}].resources[{resource_index}].tag",
            )
            resource_key = (repository, resource_type, tag)
            if resource_key in seen_resources:
                raise ProvisioningError("policy index contains a duplicate resource")
            seen_resources.add(resource_key)
            body_path = resource_dir / repository / resource_type / tag
            body = _read_bounded(
                body_path,
                f"resource {repository}/{resource_type}/{tag}",
                MAX_RESOURCE_BYTES,
                private=True,
            )
            resource_sha256 = _digest(
                resource["sha256"],
                f"policies[{policy_index}].resources[{resource_index}].sha256",
            )
            if _sha256(body) != resource_sha256:
                raise ProvisioningError(
                    f"resource digest does not match {repository}/{resource_type}/{tag}"
                )
            expected_resource_files.add(body_path)
            resources.append(
                ResourceRecord(
                    repository,
                    resource_type,
                    tag,
                    body,
                    resource_sha256,
                )
            )

    actual_resource_files: set[Path] = set()
    for path in resource_dir.rglob("*"):
        if path.is_symlink():
            raise ProvisioningError(f"resource tree contains a symlink: {path.name}")
        if path.is_file():
            actual_resource_files.add(path)
    extras = actual_resource_files - expected_resource_files
    if extras:
        raise ProvisioningError("resource tree contains an unindexed resource")
    missing = expected_resource_files - actual_resource_files
    if missing:
        raise ProvisioningError("resource tree is missing an indexed resource")

    return ProvisioningBundle(
        grant_sha256=grant_sha256,
        policies=tuple(sorted(policies, key=lambda item: item.endpoint)),
        resources=tuple(sorted(resources, key=lambda item: item.endpoint)),
    )


def provision_bundle(bundle: ProvisioningBundle, client: AdminClient) -> dict[str, object]:
    for policy in bundle.policies:
        encoded = base64.urlsafe_b64encode(policy.source).rstrip(b"=").decode("ascii")
        body = json.dumps({"policy": encoded}, separators=(",", ":")).encode()
        client.post_bytes(policy.endpoint, body, "application/json")
        if client.get_bytes(policy.endpoint) != policy.source:
            raise ProvisioningError(f"policy readback mismatch for {policy.endpoint}")

    for resource in bundle.resources:
        client.post_bytes(
            resource.endpoint, resource.body, "application/octet-stream"
        )

    return {
        "version": "v1",
        "grantSha256": bundle.grant_sha256,
        "policies": [
            {"path": policy.endpoint, "sha256": policy.sha256}
            for policy in bundle.policies
        ],
        "resources": [
            {"path": resource.endpoint, "sha256": resource.sha256}
            for resource in bundle.resources
        ],
    }


def read_private_token(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ProvisioningError("admin token must be a private regular file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProvisioningError("admin token must be a private regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ProvisioningError(
                "admin token permissions must not allow group or other access"
            )
        if metadata.st_size < 1 or metadata.st_size > 16 * 1024:
            raise ProvisioningError("admin token has an invalid size")
        with os.fdopen(descriptor, "rb", closefd=False) as token_file:
            token = token_file.read(16 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(token) != metadata.st_size:
        raise ProvisioningError("admin token changed while it was being read")
    try:
        value = token.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProvisioningError("admin token must be an ASCII JWT") from error
    if value.endswith("\n"):
        value = value[:-1]
    if JWT.fullmatch(value) is None:
        raise ProvisioningError("admin token must be a compact JWT")
    return value


class CurlAdminClient:
    def __init__(
        self,
        base_url: str,
        ca_certificate: Path,
        token: str,
        connect_address: str,
        connect_port: int | None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ProvisioningError("base URL must be an HTTPS origin")
        if connect_address not in {"127.0.0.1", "::1"}:
            raise ProvisioningError("canary admin connection must use a loopback port forward")
        if shutil.which("curl") is None:
            raise ProvisioningError("curl is required")
        self._origin = base_url.rstrip("/")
        self._hostname = parsed.hostname
        self._origin_port = parsed.port or 443
        self._connect_address = connect_address
        self._connect_port = connect_port or self._origin_port
        self._ca_certificate = _read_bounded(
            ca_certificate, "backend CA certificate", 256 * 1024
        )
        self._token = token

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> bytes:
        if not path.startswith("/kbs/v0/") or "?" in path or "#" in path:
            raise ProvisioningError("admin request path is invalid")
        with tempfile.TemporaryDirectory(prefix="trustee-admin-") as directory:
            temporary = Path(directory)
            ca_path = temporary / "ca.pem"
            ca_descriptor = os.open(
                ca_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(ca_descriptor, "wb") as output:
                output.write(self._ca_certificate)
            arguments = [
                "curl",
                "--disable",
                "--config",
                "-",
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--proto",
                "=https",
                "--noproxy",
                "*",
                "--http1.1",
                "--tlsv1.2",
                "--connect-timeout",
                "5",
                "--max-time",
                "30",
                "--max-filesize",
                str(MAX_POLICY_BYTES),
                "--cacert",
                str(ca_path),
                "--connect-to",
                (
                    f"{self._hostname}:{self._origin_port}:"
                    f"{self._connect_address}:{self._connect_port}"
                ),
                "--request",
                method,
            ]
            if content_type is not None:
                arguments.extend(["--header", f"Content-Type: {content_type}"])
            if body is not None:
                body_path = temporary / "body"
                body_descriptor = os.open(
                    body_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                with os.fdopen(body_descriptor, "wb") as output:
                    output.write(body)
                arguments.extend(["--data-binary", f"@{body_path}"])
            arguments.append(self._origin + path)
            config = f'header = "Authorization: Bearer {self._token}"\n'
            result = subprocess.run(
                arguments,
                input=config.encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ProvisioningError(
                f"Trustee admin request failed for {method} {path}: {detail[:500]}"
            )
        if len(result.stdout) > MAX_POLICY_BYTES:
            raise ProvisioningError("Trustee admin response exceeded the size limit")
        return result.stdout

    def post_bytes(self, path: str, body: bytes, content_type: str) -> None:
        self._request("POST", path, body, content_type)

    def get_bytes(self, path: str) -> bytes:
        return self._request("GET", path)


def _write_new_json(path: Path, document: object) -> None:
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    apply = subparsers.add_parser("apply")
    for command in (validate, apply):
        command.add_argument("--bundle", required=True, type=Path)
        command.add_argument("--resources", required=True, type=Path)
    apply.add_argument("--base-url", required=True)
    apply.add_argument("--ca-certificate", required=True, type=Path)
    apply.add_argument("--admin-token-file", required=True, type=Path)
    apply.add_argument("--connect-address", default="127.0.0.1")
    apply.add_argument("--connect-port", type=int)
    apply.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()

    try:
        bundle = load_bundle(args.bundle, args.resources)
        if args.command == "validate":
            print(
                f"validated {len(bundle.policies)} scoped policies and "
                f"{len(bundle.resources)} resources"
            )
            return
        token = read_private_token(args.admin_token_file)
        client = CurlAdminClient(
            args.base_url,
            args.ca_certificate,
            token,
            args.connect_address,
            args.connect_port,
        )
        receipt = provision_bundle(bundle, client)
        _write_new_json(args.receipt, receipt)
        print(
            f"provisioned {len(bundle.policies)} scoped policies and "
            f"{len(bundle.resources)} resources"
        )
    except (ProvisioningError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
