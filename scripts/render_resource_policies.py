#!/usr/bin/env python3
"""Compile a resource grant into deterministic scoped KBS policies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


SHA256 = re.compile(r"^[0-9a-f]{64}$")
OWNER = re.compile(r"^akash1[0-9a-z]+$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
REPOSITORY_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9-]*$")
TAG_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
POLICY_FILE_DOMAIN = b"ocl.trustee.qualification-resource-policy.v1\0"


class GrantValidationError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class ResourcePath:
    repository: str
    resource_type: str
    tag: str
    sha256: str

    @property
    def scope(self) -> tuple[str, str]:
        return self.repository, self.resource_type


@dataclass(frozen=True)
class WorkloadExpectation:
    initdata_sha256: str
    cpu_tee: str
    gpu_architecture: str
    gpu_count: int


@dataclass(frozen=True)
class ResourceGrant:
    owner: str
    dseq: str
    gseq: int
    oseq: int
    service: str
    replica: int
    expectation: WorkloadExpectation
    resources: tuple[ResourcePath, ...]
    expires_at: str
    expires_at_epoch: int


def _object(value: object, name: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GrantValidationError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise GrantValidationError(f"{name} must be a non-empty string")
    return value


def _integer(value: object, name: str, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise GrantValidationError(f"{name} must be an integer >= {minimum}")
    return value


def parse_grant(document: object) -> ResourceGrant:
    root = _object(
        document,
        "grant",
        {"version", "workload", "expectation", "resources", "expiresAt"},
    )
    if root["version"] != "v1":
        raise GrantValidationError("grant version must be v1")

    workload = _object(
        root["workload"],
        "workload",
        {"owner", "dseq", "gseq", "oseq", "service", "replica"},
    )
    owner = _string(workload["owner"], "workload.owner")
    if OWNER.fullmatch(owner) is None:
        raise GrantValidationError("workload.owner is not an Akash address")
    dseq = _string(workload["dseq"], "workload.dseq")
    if POSITIVE_DECIMAL.fullmatch(dseq) is None:
        raise GrantValidationError("workload.dseq must be a positive decimal string")
    gseq = _integer(workload["gseq"], "workload.gseq")
    oseq = _integer(workload["oseq"], "workload.oseq")
    service = _string(workload["service"], "workload.service")
    replica = workload["replica"]
    if type(replica) is not int or replica != 0:
        raise GrantValidationError("workload.replica must be 0")

    expectation_document = _object(
        root["expectation"],
        "expectation",
        {"initdataSha256", "cpuTee", "gpu"},
    )
    initdata_sha256 = _string(
        expectation_document["initdataSha256"], "expectation.initdataSha256"
    )
    if SHA256.fullmatch(initdata_sha256) is None:
        raise GrantValidationError("expectation.initdataSha256 must be lowercase SHA-256")
    if expectation_document["cpuTee"] != "snp":
        raise GrantValidationError("expectation.cpuTee must be snp")
    gpu = _object(
        expectation_document["gpu"],
        "expectation.gpu",
        {"architecture", "count"},
    )
    architecture = _string(gpu["architecture"], "expectation.gpu.architecture")
    if architecture not in {"blackwell", "hopper"}:
        raise GrantValidationError("expectation.gpu.architecture is unsupported")
    gpu_count = _integer(gpu["count"], "expectation.gpu.count")
    if gpu_count > 8:
        raise GrantValidationError("expectation.gpu.count must not exceed 8")

    raw_resources = root["resources"]
    if not isinstance(raw_resources, list) or not raw_resources:
        raise GrantValidationError("resources must be a non-empty array")
    resources: list[ResourcePath] = []
    seen_paths: set[tuple[str, str, str]] = set()
    for index, item in enumerate(raw_resources):
        resource = _object(
            item,
            f"resources[{index}]",
            {"repository", "type", "tag", "sha256"},
        )
        repository = _string(resource["repository"], f"resources[{index}].repository")
        resource_type = _string(resource["type"], f"resources[{index}].type")
        tag = _string(resource["tag"], f"resources[{index}].tag")
        digest = _string(resource["sha256"], f"resources[{index}].sha256")
        if REPOSITORY_SEGMENT.fullmatch(repository) is None:
            raise GrantValidationError(f"resources[{index}].repository is invalid")
        if resource_type not in {
            "environment",
            "registry-auth",
            "security-policy",
            "signing-key",
            "volume-key",
        }:
            raise GrantValidationError(f"resources[{index}].type is unsupported")
        if TAG_SEGMENT.fullmatch(tag) is None:
            raise GrantValidationError(f"resources[{index}].tag is invalid")
        if SHA256.fullmatch(digest) is None:
            raise GrantValidationError(f"resources[{index}].sha256 is invalid")
        path = (repository, resource_type, tag)
        if path in seen_paths:
            raise GrantValidationError("duplicate resource path")
        seen_paths.add(path)
        resources.append(ResourcePath(repository, resource_type, tag, digest))

    expires_at = _string(root["expiresAt"], "expiresAt")
    try:
        parsed_expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise GrantValidationError("expiresAt must be an RFC 3339 timestamp") from error
    if parsed_expiration.tzinfo is None:
        raise GrantValidationError("expiresAt must include a timezone")
    expires_at_epoch = int(parsed_expiration.timestamp())

    return ResourceGrant(
        owner=owner,
        dseq=dseq,
        gseq=gseq,
        oseq=oseq,
        service=service,
        replica=replica,
        expectation=WorkloadExpectation(
            initdata_sha256=initdata_sha256,
            cpu_tee="snp",
            gpu_architecture=architecture,
            gpu_count=gpu_count,
        ),
        resources=tuple(sorted(resources)),
        expires_at=expires_at,
        expires_at_epoch=expires_at_epoch,
    )


def _gpu_labels(architecture: str, count: int) -> list[str]:
    base = f"nvidia-{architecture}"
    if count == 1:
        return [base]
    return [f"{base}-{index}" for index in range(count)]


def _policy_for_scope(grant: ResourceGrant, resources: list[ResourcePath]) -> str:
    architecture = grant.expectation.gpu_architecture
    architecture_claim = architecture.title()
    labels = _gpu_labels(architecture, grant.expectation.gpu_count)
    path_rules = "\n\n".join(
        "allowed_resource_path if {\n"
        f"    data[\"resource-path\"] == {json.dumps([item.repository, item.resource_type, item.tag])}\n"
        "}"
        for item in resources
    )

    gpu_checks: list[str] = []
    for label in labels:
        submod = f'input["submods"][{json.dumps(label)}]'
        evidence = f'{submod}["ear.veraison.annotated-evidence"]["nvidia"]'
        gpu_checks.extend(
            [
                f'    {submod}["ear.status"] == "affirming"',
                f'    {evidence}["arch"] == {json.dumps(architecture_claim)}',
                f'    regex.match("^sha256:[0-9a-f]{{64}}$", {evidence}["attestation_key_id"])',
            ]
        )
    for left in range(len(labels)):
        for right in range(left + 1, len(labels)):
            left_key = (
                f'input["submods"][{json.dumps(labels[left])}]'
                '["ear.veraison.annotated-evidence"]["nvidia"]["attestation_key_id"]'
            )
            right_key = (
                f'input["submods"][{json.dumps(labels[right])}]'
                '["ear.veraison.annotated-evidence"]["nvidia"]["attestation_key_id"]'
            )
            gpu_checks.append(f"    {left_key} != {right_key}")

    return f'''package policy
import rego.v1

default allow := false

cpu0 := input["submods"]["cpu0"]
annotated_evidence := cpu0["ear.veraison.annotated-evidence"]

{path_rules}

allow if {{
    data.plugin == "resource"
    count(data.query) == 0
    allowed_resource_path
    time.now_ns() < {grant.expires_at_epoch * 1_000_000_000}
    count(input["submods"]) == {grant.expectation.gpu_count + 1}
    cpu0["ear.status"] == "affirming"
    annotated_evidence["snp"]
    annotated_evidence["init_data"] == "{grant.expectation.initdata_sha256}"
{chr(10).join(gpu_checks)}
}}
'''


def render_scoped_policies(grant: ResourceGrant) -> dict[tuple[str, str], str]:
    grouped: dict[tuple[str, str], list[ResourcePath]] = {}
    for resource in grant.resources:
        grouped.setdefault(resource.scope, []).append(resource)
    return {
        scope: _policy_for_scope(grant, sorted(resources))
        for scope, resources in sorted(grouped.items())
    }


def _policy_filename(scope: tuple[str, str]) -> str:
    digest = hashlib.sha256(POLICY_FILE_DOMAIN)
    for segment in scope:
        encoded = segment.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"sha256-{digest.hexdigest()}.rego"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GrantValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)


def write_policy_bundle(grant_path: Path, output_dir: Path) -> None:
    raw_grant = grant_path.read_bytes()
    document = json.loads(raw_grant, object_pairs_hook=_reject_duplicate_keys)
    grant = parse_grant(document)
    policies = render_scoped_policies(grant)

    output_dir.mkdir(mode=0o700)
    records: list[dict[str, object]] = []
    for scope, policy in policies.items():
        filename = _policy_filename(scope)
        content = policy.encode()
        _write_new(output_dir / filename, content)
        resources = [item for item in grant.resources if item.scope == scope]
        records.append(
            {
                "repository": scope[0],
                "type": scope[1],
                "file": filename,
                "policySha256": hashlib.sha256(content).hexdigest(),
                "resources": [
                    {"tag": item.tag, "sha256": item.sha256} for item in resources
                ],
            }
        )

    index = {
        "version": "v1",
        "grantSha256": hashlib.sha256(raw_grant).hexdigest(),
        "workload": {
            "owner": grant.owner,
            "dseq": grant.dseq,
            "gseq": grant.gseq,
            "oseq": grant.oseq,
            "service": grant.service,
            "replica": grant.replica,
        },
        "expiresAt": grant.expires_at,
        "expiresAtEpoch": grant.expires_at_epoch,
        "policies": records,
    }
    _write_new(
        output_dir / "index.json",
        (json.dumps(index, indent=2, sort_keys=True) + "\n").encode(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grant", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        write_policy_bundle(args.grant, args.output_dir)
    except (GrantValidationError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
