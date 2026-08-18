#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
environment=${1:-staging}

exec python3 "$repo_root/scripts/readiness.py" readiness "$environment"
