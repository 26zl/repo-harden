#!/usr/bin/env bash
set -euo pipefail

test "$#" = 2
artifact=$1
document=$2
: "${REPO_HARDEN_SBOM_CREATED:?REPO_HARDEN_SBOM_CREATED is required}"

temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
syft "$artifact" --output "spdx-json=$temporary" --enrich all
if command -v sha256sum >/dev/null 2>&1; then
  artifact_digest=$(sha256sum "$artifact" | awk '{print $1}')
else
  artifact_digest=$(shasum -a 256 "$artifact" | awk '{print $1}')
fi
namespace="https://github.com/26zl/repo-harden/sbom/sha256/$artifact_digest"
jq --arg created "$REPO_HARDEN_SBOM_CREATED" --arg namespace "$namespace" \
  '.creationInfo.created = $created | .documentNamespace = $namespace' \
  "$temporary" > "$document"
jq -e --arg created "$REPO_HARDEN_SBOM_CREATED" --arg namespace "$namespace" \
  '.spdxVersion == "SPDX-2.3" and .creationInfo.created == $created and
   .documentNamespace == $namespace' "$document" >/dev/null
