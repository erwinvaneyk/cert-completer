#!/usr/bin/env bash

# generate-k8s-resources.sh - prebuild k8s resources

set -o errexit
set -o nounset
set -o pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )";

kustomize build "${ROOT}/../config/default" > "${ROOT}/../cert-completer.yaml"