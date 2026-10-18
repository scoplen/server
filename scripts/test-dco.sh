#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-dco.sh
scratch_root=$(cd "${TMPDIR:-/tmp}" && pwd -P)
fixture=$(mktemp -d "$scratch_root/scoplen-dco.XXXXXXXX")
cleanup() {
  if [[ "$fixture" == "$scratch_root"/scoplen-dco.* && -d "$fixture" ]]; then
    rm -rf -- "$fixture"
  fi
}
trap cleanup EXIT

git init -q "$fixture"
cd "$fixture"
export GIT_AUTHOR_NAME='DCO fixture' GIT_AUTHOR_EMAIL='dco@example.com'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git -c commit.gpgsign=false commit -q --allow-empty -m 'legacy imported history'
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed import snapshot'
export DCO_IMPORT_BASELINE
DCO_IMPORT_BASELINE=$(git rev-parse HEAD)
export HEAD_SHA="$DCO_IMPORT_BASELINE"
export EVENT_NAME=push BEFORE_SHA=0000000000000000000000000000000000000000
bash "$script"

git -c commit.gpgsign=false commit -q --allow-empty -m 'unsigned intermediate contribution'
unsigned=$(git rev-parse HEAD)
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed branch tip'
export HEAD_SHA
HEAD_SHA=$(git rev-parse HEAD)
if bash "$script" 2>/dev/null; then
  printf 'new branch accepted an unsigned intermediate commit\n' >&2
  exit 1
fi

export BEFORE_SHA="$DCO_IMPORT_BASELINE"
if bash "$script" 2>/dev/null; then
  printf 'push accepted an unsigned commit\n' >&2
  exit 1
fi
export EVENT_NAME=pull_request BASE_SHA="$DCO_IMPORT_BASELINE"
if bash "$script" 2>/dev/null; then
  printf 'pull request accepted an unsigned commit\n' >&2
  exit 1
fi
export BASE_SHA="$unsigned"
bash "$script"
export EVENT_NAME=push BEFORE_SHA="$unsigned"
bash "$script"

# Missing or invalid revision input must fail, even before sign-off inspection.
export BEFORE_SHA=1111111111111111111111111111111111111111
if bash "$script" >/dev/null 2>&1; then
  printf 'invalid push base was accepted\n' >&2
  exit 1
fi
printf 'DCO event-range regression checks passed\n'
