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
git symbolic-ref HEAD refs/heads/main
export GIT_AUTHOR_NAME='DCO fixture' GIT_AUTHOR_EMAIL='dco@example.com'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git -c commit.gpgsign=false commit -q --allow-empty -m 'legacy imported history'
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed import snapshot'
export DCO_IMPORT_BASELINE
DCO_IMPORT_BASELINE=$(git rev-parse HEAD)
export HEAD_SHA="$DCO_IMPORT_BASELINE"
export EVENT_NAME=push BEFORE_SHA=0000000000000000000000000000000000000000
export DEFAULT_BRANCH=main PUSH_REF=refs/heads/main
bash "$script"

# Published history is not new topic-branch work, even if it contains an old unsigned merge.
git -c commit.gpgsign=false commit -q --allow-empty -m 'published unsigned historical merge'
published=$(git rev-parse HEAD)
HEAD_SHA=$published
if bash "$script" >/dev/null 2>&1; then
  printf 'initial main push accepted an unsigned historical commit\n' >&2
  exit 1
fi
git update-ref refs/remotes/origin/main "$published"
git switch -q -c signed-topic
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed topic contribution'
HEAD_SHA=$(git rev-parse HEAD)
signed_tip=$HEAD_SHA
export PUSH_REF=refs/heads/signed-topic
bash "$script"
BASE_SHA=$published EVENT_NAME=pull_request bash "$script"

git -c commit.gpgsign=false commit -q --allow-empty -m 'unsigned intermediate contribution'
unsigned=$(git rev-parse HEAD)
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed branch tip'
export HEAD_SHA
HEAD_SHA=$(git rev-parse HEAD)
if bash "$script" 2>/dev/null; then
  printf 'new branch accepted an unsigned intermediate commit\n' >&2
  exit 1
fi

export BEFORE_SHA="$signed_tip"
if bash "$script" 2>/dev/null; then
  printf 'push accepted an unsigned commit\n' >&2
  exit 1
fi
export EVENT_NAME=pull_request BASE_SHA="$published"
if bash "$script" 2>/dev/null; then
  printf 'pull request accepted an unsigned commit\n' >&2
  exit 1
fi
export BASE_SHA="$unsigned"
bash "$script"
export EVENT_NAME=push BEFORE_SHA="$unsigned"
bash "$script"

# A topic based on an older main must still exclude all published commits.
git switch -q main
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'main advanced'
advanced_main=$(git rev-parse HEAD)
git update-ref refs/remotes/origin/main "$advanced_main"
git switch -q -c lagging-topic "$published"
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed lagging topic'
HEAD_SHA=$(git rev-parse HEAD)
BEFORE_SHA=0000000000000000000000000000000000000000
PUSH_REF=refs/heads/lagging-topic
bash "$script"
BASE_SHA=$advanced_main EVENT_NAME=pull_request bash "$script"

# A signed merge must not conceal an unsigned side commit.
git switch -q -c unsigned-side "$published"
git -c commit.gpgsign=false commit -q --allow-empty -m 'unsigned side contribution'
unsigned_side=$(git rev-parse HEAD)
git switch -q -c merge-topic "$published"
git -c commit.gpgsign=false commit -q -s --allow-empty -m 'signed merge topic'
git -c commit.gpgsign=false merge -q --no-ff --no-edit --signoff unsigned-side
HEAD_SHA=$(git rev-parse HEAD)
PUSH_REF=refs/heads/merge-topic
if result=$(bash "$script" 2>&1); then
  printf 'signed merge concealed an unsigned side commit\n' >&2
  exit 1
fi
if [[ "$result" != *"$unsigned_side"* ]]; then
  printf 'merge regression failed for the wrong reason: %s\n' "$result" >&2
  exit 1
fi

git update-ref -d refs/remotes/origin/main
if bash "$script" >/dev/null 2>&1; then
  printf 'missing fetched default branch was accepted\n' >&2
  exit 1
fi
git update-ref refs/remotes/origin/main "$advanced_main"

# Missing or invalid revision input must fail, even before sign-off inspection.
export BEFORE_SHA=1111111111111111111111111111111111111111
if bash "$script" >/dev/null 2>&1; then
  printf 'invalid push base was accepted\n' >&2
  exit 1
fi
printf 'DCO event-range regression checks passed\n'
