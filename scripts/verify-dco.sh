#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${EVENT_NAME:?missing event name}"
: "${HEAD_SHA:?missing head commit}"
zero=0000000000000000000000000000000000000000

if [[ "$EVENT_NAME" == pull_request ]]; then
  : "${BASE_SHA:?missing pull request base}"
  commits=$(git rev-list "$BASE_SHA..$HEAD_SHA")
elif [[ "$EVENT_NAME" == push && "${BEFORE_SHA:-$zero}" != "$zero" ]]; then
  commits=$(git rev-list "$BEFORE_SHA..$HEAD_SHA")
elif [[ "$EVENT_NAME" == push ]]; then
  : "${DCO_IMPORT_BASELINE:?missing imported history baseline}"
  git merge-base --is-ancestor "$DCO_IMPORT_BASELINE" "$HEAD_SHA"
  : "${DEFAULT_BRANCH:?missing default branch}"
  : "${PUSH_REF:?missing push ref}"
  if [[ "$PUSH_REF" == "refs/heads/$DEFAULT_BRANCH" ]]; then
    # An initial default-branch push still checks the signed import boundary.
    commits=$(git rev-list "$HEAD_SHA" "^$DCO_IMPORT_BASELINE")
    commits="${commits:+$commits
}$DCO_IMPORT_BASELINE"
  else
    default_ref="refs/remotes/origin/$DEFAULT_BRANCH"
    if ! git show-ref --verify --quiet "$default_ref"; then
      printf 'missing fetched default branch: %s\n' "$default_ref" >&2
      exit 1
    fi
    git merge-base --is-ancestor "$DCO_IMPORT_BASELINE" "$default_ref"
    # Only commits absent from the fetched default branch are new branch work.
    commits=$(git rev-list "$HEAD_SHA" "^$default_ref")
  fi
else
  printf 'unsupported DCO event: %s\n' "$EVENT_NAME" >&2
  exit 1
fi

while IFS= read -r commit; do
  [[ -z "$commit" ]] && continue
  trailers=$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$commit")
  if ! grep -Eq '^[^<>]+ <[^<>[:space:]]+@[^<>[:space:]]+>$' <<< "$trailers"; then
    printf 'missing valid Signed-off-by trailer in %s\n' "$commit" >&2
    exit 1
  fi
done <<< "$commits"
