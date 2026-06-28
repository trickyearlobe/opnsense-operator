#!/usr/bin/env bash
# Compute the next semver from the latest git tag, create an annotated tag, and
# push it. Pushing a v* tag triggers the release workflow (.github/workflows/
# release.yaml), which builds + signs the image and publishes the GitHub Release
# and Helm chart.
#
# Usage: hack/bump-version.sh <patch|minor|major>
set -euo pipefail

part="${1:-}"
case "$part" in
  patch | minor | major) ;;
  *)
    echo "usage: $0 <patch|minor|major>" >&2
    exit 2
    ;;
esac

# Refuse to tag a dirty tree — the tag must point at a real, committed state.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is dirty; commit or stash before bumping" >&2
  exit 1
fi

remote="${REMOTE:-origin}"
if ! git remote get-url "$remote" >/dev/null 2>&1; then
  echo "error: git remote '$remote' not configured (set one, or REMOTE=...)" >&2
  exit 1
fi

# Latest v-prefixed semver tag, or v0.0.0 if there are none yet.
latest="$(git tag -l 'v*' | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
latest="${latest:-0.0.0}"
IFS=. read -r major minor patch <<<"$latest"

case "$part" in
  major)
    major=$((major + 1))
    minor=0
    patch=0
    ;;
  minor)
    minor=$((minor + 1))
    patch=0
    ;;
  patch)
    patch=$((patch + 1))
    ;;
esac

next="v${major}.${minor}.${patch}"

if git rev-parse "$next" >/dev/null 2>&1; then
  echo "error: tag $next already exists" >&2
  exit 1
fi

echo "Bumping ${part}: v${latest} -> ${next}"
git tag -a "$next" -m "Release ${next}"
git push "$remote" "$next"
echo "Pushed ${next} to ${remote}. Release workflow will publish the image, GitHub Release, and Helm chart."
