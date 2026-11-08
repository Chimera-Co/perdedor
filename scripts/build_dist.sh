#!/bin/sh
# Build the Python sdist and wheel with the catalog bundled inside perdedor_common, so an installed
# package scores and validates without a checkout. Usage: scripts/build_dist.sh [OUTDIR]
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$root/dist"}
pkg="$root/common/python/perdedor_common"
rm -rf "$pkg/_catalog"
cp -R "$root/catalog" "$pkg/_catalog"
trap 'rm -rf "$pkg/_catalog"' EXIT
python -m build --outdir "$out" "$root"
