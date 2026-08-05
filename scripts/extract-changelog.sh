#!/bin/bash
# Copyright (c) 2026 Cliff Brake
# SPDX-License-Identifier: Apache-2.0
#
# Extract the changelog section for a specific version from CHANGELOG.md
# Usage: extract-changelog.sh <version>
#
# The version may be given with or without the leading "v", and headings may
# carry it either way, so "0.1.0" and "v0.1.0" both find "## [v0.1.0] - ...".

set -euo pipefail

VERSION=${1:-}

if [ -z "$VERSION" ]; then
	echo "Usage: $0 <version>" >&2
	exit 1
fi

# Remove the 'v' prefix if present; the heading match allows it either way.
VERSION=${VERSION#v}

CHANGELOG=${CHANGELOG:-CHANGELOG.md}

# Print the lines between this version's heading and the next one.
awk -v version="$VERSION" '
BEGIN {
	# Escape the dots so "0.1.0" does not also match "0a1b0".
	gsub(/\./, "\\.", version)
	pattern = "^## \\[v?" version "\\]"
}
$0 ~ pattern { found = 1; next }
found && /^## / { exit }
found { print }
' "$CHANGELOG"
