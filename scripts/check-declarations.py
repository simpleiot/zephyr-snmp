#!/usr/bin/env python3
# Copyright (c) 2026 Cliff Brake
# SPDX-License-Identifier: Apache-2.0
#
# Check that every function declared in the public headers is defined in the
# built library, so an application that calls one never meets an undefined
# reference at link time.
#
# Usage: check-declarations.py <libsnmp.a> <include-dir>
#
# The headers follow .clang-format, so a light parse is enough: comments,
# preprocessor lines, and brace blocks (struct bodies, inline functions) are
# removed, and every remaining "name(...);" statement that is not a typedef is
# a function declaration.

import pathlib
import re
import subprocess
import sys


def declared_functions(include_dir):
	names = {}
	for header in sorted(pathlib.Path(include_dir).rglob("*.h")):
		text = header.read_text()
		text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
		text = re.sub(r"//[^\n]*", "", text)
		# The extern "C" wrapper would otherwise read as one brace block
		# holding the whole header.
		text = re.sub(r"#ifdef __cplusplus.*?#endif", "", text, flags=re.S)
		text = re.sub(r"^\s*#(?:[^\n]*\\\n)*[^\n]*", "", text, flags=re.M)
		while True:
			stripped = re.sub(r"\{[^{}]*\}", "", text)
			if stripped == text:
				break
			text = stripped
		for statement in text.split(";"):
			statement = " ".join(statement.split())
			if statement.startswith("typedef"):
				continue
			match = re.search(r"\b([A-Za-z_]\w*)\s*\(", statement)
			if match:
				names.setdefault(match.group(1), header.name)
	return names


def defined_symbols(library):
	output = subprocess.run(
		["nm", "--defined-only", library], check=True, capture_output=True, text=True
	).stdout
	return {
		fields[2]
		for fields in (line.split() for line in output.splitlines())
		if len(fields) == 3 and fields[1] in "TW"
	}


def main():
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} <libsnmp.a> <include-dir>", file=sys.stderr)
		return 2

	declared = declared_functions(sys.argv[2])
	defined = defined_symbols(sys.argv[1])
	missing = sorted(name for name in declared if name not in defined)

	for name in missing:
		print(f"{declared[name]}: {name}() is declared but not defined", file=sys.stderr)
	if missing:
		return 1

	print(f"All {len(declared)} declared functions are defined in {sys.argv[1]}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
