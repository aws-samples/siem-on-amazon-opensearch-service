#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Update or check the release version string in every file.

Usage:
    python3 deployment/bump_version.py 2.10.7   # update all files
    python3 deployment/bump_version.py --check  # fail on mismatch (CI)

The current version is read from source/cdk/app.py. CHANGELOG.md and
README*.md are skipped because they mention past versions on purpose
(e.g. "Since v2.10.6, ...").
"""
import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / 'source' / 'cdk' / 'app.py'
VERSION_RE = re.compile(r"__version__ = '(\d+\.\d+\.\d+)'")
SKIP_RE = re.compile(r'^(CHANGELOG\.md|README[^/]*\.md)$')
# patterns that must always carry the current version
CHECK_RES = [
    re.compile(r"__version__ = '(\d+\.\d+\.\d+)'"),
    re.compile(r'OpenSearch Service v(\d+\.\d+\.\d+)'),
    re.compile(r'opensearch-service/v(\d+\.\d+\.\d+)/'),
    re.compile(r'ConfigVersion: (\d+\.\d+\.\d+)'),
    re.compile(r'CustomResource::policy\d+-(\d+\.\d+\.\d+)-'),
]


def current_version():
    match = VERSION_RE.search(VERSION_FILE.read_text())
    if not match:
        sys.exit(f'version not found in {VERSION_FILE}')
    return match.group(1)


def tracked_files():
    out = subprocess.run(['git', 'ls-files'], cwd=ROOT, check=True,
                         capture_output=True, text=True).stdout
    for name in out.splitlines():
        if SKIP_RE.match(name):
            continue
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            continue
        try:
            yield name, path.read_text()
        except UnicodeDecodeError:
            continue


def bump(new):
    old = current_version()
    if not re.fullmatch(r'\d+\.\d+\.\d+', new):
        sys.exit(f'invalid version: {new}')
    if old == new:
        sys.exit(f'already {new}')
    changed = 0
    for name, text in tracked_files():
        if old in text:
            (ROOT / name).write_text(text.replace(old, new))
            changed += 1
            print(f'updated {name}')
    print(f'{old} -> {new}: {changed} files')


def check():
    version = current_version()
    errors = []
    for name, text in tracked_files():
        if name.startswith('docs/'):
            # docs describe upgrades from past versions on purpose
            continue
        for regex in CHECK_RES:
            for match in regex.finditer(text):
                if match.group(1) != version:
                    line = text.count('\n', 0, match.start()) + 1
                    errors.append(f'{name}:{line}: {match.group(1)}')
    for err in errors:
        print(err)
    if errors:
        sys.exit(f'{len(errors)} version mismatches (expected {version})')
    print(f'all version strings are {version}')


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('version', nargs='?')
    group.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        check()
    else:
        bump(args.version)


if __name__ == '__main__':
    main()
