#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Every check, the maintainer's included (tests/maintainer_rows.txt): what the release checklist and the GitHub checks
# run. An installation runs tests/run_all_checks.sh, its own checks only. Some of these need tools an installation does
# not have (Node, Playwright with Chromium, pypdfium2), a test system or a throwaway database (docs/TESTING.md).
# Usage: bash tests/maintainer_checks.sh
cd "$(dirname "$0")/.." || exit 1
LG_SUITE=all exec bash tests/run_all_checks.sh "$@"
