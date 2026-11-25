#!/usr/bin/env bash
# j8_check_line_pin.sh - J8: v2v_ttl_resmgr.c pins the line number of its only __LINE__ user of the default build (OPENSSL_free in the ECDSA check)
# to the main workspace's value 719 with "#line 719", and goes back to the physical numbering right after with "#line N". This checks
#   1. there is exactly one "#line 719" and it is directly followed by the OPENSSL_free(der) line,
#   2. the "#line N" after it names the physical number of the line that follows it (so every later diagnostic points to the right line),
#   3. no other #line directive exists.
# Usage: bash scripts/j8_check_line_pin.sh [file]   exit 0 = pin consistent.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
F="${1:-${HERE}/qnx_target/src/v2v_ttl_resmgr.c}"
awk '
  /^#line / { n++; ln[n] = NR; val[n] = $2 }
  { line[NR] = $0 }
  END {
    if (n != 2) { printf("line pin: expected 2 #line directives, found %d\n", n); exit 1 }
    if (val[1] != 719) { printf("line pin: first #line is %s, expected 719\n", val[1]); exit 1 }
    if (line[ln[1] + 1] !~ /^    OPENSSL_free\(der\);/) { printf("line pin: line after #line 719 is not OPENSSL_free(der)\n"); exit 1 }
    if (ln[2] != ln[1] + 2) { printf("line pin: the restoring #line is not right after OPENSSL_free\n"); exit 1 }
    if (val[2] != ln[2] + 1) { printf("line pin: restoring #line says %s, the next physical line is %d\n", val[2], ln[2] + 1); exit 1 }
    printf("line pin: #line 719 at physical line %d, restored to %d at line %d (consistent)\n", ln[1], val[2], ln[2])
  }' "${F}"
