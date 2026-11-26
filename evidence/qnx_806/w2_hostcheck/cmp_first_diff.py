#!/usr/bin/env python3
"""cmp_first_diff.py HOST_ALL TARGET_SERIAL - first differing line between the host TRACE_ALL output and the target's (lines between '[W2] begin' and '[W2] end' that start with '[op ' or '[trace]')."""
import sys, re
host = [l.rstrip('\n') for l in open(sys.argv[1], errors='replace')]
tgt = []
on = False
for l in open(sys.argv[2], errors='replace'):
    l = l.rstrip('\r\n')
    if l.startswith('[W2] lines='): on = True; continue
    if l.startswith('[W2] end'): on = False
    if on and (l.startswith('[op ') or l.startswith('[trace]')): tgt.append(l)
host = [l for l in host if l.startswith('[op ') or l.startswith('[trace]')]
print('host lines', len(host), 'target lines', len(tgt))
n = min(len(host), len(tgt))
for i in range(n):
    if host[i] != tgt[i]:
        print('FIRST DIFF at line', i + 1)
        for k in range(max(0, i - 3), min(n, i + 4)):
            print(('>>' if k == i else '  '), 'host:', host[k], '| target:', tgt[k])
        sys.exit(1)
print('no difference in the first', n, 'lines'); sys.exit(0 if len(host) == len(tgt) else 1)
