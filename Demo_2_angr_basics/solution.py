#!/usr/bin/env python

import angr
import claripy

# setup project
p = angr.Project('./engine')

# create input characters
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(256)]
stdin = [claripy.BVV(b'\n')] + flag_chars + [claripy.BVV(b'\n')]

# create stdin line
stdin = claripy.Concat(*stdin)

# create starting state
ss = p.factory.full_init_state(args=['./engine'], stdin=stdin)

# add constraints
for k in flag_chars:
    # ascii and non-newline
    ss.solver.add(k < 0x7f)
    ss.solver.add(k > 0x20)

# setup and run simulation manager
sm = p.factory.simulation_manager(ss)
sm.run()

for s in sm.deadended:
    if b"Chugga" in b''.join(s.posix.stdout.concretize()):
        raw = s.posix.stdin.concretize()
        input = ''.join([chr(raw[i]) for i in range(0, len(raw), 2)])
        print(input)
