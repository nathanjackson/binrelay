#!/usr/bin/env python3

import angr
import claripy

import binrelay

proj = angr.Project("../ubuntu1804/binaries/genisoimage", auto_load_libs=False)

argv = "genisoimage -jigdo-template template -jigdo-jigdo jigdo -md5-list md5_list -o test.iso test".split(" ")
print(argv)

state = proj.factory.entry_state(argc=len(argv), args=argv)

binrelay.utils.hook_loops(proj, max_iters=1)
binrelay.utils.hook_pthread_exit(proj)

race_finder = proj.analyses.RaceFinder(state=state)

#simgr = proj.factory.simgr(proj.factory.entry_state())
#result = simgr.explore(find=0x43c705)
