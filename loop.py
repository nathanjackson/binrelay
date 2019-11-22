#!/usr/bin/env python3

import angr

proj = angr.Project("loop.elf", auto_load_libs=False)

cfg = proj.analyses.CFGFast()

loop_finder_result = proj.analyses.LoopFinder()

def mk_hook(dest_addr):
    hit_count = 0
    def the_hook(state):
        nonlocal hit_count
        if hit_count > 9:
            state.ip = dest_addr
            print("jumping out of loop, ip = %s" % (state.ip))
        hit_count += 1
    return the_hook

for loop in loop_finder_result.loops:
    print("break edges:")
    edge = loop.break_edges[0]
    src_block = proj.factory.block(edge[0].addr)
    jmp_out_addr = src_block.instruction_addrs[-1]
    print("jump out addr = 0x%X" % (jmp_out_addr))

#    hit_count = 0
#    def the_hook(state):
#        print("hook called %s (count = %d)" % (state.ip, hit_count))
#        if hit_count > 0:
#            state.ip = edge[1].addr
#            print("jumping out of loop, ip = %s" % (state.ip))
#        hit_count += 1
        #print(the_hook.foo)

    proj.hook(jmp_out_addr, hook=mk_hook(edge[1].addr))


state = proj.factory.entry_state()
simmgr = proj.factory.simulation_manager(state)
simmgr.run()
