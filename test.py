#!/usr/bin/env python3

import angr
import pyvex

import networkx as nx
import matplotlib.pyplot as plt

import binrelay

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Executes the thread entry point "
                                 "analysis on a binary.")
    ap.add_argument("bin", help="the binary to analyze")
    args = ap.parse_args()

    print("Analyzing \"%s\"" % (args.bin))

    proj = angr.Project(args.bin, auto_load_libs=False)

    # We need to generated an accurate CFG for analysis. Context sensitivity
    # may need to be increased as needed.

    ### TODO: Submit pthread_exit to upstream angr?
    proj.hook_symbol("pthread_exit", binrelay.pthread_exit())

    cfg = proj.analyses.CFGEmulated(keep_state=True,
                                    context_sensitivity_level=3)

    def my_bp(state):
        print("{} @ {}".format(state.regs.rip, state.mem[0x4040d0].uint64_t))
    state = proj.factory.entry_state()
    state.inspect.b("instruction", instruction=0x4013ab, when=angr.BP_BEFORE,
                    action=my_bp)
    state.inspect.b("instruction", instruction=0x40128d, when=angr.BP_BEFORE,
                    action=my_bp)
    state.inspect.b("instruction", instruction=0x4012c1, when=angr.BP_BEFORE,
                    action=my_bp)
    state.inspect.b("instruction", instruction=0x4012b5, when=angr.BP_BEFORE,
                    action=my_bp)
    state.inspect.b("instruction", instruction=0x4012c6, when=angr.BP_BEFORE,
                    action=my_bp)
    state.inspect.b("instruction", instruction=0x4012b7, when=angr.BP_BEFORE,
                    action=my_bp)
    simmgr = proj.factory.simulation_manager(state)
    #simmgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=1))
    simmgr.run()
    print("done")

    # Get the thread-entry points via symbolic execution.
    tep = proj.analyses.TEPAnalysis()

    for addr in tep.kb.thread_entry_points:
        # Get nodes reachable from the thread-entry point.
        immediate_nodes = cfg.get_all_nodes(addr)
        tep_nodes = []
        for node in immediate_nodes:
            tep_nodes += nx.single_source_shortest_path(cfg.graph, node).keys()
        # Produce a graph for the thread-entry point.
        tep_graph = cfg.graph.subgraph(tep_nodes)

        # Generate summaries for the nodes.
        #for node in tep_graph.nodes:
        #    block = proj.factory.block(node.addr)
        #    print(block.vex.jumpkind)
            #print("vex for block @ 0x%X" % (node.addr))
            #print("-------DONE---------")

        pos = nx.drawing.nx_agraph.graphviz_layout(tep_graph, prog="dot")
        nx.draw(tep_graph, pos, with_labels=True)
        plt.show()

        #for node in nodes:
            #print(networkx.dfs_successors(node))
    
    #nodes = cfg.get_all_nodes(0x401984)
    #for node in nodes:
    #    print(node.successors)
#    def my_bp(state):
#        print(state.callstack)

#    state = proj.factory.entry_state()
#    state.inspect.b("instruction", instruction=0x4019ad, when=angr.BP_BEFORE,
#                    action=my_bp)
#    simmgr= proj.factory.simulation_manager(state)
#    simmgr.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
#    simmgr.run()
