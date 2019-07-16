#!/usr/bin/env python3

import angr
import binrelay

import networkx as nx
import matplotlib.pyplot as plt

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
    cfg = proj.analyses.CFGEmulated(keep_state=True,
                                    context_sensitivity_level=3)
    cfg.remove_cycles()

    # Get the thread-entry points.
    tep = proj.analyses.TEPAnalysis()

    for addr in tep.kb.thread_entry_points:
        print("0x%X" % (addr))
        immediate_nodes = cfg.get_all_nodes(addr)
        tep_nodes = []
        for node in immediate_nodes:
            tep_nodes += nx.single_source_shortest_path(cfg.graph, node).keys()
        tep_graph = cfg.graph.subgraph(tep_nodes)

        pos = nx.drawing.nx_agraph.graphviz_layout(tep_graph, prog="dot")
        nx.draw(tep_graph, pos, with_labels=True)
        plt.show()

        #for node in nodes:
            #print(networkx.dfs_successors(node))
    
    #nodes = cfg.get_all_nodes(0x401984)
    #for node in nodes:
    #    print(node.successors)
#    def my_bp(state):
#        print("at call")
#        print(state.regs.rdx)
#
#    state = proj.factory.entry_state()
#    state.inspect.b("instruction", instruction=0x4019ab, when=angr.BP_BEFORE,
#                    action=my_bp)
#    simmgr= proj.factory.simulation_manager(state)
#    simmgr.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
#    simmgr.run()
