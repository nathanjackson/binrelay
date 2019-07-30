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

    # Get the thread-entry points via symbolic execution.
    tep = proj.analyses.TEPAnalysis()

    # Rergister a SimProcedure for lock.
    class pthread_mutex_lock(angr.SimProcedure):
        def run(self, mutex):
            print("Locking on thread {}: {}".format(self.state.my_plugin.thread, mutex))
    proj.hook_symbol("pthread_mutex_lock", pthread_mutex_lock())

    # Register a SimProcedure for unlock.
    class pthread_mutex_unlock(angr.SimProcedure):
        def run(self, mutex):
            print("Unlocking on thread {}: {}".format(self.state.my_plugin.thread, mutex))
    proj.hook_symbol("pthread_mutex_unlock", pthread_mutex_unlock())

    # This is binary specific, but needed for our target case.
    @proj.hook(0x4012aa, length=0xD)
    def skip_loop(state):
        pass

    # Perform another symbolic execution to get the lock and unlock points
    class my_pthread_create(angr.procedures.posix.pthread.pthread_create):
        def run(self, newthread, attr, start_routine, arg):
            self.state.my_plugin.thread += 1
            super(my_pthread_create, self).run(newthread, attr, start_routine, arg)
    proj.hook_symbol("pthread_create", my_pthread_create())

    class MyFirstPlugin(angr.SimStatePlugin):
        def __init__(self, thread):
            super(MyFirstPlugin, self).__init__()
            self.thread = thread

        @angr.SimStatePlugin.memo
        def copy(self, memo):
            return MyFirstPlugin(self.thread)

#        def set_state(self, state):
#            super(MyFirstPlugin, self).set_state(state)

    state = proj.factory.entry_state()
    state.register_plugin("my_plugin", MyFirstPlugin(0))

    def mem_read(state):
        from_addr = state.inspect.mem_read_address
        print("read from {} on thread {} at {}".format(from_addr, state.my_plugin.thread, state.regs.ip))

    def mem_write(state):
        to_addr = state.inspect.mem_write_address
        print("write to {} on thread {} at {}".format(to_addr,
                                                      state.my_plugin.thread,
                                                      state.regs.ip))

    state.inspect.b("mem_read", when=angr.BP_AFTER, action=mem_read)
    state.inspect.b("mem_write", when=angr.BP_AFTER, action=mem_write)

    simmgr= proj.factory.simulation_manager(state)
    #state.inspect.b("instruction", instruction=0x401b51, when=angr.BP_BEFORE,
    #                action=my_bp)
    simmgr.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
    simmgr.run()

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
