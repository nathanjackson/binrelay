import angr

class TEPAnalysis(angr.Analysis):
    """
    Thread entry point analysis
    """
    def __init__(self):
        result = set()
        simgr = self.project.factory.simulation_manager()

        class _PthreadCreate(angr.SimProcedure):
            def run(self, newthread, attr, start_routine, arg):
                addr = self.state.solver.eval(start_routine.to_claripy())
                result.add(addr)
        self.project.hook_symbol("pthread_create", _PthreadCreate())

        simgr.run()
        self.result = result
angr.AnalysesHub.register_default("TEPAnalysis", TEPAnalysis)

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Executes the thread entry point "
                                 "analysis on a binary.")
    ap.add_argument("bin", help="the binary to analyze")
    args = ap.parse_args()

    print("Analyzing \"%s\"" % (args.bin))

    proj = angr.Project(args.bin, auto_load_libs=False)
    tep = proj.analyses.TEPAnalysis()
    for entry in tep.result:
        print("0x%X" % (entry))
