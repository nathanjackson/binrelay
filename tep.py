import angr

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Executes the thread entry point "
                                 "analysis on a binary.")
    ap.add_argument("bin", help="the binary to analyze")
    args = ap.parse_args()

    print("Analyzing \"%s\"" % (args.bin))

    proj = angr.Project(args.bin, auto_load_libs=False)

    class PthreadCreate(angr.SimProcedure):
        def run(self, newthread, attr, start_routine, arg):
            print("pthread create (start_routine = {})".format(start_routine))
    proj.hook_symbol("pthread_create", PthreadCreate())

    simgr = proj.factory.simulation_manager()
    simgr.run()
