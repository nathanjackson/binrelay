#!/usr/bin/env python3

import angr
import binrelay

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Executes the thread entry point "
                                 "analysis on a binary.")
    ap.add_argument("bin", help="the binary to analyze")
    args = ap.parse_args()

    print("Analyzing \"%s\"" % (args.bin))

    proj = angr.Project(args.bin, auto_load_libs=False)
    tep = proj.analyses.TEPAnalysis()

    for addr in tep.kb.thread_entry_points:
        print("0x%X" % (addr))
