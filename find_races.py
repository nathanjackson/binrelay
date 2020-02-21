#!/usr/bin/env python3

import argparse
import logging

import angr
import claripy 

import binrelay

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Find race conditions on a given"
                                 + " binary.")
    ap.add_argument("binary", help="the binary to analyze")
    args = ap.parse_args()

    logger.info("Finding races in %s" % (args.binary))

    project = angr.Project(args.binary, auto_load_libs=False)

    arg1 = claripy.BVS("arg1", 64)
    arg2 = claripy.BVS("arg2", 64)
    arg3 = claripy.BVS("arg3", 64)
    arg4 = claripy.BVS("arg4", 64)
    arg5 = claripy.BVS("arg5", 64)
    arg6 = claripy.BVS("arg6", 64)
    state = project.factory.call_state(0x438c50, arg1, arg2, arg3, arg4, arg5,
                                       arg6)

    binrelay.utils.hook_loops(project)
    #binrelay.utils.hook_pthread_exit(project)

    race_finder = project.analyses.RaceFinder(state=state)
