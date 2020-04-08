#!/usr/bin/env python3

import argparse
import logging

import angr
import claripy

import binrelay

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)

MAX_ARG_BYTES = 20

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Find race conditions on a given binary.")
    ap.add_argument("binary", help="the binary to analyze")
    args = ap.parse_args()

    logger.info("Finding races in %s" % (args.binary))

    project = angr.Project(args.binary, auto_load_libs=False)

    binrelay.utils.hook_pthread_exit(project)

    arg_size = project.arch.byte_width * MAX_ARG_BYTES

    analysis_args = [
        project.filename,
        claripy.BVS("arg1", arg_size),
        claripy.BVS("arg2", arg_size),
        claripy.BVS("arg3", arg_size),
        claripy.BVS("arg4", arg_size),
        claripy.BVS("arg5", arg_size),
        claripy.BVS("arg6", arg_size)
    ]
    state = project.factory.entry_state(args=analysis_args)

    race_finder = project.analyses.RaceFinder(initial_state=state)
