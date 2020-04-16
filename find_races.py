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
    ap.add_argument("-d", "--disable-filter", action="store_true",
                    default=False, help="Disable global variable filter (experimental)")
    ap.add_argument("-u", "--unicorn", action="store_true",
                    default=False, help="Use the unicorn engine")
    ap.add_argument("-l", "--loop-hooks", action="store_true",
                    default=False, help="Use loop hooks")
    args = ap.parse_args()

    logger.info("Finding races in %s" % (args.binary))

    project = angr.Project(args.binary, auto_load_libs=False)

    binrelay.utils.hook_pthread_exit(project)
    if True == args.loop_hooks:
        binrelay.utils.hook_loops(project)

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
    if True == args.unicorn:
        for opt in angr.options.unicorn:
            state.options.add(opt)

    race_finder = project.analyses.RaceFinder(
        initial_state=state, disable_global_filter=args.disable_filter)
