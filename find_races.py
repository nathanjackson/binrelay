#!/usr/bin/env python3

import argparse
import logging

import angr

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

    def test_ret(state):
        logger.info("before %s", state.callstack)
        #logger.info("return target %s", state.callstack.current_return_target)
        state.callstack.ret()
        state.ip = state.callstack.current_return_target
        #logger.info("after %s", state.callstack)
        #logger.info("return target %s", state.callstack.current_return_target)
    def dummy(state):
        pass

    project.hook(0x4019b2, hook=test_ret)
    project.hook(0x4012aa, length=0xD, hook=dummy)
    project.hook(0x401266, length=0xD, hook=dummy)

    race_finder = project.analyses.RaceFinder()
