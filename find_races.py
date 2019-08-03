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

    race_finder = project.analyses.RaceFinder()
