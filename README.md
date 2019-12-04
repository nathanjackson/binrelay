# BINRELAY

BINRELAY is an open source tool for detecting race conditions inside binaries.
It is built on top of [angr](http://angr.io/)'s concolic (static and dynamic)
analysis capabilities.

BINRELAY is currently under development and testing has been limited to the CWE
366 binaries from the [Juliet Dataset](https://samate.nist.gov/SARD/testsuite.php)
in Linux. It can currently only detect races on global variables (those
variables stored in the `.data` or `.bss` of a binary).

Results from BINRELAY should be treated with skepticism, its not (yet) a tool
worthy of production.

# Quickstart

BINRELAY's only dependency is angr. angr installation instructions can be found
in their documentation: https://docs.angr.io/introductory-errata/install. Follow
these instructions to build the Juliet dataset and run BINRELAY against them.

1. Download and build the Juliet CWE366 binaries.

    ```
    ./utils/get_juliet_cwe366_binaries.sh
    ```

2. Assuming you've already setup an angr virtual environment, execute BINRELAY
   against the Juliet binaries.

    ```
    ./find_races.py juliet-cwe366/CWE366_Race_Condition_Within_Thread__global_int_01.out
    ```
