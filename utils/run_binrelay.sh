#!/bin/bash

for f in "$@"
do
    log_name="$(basename $f | cut -f 1 -d '.')-binrelay.log"
    ./find_races.py -l $f 2>&1 | tee $log_name

    log_name="$(basename $f | cut -f 1 -d '.')-binrelay-nofilter.log"
    ./find_races.py -d -l $f 2>&1 | tee $log_name
done