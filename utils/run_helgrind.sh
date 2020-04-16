#!/bin/bash

for f in "$@"
do
    log_name="$(basename $f | cut -f 1 -d '.')-helgrind.log"
    valgrind --log-file=$log_name --tool=helgrind $(realpath $f)
done