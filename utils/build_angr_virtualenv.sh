#!/bin/bash -e

echo "building virtualenv..."

virtualenv angr-env
source ./angr-env/bin/activate

pip3 install angr

deactivate

printf "\nvirtualenv created, run the following to activate:\n"
printf ". ./angr-env/bin/activate\n\n"
