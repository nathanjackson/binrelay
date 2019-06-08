#!/bin/bash -e


echo "downloading juliet dataset..."
url="https://samate.nist.gov/SARD/testsuites/juliet/Juliet_Test_Suite_v1.3_for_C_Cpp.zip"
tmpzip=$(mktemp)
curl -# -o $tmpzip $url
tmpdir=$(mktemp -d)

function cleanup {
    rm -rf $tmpzip $tmpdir    
}
trap cleanup EXIT

echo "extracting..."
unzip -q -d $tmpdir $tmpzip
pushd $tmpdir/C/testcases/CWE366*
echo "building..."
make individuals
popd

mkdir juliet-cwe366
cp $tmpdir/C/testcases/CWE366*/{*.c,*.cpp,*.out} juliet-cwe366/

echo "done"
