#!/bin/bash
mkdir out
for dir in ./gb_programs/*/
do
    dir=${dir%*/}
    python synth.py "${dir##*/}" > out/"${dir##*/}"_out.txt 2>&1
done
