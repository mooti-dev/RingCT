#!/bin/sh
rm a.out
gtags
make clean
make
./a.out
