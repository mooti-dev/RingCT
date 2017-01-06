#!/bin/sh
rm a.exe
gtags.exe
make clean
make
./a.exe
