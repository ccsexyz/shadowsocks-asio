#!/bin/bash

cd cryptopp 
git checkout . && git clean -xdf 
cd .. 

make clean  
rm CMakeCache.txt  