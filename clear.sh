#!/bin/bash

cd cryptopp 
git checkout . && git clean -xdf 
cd .. 

cd snippets
git checkout . && git clean -xdf 
cd .. 

make clean  
rm CMakeCache.txt  
rm *.cmake
rm -rf CMakeFiles
