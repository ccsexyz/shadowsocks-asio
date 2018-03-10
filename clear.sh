#!/bin/bash

cd cryptopp 
git checkout . && git clean -xdf 
cd .. 

cd glog
git checkout . && git clean -xdf 
cd .. 

cd gflags 
git checkout . && git clean -xdf 
cd .. 

make clean  
rm CMakeCache.txt  
