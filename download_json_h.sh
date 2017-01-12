#!/bin/sh 

# download json.hpp from github.com/nlohmann/json 
# I don't want to copy it to my repo, so please download it manually

wget 'https://raw.githubusercontent.com/nlohmann/json/develop/src/json.hpp'
mv json.hpp json.h
