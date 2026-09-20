#!/bin/sh
mkdir -p out
javac -encoding UTF-8 -d out src/*.java
java -cp out Main
