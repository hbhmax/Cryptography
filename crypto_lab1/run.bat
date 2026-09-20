@echo off
if not exist out mkdir out
javac -encoding UTF-8 -d out src\*.java
java -cp out Main
pause
