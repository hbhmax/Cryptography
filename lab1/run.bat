@echo off
if not exist out mkdir out
if exist sources.txt del sources.txt
for /r src %%f in (*.java) do echo %%f>>sources.txt
javac -encoding UTF-8 -d out @sources.txt
del sources.txt
java -cp out app.Main
pause
