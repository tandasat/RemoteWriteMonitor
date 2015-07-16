@echo off
del /s *.pdb *.cer *.inf

:: Arrange the x86 folder 
rmdir /s /q _x86
mkdir _x86
move Win7Release   _x86
move Win8.1Release _x86

:: Arrange the x64 folder
rmdir /s /q _x64
mkdir _x64
move x64\Win7Release   _x64
move x64\Win8.1Release _x64

:: Arrange the bin_Scavenger folder
rmdir /s /q bin_RemoteWriteMonitor
mkdir bin_RemoteWriteMonitor
move _x86 bin_RemoteWriteMonitor\x86
move _x64 bin_RemoteWriteMonitor\x64
move Release\TestInjector.exe bin_RemoteWriteMonitor\
pause
