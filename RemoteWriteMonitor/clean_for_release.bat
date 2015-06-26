del /s *.pdb *.cer *.inf
mkdir x86
move Win7Release x86
move Win8.1Release x86
mkdir bin_RemoteWriteMonitor
move x86 bin_RemoteWriteMonitor
move x64 bin_RemoteWriteMonitor
move Release bin_RemoteWriteMonitor
pause
