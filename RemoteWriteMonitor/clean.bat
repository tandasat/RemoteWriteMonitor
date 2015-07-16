@echo off
del *.sdf *.sdf *.opensdf
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q Win7Debug
rmdir /s /q Win7Release
rmdir /s /q Win8.1Debug
rmdir /s /q Win8.1Release
rmdir /s /q x64
rmdir /s /q TestInjector\Debug
rmdir /s /q TestInjector\Release
rmdir /s /q RemoteWriteMonitor\Win7Debug
rmdir /s /q RemoteWriteMonitor\Win7Release
rmdir /s /q RemoteWriteMonitor\Win8.1Debug
rmdir /s /q RemoteWriteMonitor\Win8.1Release
rmdir /s /q RemoteWriteMonitor\x64
rmdir /s /q bin_RemoteWriteMonitor
del /s *.aps
pause
