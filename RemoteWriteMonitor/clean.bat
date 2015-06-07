del *.sdf
del /a:h *.suo
rmdir /s /q ipch
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q Win7Debug
rmdir /s /q Win7Release
rmdir /s /q Win8.1Debug
rmdir /s /q Win8.1Release
rmdir /s /q x64
rmdir /s /q injector\Debug
rmdir /s /q injector\Release
rmdir /s /q RemoteWriteMonitor\Win7Debug
rmdir /s /q RemoteWriteMonitor\Win7Release
rmdir /s /q RemoteWriteMonitor\Win8.1Debug
rmdir /s /q RemoteWriteMonitor\Win8.1Release
rmdir /s /q RemoteWriteMonitor\x64
rmdir /s /q "RemoteWriteMonitor Package\Win7Debug"
rmdir /s /q "RemoteWriteMonitor Package\Win7Release"
rmdir /s /q "RemoteWriteMonitor Package\Win8.1Debug"
rmdir /s /q "RemoteWriteMonitor Package\Win8.1Release"
rmdir /s /q "RemoteWriteMonitor Package\x64"
del /s *.aps
pause
