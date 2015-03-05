del *.sdf
del /a:h *.suo
rmdir /s /q ipch
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q RemoteWriteMonitor\Debug
rmdir /s /q RemoteWriteMonitor\Release
rmdir /s /q injector\Debug
rmdir /s /q injector\Release
del /s *.aps
pause
