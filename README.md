RemoteWriteMonitor
========

RemoteWriteMonitor is a tool to help malware analysts tell that the sample is
injecting code to another process. This tool is designed to find a possible
remote code injection and execution without use of NtCreateThread/Ex(), APC or 
thread context manipulation.

A supporting tool 'injector' is a sample program doing that type of code
injection.

A related blog entory can be found here:

    http://standa-note.blogspot.ca/2015/03/section-based-code-injection-and-its.html).

Installation and Uninstallation
-----------------

Get an archive file for compiled files form this link:

    https://github.com/tandasat/RemoteWriteMonitor/releases/latest

Then use the 'sc' command. For installation:

    >sc create rwmon type= kernel binPath= C:\Users\user\Desktop\RemoteWriteMonitor.sys
    >sc start rwmon

For uninstallation:

    >sc stop rwmon
    >sc delete rwmon
    
On the x64 bit platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type 
the following command:

   >bcdedit /set {current} testsigning on
    
Then, reboot the system to activate the change. You also have to disable the 
Kernel Patch Protection (PatchGuard), and Google helps you do that work.


Usage
-------

Once you have installed it, you may execute the sample and see output from the
driver if any.

The driver reports when any process newly created after the installation called
NtWriteVirtualMemory() or NtMapViewOfSection() against another process and saves
what was written or mapped into the remote process. Output can be seen with 
DebugView and are all saved under the C:\Windows\RemoteWriteMonitor\ 
directory. Written and mapped data is stored as \<SHA1\>.bin apart from a log file.

'injector' could be used to test the driver's function. Injecting and executing 
code into notepad.exe can be done by the following commands:

    >notepad && tasklist | findstr notepad
    notepad.exe                   3368 Console                    1      4,564 K

    >injector 3368 section context
    Remote Address   : 00180000
    Waiting for the thread get executed.
    Remote Thread ID : 1912

    >injector 3368 alloc context
    Remote Address   : 001B0000
    Remote Thread ID : 2156

Output on DebugView would look like this:
![DebugView](/img/injector.png)

Note that the injector only works against 32 bit processes.


Caveats
-------
- It reports all those API calls regardless of its memory protection, contents
being written and whether it gets executed. Thus, you should only focus on
output related to the sample you are analyzing as it reports a lot of legit
activities too.

 - It was designed so because it is far more difficult to track all written
regions and reports only when it is executed.

- It does not monitor any of processes existed when the driver was installed.
Thus, the second injection will not be reported if the sample injects code
into explorer.exe, and then the injected code in the explorer.exe injects
code into another process.

- Saved memory contents may or may not be the same as what was executed because
the driver only takes dump at occurrence of those API calls. This is particularly true
in the case of ZwMapViewOfSection().

 - These are limitations but will be fine for letting analysts know injection
may be happening.


Supported Platform(s)
-----------------
- Windows 7 SP1 and 8.1 (x86/x64)


License
-----------------
This software is released under the MIT License, see LICENSE.


