RemoteWriteMonitor
========

RemoteWriteMonitor is a tool to help malware analysts tell that the sample is
injecting code to other process. This tool is designed to find a possible
remote process code injection and execution without use of NtCreateThread() or
NtCreateThreadEx().

A supporting tool 'injector' is a sample program doing that type of code
injection.

Installation and Uninstallation
-----------------

Use the 'sc' command, for example, for installation:

    >sc create rwmon type= kernel binPath= C:\Users\user\Desktop\RemoteWriteMonitor.sys
    >sc start rwmon

And for uninstallation:

    >sc stop rwmon
    >sc delete rwmon

Usage
-------

Once you have installed it, you can execute the sample and see output by the
driver if any.

The driver reports when any process newly created after the installation called
NtWriteVirtualMemory() or NtMapViewOfSection() against another process and saves
what was written or mapped into the remote process. Output can be seen with DebugView and are all saved under the
C:\Windows\RemoteWriteMonitor\ directory. Written and mapped data is stored as
\<SHA1\>.bin apart from a log file.

'injector' could be used to test the driver's function. Injecting and executing code into
notepad.exe could be done by the following commands:

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

Caveats
-------
- It reports all those API calls regardless of its memory protection, contents
being written and whether it gets executed. Thus, you should only focus on
output related to the sample you are analyzing as it reports a lot of legit
activities too.

 - It was designed so because it is far more difficult to track all written
regions and reports only when it is executed (I wrote [that](https://sites.google.com/site/tandasat/home/egg) long time ago, and that was hell).

- It does not monitor any of processes existed when the driver's installation.
Thus, the second injection will not be reported when the sample injects code
into an explorer.exe, and then the injected code in the explorer.exe injects
code into another process.

- It may or may not save the contents of memory that is really executed because
it only takes dump at the occurrence of those API call. This is particularly true
in the case of ZwMapViewOfSection().

 - These are limitations but will be fine for letting analysts know injection
may be happening.


Supported Platform(s)
-----------------
- Windows 7 SP1 x86


License
-----------------
This software is released under the MIT License, see LICENSE.


