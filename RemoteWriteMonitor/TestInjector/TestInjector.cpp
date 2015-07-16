// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#include "stdafx.h"

// C/C++ standard headers
// Other external headers
// Windows headers
// Original headers

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const auto PAGE_SIZE = 0x1000;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

namespace ntdll {

NTSTATUS NTAPI
ZwCreateSection(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
                _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
                _In_opt_ PLARGE_INTEGER MaximumSize,
                _In_ ULONG SectionPageProtection,
                _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);

enum SECTION_INHERIT {
  ViewShare = 1,
  ViewUnmap = 2,
};

NTSTATUS NTAPI
ZwMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                   _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits,
                   _In_ SIZE_T CommitSize,
                   _Inout_opt_ PLARGE_INTEGER SectionOffset,
                   _Inout_ PSIZE_T ViewSize,
                   _In_ SECTION_INHERIT InheritDisposition,
                   _In_ ULONG AllocationType, _In_ ULONG Win32Protect);

NTSTATUS NTAPI
ZwUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

NTSTATUS NTAPI ZwClose(_In_ HANDLE Handle);

NTSTATUS NTAPI ZwSuspendProcess(_In_ HANDLE ProcessHandle);

NTSTATUS NTAPI ZwResumeProcess(_In_ HANDLE ProcessHandle);

}  // ntdll

struct REMOTE_THREAD_CONTEXT {
  using CreateThreadType = decltype(&::CreateThread);
  using CloseHandleType = decltype(&::CloseHandle);
  using SleepType = decltype(&::Sleep);
  using AllocConsoleType = decltype(&::AllocConsole);
  using GetStdHandleType = decltype(&::GetStdHandle);
  using WriteConsoleAType = decltype(&::WriteConsoleA);
  DWORD Tid;
  void* ThreadEntryPoint;
  CreateThreadType CreateThread;
  CloseHandleType CloseHandle;
  SleepType Sleep;
  AllocConsoleType AllocConsole;
  GetStdHandleType GetStdHandle;
  WriteConsoleAType WriteConsoleA;
};

struct REMOTE_MEMORY_BLOCK {
  REMOTE_THREAD_CONTEXT Parameter;
  std::uint8_t Code[PAGE_SIZE - sizeof(REMOTE_THREAD_CONTEXT)];
};
static_assert(sizeof(REMOTE_MEMORY_BLOCK) == PAGE_SIZE, "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

bool AppMain(const std::vector<std::wstring>& Args);

void Usage();

HANDLE Open32BitProcess(DWORD ProcessId);

REMOTE_THREAD_CONTEXT MakeRemoteThreadContext(void* ThreadEntryPoint);
std::shared_ptr<REMOTE_MEMORY_BLOCK> InstallCodeWithVirtualAllocEx(
    HANDLE ProcessHandle);

std::shared_ptr<REMOTE_MEMORY_BLOCK> InstallCodeWithZwMapViewOfSection(
    HANDLE ProcessHandle);

DWORD ExecuteCodeWithCreateRemoteThread(HANDLE ProcessHandle,
                                        REMOTE_MEMORY_BLOCK* RemoteMemory);

DWORD ExecuteCodeWithSetThreadContext(HANDLE ProcessHandle,
                                      REMOTE_MEMORY_BLOCK* RemoteMemory);

DWORD WINAPI RemoteCode(REMOTE_THREAD_CONTEXT* Context);

void RemoteCodeAsm();

void RemoteCodeZZZ();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

int _tmain(int argc, _TCHAR* argv[]) {
  auto result = EXIT_FAILURE;
  try {
    std::vector<std::wstring> args;
    for (auto i = 0; i < argc; ++i) {
      args.push_back(argv[i]);
    }
    if (AppMain(args)) {
      result = EXIT_SUCCESS;
    }
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
  } catch (...) {
    std::cout << "An unhandled exception raised." << std::endl;
  }
  return result;
}

// Main
bool AppMain(const std::vector<std::wstring>& Args) {
  if (Args.size() != 4) {
    Usage();
    return true;
  }

  const auto pid = std::stoul(Args[1]);
  const auto installationMethod = std::wstring(Args[2]);
  const auto executionMethod = std::wstring(Args[3]);

  std::shared_ptr<REMOTE_MEMORY_BLOCK>(*installer)(HANDLE) = nullptr;
  if (installationMethod == L"alloc") {
    installer = InstallCodeWithVirtualAllocEx;
  } else if (installationMethod == L"section") {
    installer = InstallCodeWithZwMapViewOfSection;
  }
  DWORD (*executer)(HANDLE, REMOTE_MEMORY_BLOCK*) = nullptr;
  if (executionMethod == L"remote") {
    executer = ExecuteCodeWithCreateRemoteThread;
  } else if (executionMethod == L"context") {
    executer = ExecuteCodeWithSetThreadContext;
  }

  if (!installer || !executer) {
    Usage();
    return false;
  }

  const auto processHandle =
      stdexp::make_unique_resource(Open32BitProcess(pid), &::CloseHandle);
  if (!processHandle) {
    return false;
  }

  // Inject code
  const auto remoteMemory = installer(processHandle.get());
  if (!remoteMemory) {
    return false;
  }
  std::cout << "Remote Address   : " << std::hex << remoteMemory.get()
            << std::endl;

  // Execute code
  const auto remoteThreadId = executer(processHandle.get(), remoteMemory.get());
  if (!remoteThreadId) {
    return false;
  }

  std::cout << "Remote Thread ID : " << std::dec << remoteThreadId << std::endl;

  // Do not execute a destructor for remoteMemory that will release remote code
  ::ExitProcess(EXIT_SUCCESS);
}

// Prints usage
void Usage() {
  std::cout << "Usage:\n"
               "  >this.exe <PID> <installation_method> <execution_method>\n"
               "\n"
               "  PID:\n"
               "     Target's process ID. The target must be 32bit process.\n"
               "\n"
               "  installation_method:\n"
               "     alloc   - use VirtualAllocEx\n"
               "     section - use ZwMapViewOfSection\n"
               "\n"
               "  execution_method:\n"
               "     remote  - use CreateRemoteThread\n"
               "     context - use SetThreadContext\n" << std::endl;
}

// Returns a full access handle to a 32bit process, or nullptr.
HANDLE Open32BitProcess(DWORD ProcessId) {
  const auto processHandle =
      ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
  if (!processHandle) {
    return nullptr;
  }
  BOOL amIwow64 = FALSE;
  BOOL isTargetWow64 = FALSE;
  if (!::IsWow64Process(::GetCurrentProcess(), &amIwow64) ||
      !::IsWow64Process(processHandle, &isTargetWow64) ||
      (amIwow64 && !isTargetWow64)) {
    ::CloseHandle(processHandle);
    return nullptr;
  }
  return processHandle;
}

// Returns a remote thread context.
REMOTE_THREAD_CONTEXT MakeRemoteThreadContext(void* ThreadEntryPoint) {
  const auto kernel32 = ::GetModuleHandle(TEXT("kernel32"));
  return {
      0, ThreadEntryPoint,
      reinterpret_cast<REMOTE_THREAD_CONTEXT::CreateThreadType>(
          ::GetProcAddress(kernel32, "CreateThread")),
      reinterpret_cast<REMOTE_THREAD_CONTEXT::CloseHandleType>(
          ::GetProcAddress(kernel32, "CloseHandle")),
      reinterpret_cast<REMOTE_THREAD_CONTEXT::SleepType>(
          ::GetProcAddress(kernel32, "Sleep")),
      reinterpret_cast<REMOTE_THREAD_CONTEXT::AllocConsoleType>(
          ::GetProcAddress(kernel32, "AllocConsole")),
      reinterpret_cast<REMOTE_THREAD_CONTEXT::GetStdHandleType>(
          ::GetProcAddress(kernel32, "GetStdHandle")),
      reinterpret_cast<REMOTE_THREAD_CONTEXT::WriteConsoleAType>(
          ::GetProcAddress(kernel32, "WriteConsoleA")),
  };
}

// Install code into a remote process using VirtualAllocEx.
std::shared_ptr<REMOTE_MEMORY_BLOCK> InstallCodeWithVirtualAllocEx(
    HANDLE ProcessHandle) {
  const auto remoteMemory = std::shared_ptr<REMOTE_MEMORY_BLOCK>(
      reinterpret_cast<REMOTE_MEMORY_BLOCK*>(
          ::VirtualAllocEx(ProcessHandle, nullptr, PAGE_SIZE, MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE)),
      [ProcessHandle](REMOTE_MEMORY_BLOCK* p) {
        ::VirtualFreeEx(ProcessHandle, p, 0, MEM_RELEASE);
      });
  if (!remoteMemory) {
    return nullptr;
  }

  const auto context = MakeRemoteThreadContext(&remoteMemory->Code);
  if (!::WriteProcessMemory(ProcessHandle, &remoteMemory->Parameter, &context,
                            sizeof(context), nullptr)) {
    return nullptr;
  }

  const auto codeSize = reinterpret_cast<std::uintptr_t>(&::RemoteCodeZZZ) -
                        reinterpret_cast<std::uintptr_t>(&::RemoteCode);
  if (!::WriteProcessMemory(ProcessHandle, &remoteMemory->Code, &::RemoteCode,
                            codeSize, nullptr)) {
    return nullptr;
  }
  return remoteMemory;
}

// Install code into a remote process using ZwMapViewOfSection.
std::shared_ptr<REMOTE_MEMORY_BLOCK> InstallCodeWithZwMapViewOfSection(
    HANDLE ProcessHandle) {
  const auto ntdll = ::GetModuleHandle(TEXT("ntdll"));
  const auto ZwCreateSection =
      reinterpret_cast<decltype(&ntdll::ZwCreateSection)>(
          ::GetProcAddress(ntdll, "ZwCreateSection"));
  const auto ZwMapViewOfSection =
      reinterpret_cast<decltype(&ntdll::ZwMapViewOfSection)>(
          ::GetProcAddress(ntdll, "ZwMapViewOfSection"));
  const auto ZwUnmapViewOfSection =
      reinterpret_cast<decltype(&ntdll::ZwUnmapViewOfSection)>(
          ::GetProcAddress(ntdll, "ZwUnmapViewOfSection"));
  const auto ZwClose = reinterpret_cast<decltype(&ntdll::ZwClose)>(
      ::GetProcAddress(ntdll, "ZwClose"));

  HANDLE sectionHandle = nullptr;
  LARGE_INTEGER sectionSize = {PAGE_SIZE};
  auto status =
      ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, nullptr, &sectionSize,
                      PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
  if (!NT_SUCCESS(status)) {
    return nullptr;
  }
  const auto sectionHandleCleaner =
      stdexp::make_scope_exit([&]() { ZwClose(sectionHandle); });

  SIZE_T viewSize = 0;
  void* viewAddress = nullptr;
  status = ZwMapViewOfSection(sectionHandle, ::GetCurrentProcess(),
                              &viewAddress, 0, PAGE_SIZE, nullptr, &viewSize,
                              ntdll::ViewUnmap, 0, PAGE_READWRITE);
  if (!NT_SUCCESS(status)) {
    return nullptr;
  }
  const auto viewCleaner = stdexp::make_scope_exit(
      [&]() { ZwUnmapViewOfSection(::GetCurrentProcess(), viewAddress); });

  SIZE_T remoteViewSize = 0;
  void* remoteViewAddress = nullptr;
  status = ZwMapViewOfSection(sectionHandle, ProcessHandle, &remoteViewAddress,
                              0, PAGE_SIZE, nullptr, &remoteViewSize,
                              ntdll::ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(status)) {
    return nullptr;
  }
  const auto remoteMemory =
      reinterpret_cast<REMOTE_MEMORY_BLOCK*>(remoteViewAddress);

  const auto memory = reinterpret_cast<REMOTE_MEMORY_BLOCK*>(viewAddress);
  memory->Parameter = MakeRemoteThreadContext(&remoteMemory->Code);

  const auto codeSize = reinterpret_cast<std::uintptr_t>(&::RemoteCodeZZZ) -
                        reinterpret_cast<std::uintptr_t>(&::RemoteCode);
  memcpy(&memory->Code, &::RemoteCode, codeSize);

  return std::shared_ptr<REMOTE_MEMORY_BLOCK>(
      remoteMemory,
      [=](REMOTE_MEMORY_BLOCK* p) { ZwUnmapViewOfSection(ProcessHandle, p); });
}

// Execute code in a remote process using CreateRemoteThread.
DWORD ExecuteCodeWithCreateRemoteThread(HANDLE ProcessHandle,
                                        REMOTE_MEMORY_BLOCK* RemoteMemory) {
  auto remoteThreadId = 0ul;
  const auto threadHandle = stdexp::make_unique_resource(
      ::CreateRemoteThread(
          ProcessHandle, nullptr, 0,
          reinterpret_cast<LPTHREAD_START_ROUTINE>(&RemoteMemory->Code),
          &RemoteMemory->Parameter, 0, &remoteThreadId),
      &::CloseHandle);
  if (!threadHandle) {
    return 0;
  }
  return remoteThreadId;
}

// Execute code in a remote process using SetThreadContext.
DWORD ExecuteCodeWithSetThreadContext(HANDLE ProcessHandle,
                                      REMOTE_MEMORY_BLOCK* RemoteMemory) {
  const auto ntdll = ::GetModuleHandle(TEXT("ntdll"));
  const auto ZwSuspendProcess =
      reinterpret_cast<decltype(&ntdll::ZwSuspendProcess)>(
          ::GetProcAddress(ntdll, "ZwSuspendProcess"));
  const auto ZwResumeProcess =
      reinterpret_cast<decltype(&ntdll::ZwResumeProcess)>(
          ::GetProcAddress(ntdll, "ZwResumeProcess"));

  auto status = ZwSuspendProcess(ProcessHandle);
  if (!NT_SUCCESS(status)) {
    return 0;
  }
  const auto processResumer =
      stdexp::make_scope_exit([=]() { ZwResumeProcess(ProcessHandle); });

  const auto snapshot = stdexp::make_unique_resource(
      ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), &::CloseHandle);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return 0;
  }

  // Get the first thread's ID on the target process. That is less than optimal
  // because it is not guaranteed that the thread is active or can be activated
  // by the call of InvalidateRect later.
  auto targetThreadId = 0ul;
  THREADENTRY32 th32 = {sizeof(th32)};
  for (::Thread32First(snapshot.get(), &th32);
       ::Thread32Next(snapshot.get(), &th32);
       /**/) {
    if (::GetProcessId(ProcessHandle) == th32.th32OwnerProcessID) {
      targetThreadId = th32.th32ThreadID;
      break;
    }
  }
  if (targetThreadId == 0) {
    return 0;
  }

  const auto threadHandle = stdexp::make_unique_resource(
      ::OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId), &::CloseHandle);
  if (!threadHandle) {
    return 0;
  }

  CONTEXT oldThreadContext = {CONTEXT_FULL};
  if (!::GetThreadContext(threadHandle.get(), &oldThreadContext)) {
    return 0;
  }

  const auto offsetToRemoteMemory =
      reinterpret_cast<std::uintptr_t>(RemoteCodeAsm) -
      reinterpret_cast<std::uintptr_t>(RemoteCode);
  const auto remoteCodeAsmAddr = (RemoteMemory->Code + offsetToRemoteMemory);
  auto newThreadContext = oldThreadContext;

  // Do not use volatile registers as it is not guaranteed that a value you set
  // in a volatile register is preserved until your code (EIP) is get executed.
  newThreadContext.Edi = reinterpret_cast<DWORD>(&RemoteMemory->Parameter);
  newThreadContext.Eip = reinterpret_cast<DWORD>(remoteCodeAsmAddr);
  if (!::SetThreadContext(threadHandle.get(), &newThreadContext)) {
    return 0;
  }

  status = ZwResumeProcess(ProcessHandle);
  ::InvalidateRect(nullptr, nullptr, TRUE);  // An attempt to active the thread

  SIZE_T readBytes = 0;
  auto remoteThreadId = 0ul;
  for (;;) {
    // Wait a remote thread's ID is set
    ::Sleep(100);
    if (!::ReadProcessMemory(ProcessHandle, &RemoteMemory->Parameter.Tid,
                             &remoteThreadId, sizeof(remoteThreadId),
                             &readBytes)) {
      return 0;
    }
    if (remoteThreadId != 0) {
      break;
    }
    ::Sleep(900);
    std::cout << "Waiting for the thread get executed." << std::endl;
  }

  // An error on a CreateThread call
  if (remoteThreadId == 0xdeaddead) {
    return 0;
  }

  if (::SuspendThread(threadHandle.get()) == -1) {
    return 0;
  }
  CONTEXT currentThreadContext = {CONTEXT_FULL};
  if (!::GetThreadContext(threadHandle.get(), &currentThreadContext)) {
    return 0;
  }
  if (!::SetThreadContext(threadHandle.get(), &oldThreadContext)) {
    return 0;
  }
  if (::ResumeThread(threadHandle.get()) == -1) {
    return 0;
  }
  return remoteThreadId;
}

// Following code is injected to a remote process
#pragma optimize("", off)
#pragma check_stack(off)
#pragma runtime_checks("", off)

// Hi!
DWORD WINAPI RemoteCode(REMOTE_THREAD_CONTEXT* Context) {
  Context->AllocConsole();
  const auto out = Context->GetStdHandle(STD_OUTPUT_HANDLE);
  for (; /*ever*/;) {
    const char MESSAGE[] = {
        'H', 'i', '\n',
    };
    auto written = 0ul;
    Context->WriteConsoleA(out, MESSAGE, sizeof(MESSAGE), &written, nullptr);
    Context->Sleep(1000);
  }
}

// Used for remote executing using a section. It creates a thread executing
// RemoteCode.
__declspec(naked) void RemoteCodeAsm() {
  __asm {
  nop
  xor eax, eax
  mov ecx, [edi + 4]  ; ThreadEntry
  mov edx, [edi + 8]  ; CreateThread

  push edi  ; lpThreadId
  push eax  ; dwCreationFlags
  push edi  ; lpParameter
  push ecx  ; lpStartAddress
  push eax  ; dwStackSize
  push eax  ; lpThreadAttributes
  call edx  ; CreateThread

  test eax, eax
  jnz Close
  mov dword ptr [edi], 0xdeaddead   ; *Tid = 0xdeaddead
  jmp EndlessLoop

Close:
  push eax
  mov edx, [edi + 12]  ; CloseHandle
  call ecx  ; CloseHandle

EndlessLoop:
  jmp EndlessLoop
  int 3
  }
}

void RemoteCodeZZZ() {}
#pragma runtime_checks("", restore)
#pragma check_stack()
#pragma optimize("", on)
