// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver and initializes other
// components in this module.
//
#include "stdafx.h"
#include "log.h"

namespace stdexp = std::experimental;

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const auto RWMONP_WHITELIST_ARRAY_SIZE = 1000;

static const wchar_t RWMONP_OUT_DIRECTORY_PATH[] =
    L"\\SystemRoot\\RemoteWriteMonitor";
static const wchar_t RWMONP_LOG_FILE_PATH[] =
    L"\\SystemRoot\\RemoteWriteMonitor\\RemoteWriteMonitor.log";

#if DBG
static const auto RWMONP_LOG_LEVEL = LOG_PUT_LEVEL_DEBUG;
#else
static const auto RWMONP_LOG_LEVEL = LOG_PUT_LEVEL_INFO;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct SERVICE_DESCRIPTOR_TABLE {
  PVOID *ServiceTable;
  PULONG CounterTable;
  ULONG TableSize;
  PUCHAR ArgumentTable;
};

union CR0_REGISTER {
  ULONG_PTR Value;
  struct {
    unsigned PE : 1;          // [0] Protected Mode Enabled
    unsigned MP : 1;          // [1] Monitor Coprocessor FLAG
    unsigned EM : 1;          // [2] Emulate FLAG
    unsigned TS : 1;          // [3] Task Switched FLAG
    unsigned ET : 1;          // [4] Extension Type FLAG
    unsigned NE : 1;          // [5] Numeric Error
    unsigned Reserved1 : 10;  // [6-15]
    unsigned WP : 1;          // [16] Write Protect
    unsigned Reserved2 : 1;   // [17]
    unsigned AM : 1;          // [18] Alignment Mask
    unsigned Reserved3 : 10;  // [19-28]
    unsigned NW : 1;          // [29] Not Write-Through
    unsigned CD : 1;          // [30] Cache Disable
    unsigned PG : 1;          // [31] Paging Enabled
  } Fields;
};
static_assert(sizeof(CR0_REGISTER) == sizeof(void *), "Size check");

struct SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  BYTE Reserved1[48];
  PVOID Reserved2[3];
  HANDLE UniqueProcessId;
  PVOID Reserved3;
  ULONG HandleCount;
  BYTE Reserved4[4];
  PVOID Reserved5[11];
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER Reserved6[6];
};

enum SYSTEM_INFORMATION_CLASS {
  SystemProcessInformation = 5,
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTKERNELAPI UCHAR *NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);

EXTERN_C NTSTATUS NTAPI
ZwQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
                         _Inout_ PVOID SystemInformation,
                         _In_ ULONG SystemInformationLength,
                         _Out_opt_ PULONG ReturnLength);

EXTERN_C
NTSTATUS NTAPI NtWriteVirtualMemory(_In_ HANDLE ProcessHandle,
                                    _In_ PVOID BaseAddress, _In_ PVOID Buffer,
                                    _In_ ULONG BytesToWrite,
                                    _Out_opt_ PULONG BytesWritten);
EXTERN_C
NTSTATUS NTAPI
NtMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                   _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                   _In_ SIZE_T CommitSize,
                   _Inout_opt_ PLARGE_INTEGER SectionOffset,
                   _Inout_ PSIZE_T ViewSize,
                   _In_ SECTION_INHERIT InheritDisposition,
                   _In_ ULONG AllocationType, _In_ ULONG Win32Protect);

using NtWriteVirtualMemoryPtrType = decltype(&NtWriteVirtualMemory);
using NtMapViewOfSectionPtrType = decltype(&NtMapViewOfSection);

EXTERN_C DRIVER_INITIALIZE DriverEntry;

EXTERN_C static NTSTATUS RWMonpCreateDirectory(_In_ const wchar_t *PathW);

EXTERN_C static NTSTATUS RWMonpForEachProcess(
    _In_ bool (*Callback)(_In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo,
                          _In_opt_ void *Context),
    _In_opt_ void *Context);

EXTERN_C static bool RWMonpSaveExistingPID(
    _In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo, _In_ void *Context);

EXTERN_C static DRIVER_UNLOAD RWMonpDriverUnload;

EXTERN_C static NTSTATUS RWMonpSleep(_In_ LONG Millisecond);

EXTERN_C static NTSTATUS RWMonpSetMonitorHooks(_In_ bool Enable);

EXTERN_C static void RWMonpDisableWriteProtect();

EXTERN_C static void RWMonpEnableWriteProtect();

EXTERN_C static void RWMonpHookSSDT(_In_ ULONG Index, _In_ void *HookRoutine,
                                    _Out_opt_ void **OriginalRoutine);

EXTERN_C static NTSTATUS NTAPI
RWMonpNtWriteVirtualMemory_Hook(_In_ HANDLE ProcessHandle,
                                _In_ PVOID BaseAddress, _In_ PVOID Buffer,
                                _In_ ULONG BytesToWrite,
                                _Out_opt_ PULONG BytesWritten);

EXTERN_C static NTSTATUS NTAPI RWMonpNtMapViewOfSection_Hook(
    _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect);

EXTERN_C static bool RWMonpCheckData(_In_ HANDLE ProcessHandle,
                                     _In_ void *RemoteAddress,
                                     _In_opt_ void *Contents,
                                     _In_ ULONG DataSize);

_Success_(return == true) EXTERN_C
    static bool RWMonpIsInterprocessWrite(_In_ HANDLE ProcessHandle,
                                          _Out_ PEPROCESS *TargetProcess);

EXTERN_C static NTSTATUS RWMonpCopyDataFromUserSpace(
    _Out_ void *Buffer, _In_ const void *BaseAddress, _In_ ULONG DataSize,
    _In_opt_ PEPROCESS TargetProcess);

EXTERN_C static NTSTATUS RWMonpCopyMemoryWithSEH(_Out_ void *Destionation,
                                                 _In_ const void *Source,
                                                 _In_ SIZE_T Length);

_Success_(return == true) EXTERN_C
    static bool RWMonpGetSha1(_Out_ UCHAR(&Sha1Hash)[20], _In_ void *Data,
                              _In_ SIZE_T DataSize);

EXTERN_C static NTSTATUS RWMonpWriteFile(_In_ const wchar_t *OutPathW,
                                         _In_ void *Buffer,
                                         _In_ ULONG BufferSize,
                                         _In_ ACCESS_MASK DesiredAccess,
                                         _In_ ULONG CreateDisposition);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

EXTERN_C SERVICE_DESCRIPTOR_TABLE *KeServiceDescriptorTable;

static auto g_RWMonpNtMapViewOfSection_Index = 0;
static auto g_RWMonpNtWriteVirtualMemory_Index = 0;
static NtWriteVirtualMemoryPtrType g_RWMonpNtWriteVirtualMemory_Orig = nullptr;
static NtMapViewOfSectionPtrType g_RWMonpNtMapViewOfSection_Orig = nullptr;

static HANDLE g_RWMonpWhiteListedProcessIDs[RWMONP_WHITELIST_ARRAY_SIZE] = {};
static BCRYPT_ALG_HANDLE g_RWMonpSha1AlgorithmHandle = nullptr;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

//
// INIT section begin
//
ALLOC_TEXT(INIT, DriverEntry)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                              _In_ PUNICODE_STRING RegistryPath) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(RegistryPath);
  auto status = STATUS_UNSUCCESSFUL;

  DriverObject->DriverUnload = RWMonpDriverUnload;
  DBG_BREAK();

  // Create a directory for a log file and dumped files before initializing
  // the Log system
  status = RWMonpCreateDirectory(RWMONP_OUT_DIRECTORY_PATH);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialize the Log system
  status = LogInitialization(
      RWMONP_LOG_LEVEL | LOG_OPT_DISABLE_TIME | LOG_OPT_DISABLE_FUNCTION_NAME,
      RWMONP_LOG_FILE_PATH, nullptr);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedLogTermination =
      stdexp::make_scope_exit([] { LogTermination(nullptr); });

  // Check the OS version and initialize right indexes for SSDT hook.
  RTL_OSVERSIONINFOW osVersion = {sizeof(osVersion)};
  status = RtlGetVersion(&osVersion);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("RtlGetVersion failed (%08x)", status);
    return status;
  }
  if (osVersion.dwMajorVersion == 6 && osVersion.dwMinorVersion == 1) {
    g_RWMonpNtMapViewOfSection_Index = 0xA8;
    g_RWMonpNtWriteVirtualMemory_Index = 0x18F;
  } else if (osVersion.dwMajorVersion == 6 && osVersion.dwMinorVersion == 3) {
    g_RWMonpNtMapViewOfSection_Index = 0xF6;
    g_RWMonpNtWriteVirtualMemory_Index = 0x3;
  } else {
    LOG_ERROR("Unsupported OS version");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }

  // Save existing processes' IDs in a white list
  auto index = 0;
  status = RWMonpForEachProcess(RWMonpSaveExistingPID, &index);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("ForEachProcess failed (%08x)", status);
    return status;
  }

  // Initialize the crypt APIs.
  status = BCryptOpenAlgorithmProvider(&g_RWMonpSha1AlgorithmHandle,
                                       BCRYPT_SHA1_ALGORITHM, nullptr, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptOpenAlgorithmProvider failed (%08x)", status);
    return status;
  }

  // Install SSDT hooks
  RWMonpSetMonitorHooks(true);
  scopedLogTermination.release();
  LOG_INFO("RemoteWriteMonitor installed");
  return status;
}

// Create a directory
ALLOC_TEXT(INIT, RWMonpCreateDirectory)
EXTERN_C static NTSTATUS RWMonpCreateDirectory(_In_ const wchar_t *PathW) {
  PAGED_CODE();

  UNICODE_STRING path = {};
  RtlInitUnicodeString(&path, PathW);
  OBJECT_ATTRIBUTES objAttr = RTL_INIT_OBJECT_ATTRIBUTES(
      &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

  IO_STATUS_BLOCK ioStatus = {};
  HANDLE directory = nullptr;
  NTSTATUS status = ZwCreateFile(
      &directory, GENERIC_WRITE, &objAttr, &ioStatus, nullptr,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, nullptr, 0);
  if (NT_SUCCESS(status)) {
    ZwClose(directory);
  }

  return status;
}

// Apply Callback for each process. Enumeration can be discontinued by returning
// false from Callback.
ALLOC_TEXT(INIT, RWMonpForEachProcess)
EXTERN_C static NTSTATUS RWMonpForEachProcess(
    _In_ bool (*Callback)(_In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo,
                          _In_opt_ void *Context),
    _In_opt_ void *Context) {
  PAGED_CODE();

  auto processInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
      ExAllocatePoolWithTag(PagedPool, 0x10000, RWMON_POOL_TAG_NAME));
  if (!processInfo) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  ULONG returnLength = 0;
  auto status = ZwQuerySystemInformation(SystemProcessInformation, processInfo,
                                         0x10000, &returnLength);
  if (!NT_SUCCESS(status) && returnLength) {
    ExFreePoolWithTag(processInfo, RWMON_POOL_TAG_NAME);
    processInfo =
        reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(ExAllocatePoolWithTag(
            PagedPool, returnLength + PAGE_SIZE, RWMON_POOL_TAG_NAME));
    if (!processInfo) {
      return STATUS_MEMORY_NOT_ALLOCATED;
    }

    status =
        ZwQuerySystemInformation(SystemProcessInformation, processInfo,
                                 (returnLength + PAGE_SIZE), &returnLength);
  }
  const auto scopedExFreePoolWithTag = stdexp::make_scope_exit(
      [processInfo] { ExFreePoolWithTag(processInfo, RWMON_POOL_TAG_NAME); });
  if (!NT_SUCCESS(status)) {
    return status;
  }

  for (auto current = processInfo; current; /**/) {
    if (!Callback(current, Context)) {
      break;
    }

    if (!current->NextEntryOffset) {
      break;
    }
    current = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
        reinterpret_cast<ULONG_PTR>(current) + current->NextEntryOffset);
  }

  return status;
}

// A callback routine saving existing processes' IDs into a white list.
ALLOC_TEXT(INIT, RWMonpSaveExistingPID)
EXTERN_C static bool RWMonpSaveExistingPID(
    _In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo, _In_ void *Context) {
  PAGED_CODE();

  auto &index = *static_cast<int *>(Context);
  if (index >=
      RWMONP_WHITELIST_ARRAY_SIZE - 1) {  // -1 to have 0 at the end at least
    return false;
  }
  if (ProcessInfo->UniqueProcessId) {
    g_RWMonpWhiteListedProcessIDs[index++] = ProcessInfo->UniqueProcessId;
  }
  return true;
}

//
// Unloading Functions
//

// Unloading the driver. Close and restore everything.
ALLOC_TEXT(PAGED, RWMonpDriverUnload)
EXTERN_C static void RWMonpDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DriverObject);

  LOG_DEBUG("Being terminated.");
  // DBG_BREAK();

  RWMonpSetMonitorHooks(false);
  RWMonpSleep(1000);
  BCryptCloseAlgorithmProvider(g_RWMonpSha1AlgorithmHandle, 0);
  LogTermination(nullptr);
}

// Sleep.
ALLOC_TEXT(PAGED, RWMonpSleep)
EXTERN_C static NTSTATUS RWMonpSleep(_In_ LONG Millisecond) {
  PAGED_CODE();

  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000 * Millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

//
// Common
//

// Install or Uninstall necessary SSDT hooks.
EXTERN_C static NTSTATUS RWMonpSetMonitorHooks(_In_ bool Enable) {
  // Need to rise IRQL not to allow the system to change an execution processor
  // during the operation because this code changes a state of processor (CR0).
  KIRQL oldIrql = 0;
  KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
  const auto scopedIrql =
      stdexp::make_scope_exit([oldIrql]() { KeLowerIrql(oldIrql); });

  RWMonpDisableWriteProtect();
  const auto scopedWriteProtection =
      stdexp::make_scope_exit([] { RWMonpEnableWriteProtect(); });

  if (Enable) {
    // Install
    RWMonpHookSSDT(g_RWMonpNtMapViewOfSection_Index,
                   RWMonpNtMapViewOfSection_Hook,
                   reinterpret_cast<void **>(&g_RWMonpNtMapViewOfSection_Orig));
    RWMonpHookSSDT(
        g_RWMonpNtWriteVirtualMemory_Index, RWMonpNtWriteVirtualMemory_Hook,
        reinterpret_cast<void **>(&g_RWMonpNtWriteVirtualMemory_Orig));
  } else {
    // Uninstall
    RWMonpHookSSDT(g_RWMonpNtMapViewOfSection_Index,
                   g_RWMonpNtMapViewOfSection_Orig, nullptr);
    RWMonpHookSSDT(g_RWMonpNtWriteVirtualMemory_Index,
                   g_RWMonpNtWriteVirtualMemory_Orig, nullptr);
  }
  return STATUS_SUCCESS;
}

// Disable the write protection
EXTERN_C static void RWMonpDisableWriteProtect() {
  CR0_REGISTER cr0 = {__readcr0()};
  cr0.Fields.WP = false;
  __writecr0(cr0.Value);
}

// Enable the write protection
EXTERN_C static void RWMonpEnableWriteProtect() {
  CR0_REGISTER cr0 = {__readcr0()};
  cr0.Fields.WP = true;
  __writecr0(cr0.Value);
}

// Get an original value of the SSDT and replace it with a new value.
EXTERN_C static void RWMonpHookSSDT(_In_ ULONG Index, _In_ void *HookRoutine,
                                    _Out_opt_ void **OriginalRoutine) {
  if (OriginalRoutine) {
    *OriginalRoutine = KeServiceDescriptorTable->ServiceTable[Index];
  }
  KeServiceDescriptorTable->ServiceTable[Index] = HookRoutine;
}

//
// Hook Handlers
//

// A hook handler for NtWriteVirtualMemory
ALLOC_TEXT(PAGED, RWMonpNtWriteVirtualMemory_Hook)
EXTERN_C static NTSTATUS NTAPI
RWMonpNtWriteVirtualMemory_Hook(_In_ HANDLE ProcessHandle,
                                _In_ PVOID BaseAddress, _In_ PVOID Buffer,
                                _In_ ULONG BytesToWrite,
                                _Out_opt_ PULONG BytesWritten) {
  PAGED_CODE();

  const auto result = g_RWMonpNtWriteVirtualMemory_Orig(
      ProcessHandle, BaseAddress, Buffer, BytesToWrite, BytesWritten);
  if (NT_SUCCESS(result)) {
    RWMonpCheckData(ProcessHandle, BaseAddress, Buffer, BytesToWrite);
  }
  return result;
}

// A hook handler for NtMapViewOfSection
ALLOC_TEXT(PAGED, RWMonpNtMapViewOfSection_Hook)
EXTERN_C static NTSTATUS NTAPI RWMonpNtMapViewOfSection_Hook(
    _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect) {
  PAGED_CODE();

  const auto result = g_RWMonpNtMapViewOfSection_Orig(
      SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
      SectionOffset, ViewSize, InheritDisposition, AllocationType,
      Win32Protect);
  if (NT_SUCCESS(result)) {
    RWMonpCheckData(ProcessHandle, *BaseAddress, nullptr, *ViewSize);
  }
  return result;
}

// Check if the call is inter-process write, and log it if so.
ALLOC_TEXT(PAGED, RWMonpCheckData)
EXTERN_C static bool RWMonpCheckData(_In_ HANDLE ProcessHandle,
                                     _In_ void *RemoteAddress,
                                     _In_opt_ void *Contents,
                                     _In_ ULONG DataSize) {
  PAGED_CODE();

  const auto isWriteVirtualMemory = (Contents != nullptr);

  // Check if it is a interprocess operation
  PEPROCESS targetProcess = nullptr;
  if (!RWMonpIsInterprocessWrite(ProcessHandle, &targetProcess)) {
    return false;
  }
  const auto scopedDereference = stdexp::make_scope_exit(
      [targetProcess] { ObDereferenceObject(targetProcess); });

  // Allocate a memory to copy written data
  auto data = stdexp::make_unique_resource(
      ExAllocatePoolWithTag(PagedPool, DataSize, RWMON_POOL_TAG_NAME),
      [](void *p) { ExFreePoolWithTag(p, RWMON_POOL_TAG_NAME); });
  if (!data) {
    return false;
  }

  // Copy the written data
  auto status = STATUS_SUCCESS;
  if (Contents) {
    status =
        RWMonpCopyDataFromUserSpace(data.get(), Contents, DataSize, nullptr);
  } else {
    status = RWMonpCopyDataFromUserSpace(data.get(), RemoteAddress, DataSize,
                                         targetProcess);
  }
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("CopyDataFromUserSpace failed (%08x)", status);
    return false;
  }

  // Calculate SHA1 of the written data
  UCHAR sha1Hash[20] = {};
  if (!RWMonpGetSha1(sha1Hash, data.get(), DataSize)) {
    return false;
  }
  wchar_t sha1HashW[41] = {};
  for (auto i = 0; i < RTL_NUMBER_OF(sha1Hash); ++i) {
    const auto outW = sha1HashW + i * 2;
    RtlStringCchPrintfW(outW, 3, L"%02x", sha1Hash[i]);
  }

  // Save it to a file
  wchar_t outPathW[260];
  status = RtlStringCchPrintfW(outPathW, RTL_NUMBER_OF(outPathW), L"%s\\%s.bin",
                               RWMONP_OUT_DIRECTORY_PATH, sha1HashW);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("RtlStringCchPrintfW failed (%08x)", status);
    return false;
  }
  status = RWMonpWriteFile(outPathW, data.get(), DataSize, GENERIC_WRITE,
                           FILE_CREATE);
  if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) {
    LOG_ERROR_SAFE("WriteFile failed (%08x)", status);
    return false;
  }

  // Log it
  LOG_INFO_SAFE("Remote %s onto %5lu (%-15s) at %p (saved as %S, %lu bytes)",
                (isWriteVirtualMemory) ? "write" : "map  ",
                PsGetProcessId(targetProcess),
                PsGetProcessImageFileName(targetProcess), RemoteAddress,
                sha1HashW, DataSize);
  return true;
}

// Check if the write operation is interprocess and from a not white listed
// process
ALLOC_TEXT(PAGED, RWMonpIsInterprocessWrite)
_Success_(return == true) EXTERN_C
    static bool RWMonpIsInterprocessWrite(_In_ HANDLE ProcessHandle,
                                          _Out_ PEPROCESS *TargetProcess) {
  PAGED_CODE();

  if (ProcessHandle == ZwCurrentProcess()) {
    return false;
  }

  const auto pid = PsGetCurrentProcessId();
  for (auto i = 0; g_RWMonpWhiteListedProcessIDs[i]; ++i) {
    if (g_RWMonpWhiteListedProcessIDs[i] == pid) {
      return false;
    }
  }

  auto status = ObReferenceObjectByHandle(
      ProcessHandle, 0, *PsProcessType, UserMode,
      reinterpret_cast<void **>(TargetProcess), nullptr);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("ObReferenceObjectByHandle failed (%08x)", status);
    return false;
  }

  if (*TargetProcess == PsGetCurrentProcess()) {
    ObDereferenceObject(*TargetProcess);
    return false;
  }
  return true;
}

// Copy data from user-space
ALLOC_TEXT(PAGED, RWMonpCopyDataFromUserSpace)
EXTERN_C static NTSTATUS RWMonpCopyDataFromUserSpace(
    _Out_ void *Buffer, _In_ const void *BaseAddress, _In_ ULONG DataSize,
    _In_opt_ PEPROCESS TargetProcess) {
  PAGED_CODE();

  if (TargetProcess) {
    // Need to switch to another process memory space to access the data
    KAPC_STATE apcState = {};
    KeStackAttachProcess(TargetProcess, &apcState);
    const auto scopedKeUnstackDetachProcess = stdexp::make_scope_exit(
        [&apcState] { KeUnstackDetachProcess(&apcState); });
    return RWMonpCopyMemoryWithSEH(Buffer, BaseAddress, DataSize);
  } else {
    // The current process contains the data
    return RWMonpCopyMemoryWithSEH(Buffer, BaseAddress, DataSize);
  }
}

// RtlCopyMemory wrapped with SEH
ALLOC_TEXT(PAGED, RWMonpCopyMemoryWithSEH)
EXTERN_C static NTSTATUS RWMonpCopyMemoryWithSEH(_Out_ void *Destionation,
                                                 _In_ const void *Source,
                                                 _In_ SIZE_T Length) {
  PAGED_CODE();

  auto status = STATUS_SUCCESS;
  __try {
    RtlCopyMemory(Destionation, Source, Length);
  } __except (status = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
  }
  return status;
}

// Calculate SHA1
ALLOC_TEXT(PAGED, RWMonpGetSha1)
_Success_(return == true) EXTERN_C
    static bool RWMonpGetSha1(_Out_ UCHAR(&Sha1Hash)[20], _In_ void *Data,
                              _In_ SIZE_T DataSize) {
  PAGED_CODE();

  BCRYPT_HASH_HANDLE hashHandle = nullptr;
  auto status = BCryptCreateHash(g_RWMonpSha1AlgorithmHandle, &hashHandle,
                                 nullptr, 0, nullptr, 0, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptCreateHash failed (%08x)", status);
    return false;
  }
  const auto scopedBCryptDestroyHash =
      stdexp::make_scope_exit([hashHandle] { BCryptDestroyHash(hashHandle); });

  status = BCryptHashData(hashHandle, static_cast<UCHAR *>(Data), DataSize, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptHashData failed (%08x)", status);
    return false;
  }

  static_assert(sizeof(Sha1Hash) == 20, "Size check");
  status = BCryptFinishHash(hashHandle, Sha1Hash, sizeof(Sha1Hash), 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptFinishHash failed (%08x)", status);
    return false;
  }

  return true;
}

// Write data to a file
ALLOC_TEXT(PAGED, RWMonpWriteFile)
EXTERN_C static NTSTATUS RWMonpWriteFile(_In_ const wchar_t *OutPathW,
                                         _In_ void *Buffer,
                                         _In_ ULONG BufferSize,
                                         _In_ ACCESS_MASK DesiredAccess,
                                         _In_ ULONG CreateDisposition) {
  PAGED_CODE();

  UNICODE_STRING outPath = {};
  RtlInitUnicodeString(&outPath, OutPathW);
  OBJECT_ATTRIBUTES objAttr = RTL_INIT_OBJECT_ATTRIBUTES(
      &outPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

  IO_STATUS_BLOCK ioStatus = {};
  HANDLE file = nullptr;
  auto status = ZwCreateFile(
      &file, DesiredAccess, &objAttr, &ioStatus, nullptr, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_WRITE, CreateDisposition,
      FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
          FILE_NON_DIRECTORY_FILE,
      nullptr, 0);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = ZwWriteFile(file, nullptr, nullptr, nullptr, &ioStatus, Buffer,
                       BufferSize, nullptr, nullptr);
  ZwClose(file);
  return status;
}
