// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements functions for checking if data is written
// by a remote process and saving it if so.
//
#include "stdafx.h"
#include "check.h"
#include "log.h"
#include "util.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const auto CHECKP_WHITELIST_ARRAY_SIZE = 1000;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

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


enum INTER_PROCESS_TYPE
{
  INTER_PROCESS_WRITE,
  INTER_PROCESS_MAP,
};

struct CHECK_WORK_ITEM_CONTEXT
{
  WORK_QUEUE_ITEM WorkItem;
  void *Data;
  ULONG DataSize;
  INTER_PROCESS_TYPE Type;
  PEPROCESS WriterProcess;
  PEPROCESS TargetProcess;
  void *RemoteAddress;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTKERNELAPI UCHAR *NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);

EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

EXTERN_C static NTSTATUS CheckpForEachProcess(
    _In_ bool (*Callback)(_In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo,
                          _In_opt_ void *Context),
    _In_opt_ void *Context);

EXTERN_C static bool CheckpSaveExistingPID(
    _In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo, _In_ void *Context);

_Success_(return == true) EXTERN_C
    static bool CheckpIsInterprocessWrite(_In_ HANDLE ProcessHandle,
                                          _Out_ PEPROCESS *TargetProcess);

EXTERN_C static NTSTATUS CheckpCopyDataFromUserSpace(
    _Out_ void *Buffer, _In_ const void *BaseAddress, _In_ ULONG DataSize,
    _In_opt_ PEPROCESS TargetProcess);

EXTERN_C static NTSTATUS CheckpTryCopyMemory(_Out_ void *Destionation,
                                             _In_ const void *Source,
                                             _In_ SIZE_T Length);

EXTERN_C static void CheckpWorkItemRoutine(_In_ void *Context);

_Success_(return == true) EXTERN_C
    static bool CheckpGetSha1(_Out_ UCHAR(&Sha1Hash)[20], _In_ void *Data,
                              _In_ ULONG DataSize);

EXTERN_C static NTSTATUS CheckpWriteFile(_In_ const wchar_t *OutPathW,
                                         _In_ void *Buffer,
                                         _In_ ULONG BufferSize,
                                         _In_ ACCESS_MASK DesiredAccess,
                                         _In_ ULONG CreateDisposition);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static wchar_t g_CheckpLogDirecotry[MAX_PATH] = {};
static HANDLE g_CheckpWhiteListedProcessIDs[CHECKP_WHITELIST_ARRAY_SIZE] = {};
static BCRYPT_ALG_HANDLE g_CheckpSha1AlgorithmHandle = nullptr;
static volatile long g_CheckpNumberOfActiveWorkQueueItems = 0;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initialize the Check subsystem
ALLOC_TEXT(INIT, CheckInitialization)
EXTERN_C NTSTATUS CheckInitialization(_In_ const wchar_t *LogDirectry) {
  PAGED_CODE();

  auto status = RtlStringCchCopyW(
      g_CheckpLogDirecotry, RTL_NUMBER_OF(g_CheckpLogDirecotry), LogDirectry);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("RtlStringCchCopyW failed (%08x)", status);
    return status;
  }

  // Save existing processes' IDs in a white list
  auto index = 0;
  status = CheckpForEachProcess(CheckpSaveExistingPID, &index);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("ForEachProcess failed (%08x)", status);
    return status;
  }

  // Initialize the crypt APIs.
  status = BCryptOpenAlgorithmProvider(&g_CheckpSha1AlgorithmHandle,
                                       BCRYPT_SHA1_ALGORITHM, nullptr, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptOpenAlgorithmProvider failed (%08x)", status);
    return status;
  }
  return status;
}

// Terminates the check subsystem
ALLOC_TEXT(PAGED, CheckTermination)
EXTERN_C void CheckTermination() {
  PAGED_CODE();

  // while (g_CheckpNumberOfActiveWorkQueueItems != 0)
  while (InterlockedCompareExchange(&g_CheckpNumberOfActiveWorkQueueItems, 0,
                                     0) != 0) {
    UtilSleep(500);
  }

  BCryptCloseAlgorithmProvider(g_CheckpSha1AlgorithmHandle, 0);
}

// Apply Callback for each process. Enumeration can be discontinued by returning
// false from Callback.
ALLOC_TEXT(INIT, CheckpForEachProcess)
EXTERN_C static NTSTATUS CheckpForEachProcess(
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
  if (!NT_SUCCESS(status)) {
    goto End;
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

End:;
  ExFreePoolWithTag(processInfo, RWMON_POOL_TAG_NAME);
  return status;
}

// A callback routine saving existing processes' IDs into a white list.
ALLOC_TEXT(INIT, CheckpSaveExistingPID)
EXTERN_C static bool CheckpSaveExistingPID(
    _In_ const SYSTEM_PROCESS_INFORMATION *ProcessInfo, _In_ void *Context) {
  PAGED_CODE();

  auto &index = *static_cast<int *>(Context);
  if (index >=
      CHECKP_WHITELIST_ARRAY_SIZE - 1) {  // -1 to have 0 at the end at least
    return false;
  }
  if (ProcessInfo->UniqueProcessId) {
    g_CheckpWhiteListedProcessIDs[index++] = ProcessInfo->UniqueProcessId;
  }
  return true;
}

// Check if the call is inter-process write, and log it if so.
ALLOC_TEXT(PAGED, CheckData)
EXTERN_C bool CheckData(_In_ HANDLE ProcessHandle, _In_ void *RemoteAddress,
                        _In_opt_ void *Contents, _In_ ULONG DataSize) {
  PAGED_CODE();

  // Check if it is a interprocess operation
  PEPROCESS targetProcess = nullptr;
  if (!CheckpIsInterprocessWrite(ProcessHandle, &targetProcess)) {
    return false;
  }

  // Allocate a memory to copy written data
  auto data = ExAllocatePoolWithTag(PagedPool, DataSize, RWMON_POOL_TAG_NAME);
  if (!data) {
    goto FailureEnd;
  }

  // Copy the written data
  auto status = STATUS_SUCCESS;
  if (Contents) {
    status = CheckpCopyDataFromUserSpace(data, Contents, DataSize, nullptr);
  } else {
    status = CheckpCopyDataFromUserSpace(data, RemoteAddress, DataSize,
                                         targetProcess);
  }
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("CopyDataFromUserSpace failed (%08x)", status);
    goto FailureEnd;
  }

  // Allocate and queue an work queue item
  auto workItemContext = reinterpret_cast<CHECK_WORK_ITEM_CONTEXT *>(
      ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(CHECK_WORK_ITEM_CONTEXT),
                            RWMON_POOL_TAG_NAME));
  if (!workItemContext) {
    goto FailureEnd;
  }

  status = ObReferenceObjectByPointer(PsGetCurrentProcess(), 0, *PsProcessType, KernelMode);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR_SAFE("ObReferenceObjectByPointer failed (%08x)", status);
    ExFreePoolWithTag(workItemContext, RWMON_POOL_TAG_NAME);
    goto FailureEnd;
  }

  InterlockedIncrement(&g_CheckpNumberOfActiveWorkQueueItems);
  ExInitializeWorkItem(&workItemContext->WorkItem, CheckpWorkItemRoutine,
                       workItemContext);
  workItemContext->Data = data;
  workItemContext->DataSize = DataSize;
  workItemContext->Type = (Contents) ? INTER_PROCESS_WRITE : INTER_PROCESS_MAP;
  workItemContext->WriterProcess = PsGetCurrentProcess();
  workItemContext->TargetProcess = targetProcess;
  workItemContext->RemoteAddress = RemoteAddress;
  ExQueueWorkItem(&workItemContext->WorkItem, DelayedWorkQueue);
  return true;

FailureEnd:;
  if (data) {
    ExFreePoolWithTag(data, RWMON_POOL_TAG_NAME);
  }
  ObDereferenceObject(targetProcess);
  return false;
}

// Check if the write operation is interprocess and from a not white listed
// process
ALLOC_TEXT(PAGED, CheckpIsInterprocessWrite)
_Success_(return == true) EXTERN_C
    static bool CheckpIsInterprocessWrite(_In_ HANDLE ProcessHandle,
                                          _Out_ PEPROCESS *TargetProcess) {
  PAGED_CODE();

  if (ProcessHandle == ZwCurrentProcess()) {
    return false;
  }

  const auto pid = PsGetCurrentProcessId();
  for (auto i = 0; g_CheckpWhiteListedProcessIDs[i]; ++i) {
    if (g_CheckpWhiteListedProcessIDs[i] == pid) {
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
ALLOC_TEXT(PAGED, CheckpCopyDataFromUserSpace)
EXTERN_C static NTSTATUS CheckpCopyDataFromUserSpace(
    _Out_ void *Buffer, _In_ const void *BaseAddress, _In_ ULONG DataSize,
    _In_opt_ PEPROCESS TargetProcess) {
  PAGED_CODE();

  auto status = STATUS_UNSUCCESSFUL;
  if (TargetProcess) {
    // Need to switch to another process memory space to access the data
    KAPC_STATE apcState = {};
    KeStackAttachProcess(TargetProcess, &apcState);
    status = CheckpTryCopyMemory(Buffer, BaseAddress, DataSize);
    KeUnstackDetachProcess(&apcState);
  } else {
    // The current process contains the data
    status = CheckpTryCopyMemory(Buffer, BaseAddress, DataSize);
  }
  return status;
}

// RtlCopyMemory wrapped with SEH
ALLOC_TEXT(PAGED, CheckpTryCopyMemory)
EXTERN_C static NTSTATUS CheckpTryCopyMemory(_Out_ void *Destionation,
                                             _In_ const void *Source,
                                             _In_ SIZE_T Length) {
  PAGED_CODE();

  auto status = STATUS_SUCCESS;
  __try {
    RtlCopyMemory(Destionation, Source, Length);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    status = GetExceptionCode();
  }
  return status;
}

// Calculate SHA1 of the data and write it to a file
ALLOC_TEXT(PAGED, CheckpWorkItemRoutine)
EXTERN_C static void CheckpWorkItemRoutine(_In_ void *Context)
{
  PAGED_CODE();

  auto parameter = reinterpret_cast<CHECK_WORK_ITEM_CONTEXT *>(Context);

  // Calculate SHA1 of the written data
  UCHAR sha1Hash[20] = {};
  if (!CheckpGetSha1(sha1Hash, parameter->Data, parameter->DataSize))
  {
    goto End;
  }
  wchar_t sha1HashW[41] = {};
  for (auto i = 0; i < RTL_NUMBER_OF(sha1Hash); ++i)
  {
    const auto outW = sha1HashW + i * 2;
    RtlStringCchPrintfW(outW, 3, L"%02x", sha1Hash[i]);
  }

  // Save it to a file
  wchar_t outPathW[260];
  auto status =
    RtlStringCchPrintfW(outPathW, RTL_NUMBER_OF(outPathW), L"%s\\%s.bin",
      g_CheckpLogDirecotry, sha1HashW);
  if (!NT_SUCCESS(status))
  {
    LOG_ERROR("RtlStringCchPrintfW failed (%08x)", status);
    goto End;
  }
  status = CheckpWriteFile(outPathW, parameter->Data, parameter->DataSize,
    GENERIC_WRITE, FILE_CREATE);
  if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION)
  {
    LOG_ERROR("WriteFile failed (%08x)", status);
    goto End;
  }

  const auto collision =
    (status == STATUS_OBJECT_NAME_COLLISION) ? "dup with" : "saved as";

  // Log it
  LOG_INFO("Remote %s from %5lu (%-15s) to %5lu (%-15s) at %p (%s %S, %lu bytes)",
    (parameter->Type == INTER_PROCESS_WRITE) ? "write" : "map  ",
    PsGetProcessId(parameter->WriterProcess),
    PsGetProcessImageFileName(parameter->WriterProcess),
    PsGetProcessId(parameter->TargetProcess),
    PsGetProcessImageFileName(parameter->TargetProcess),
    parameter->RemoteAddress, collision, sha1HashW, parameter->DataSize);

End:;
  ExFreePoolWithTag(parameter->Data, RWMON_POOL_TAG_NAME);
  ObDereferenceObject(parameter->WriterProcess);
  ObDereferenceObject(parameter->TargetProcess);
  ExFreePoolWithTag(parameter, RWMON_POOL_TAG_NAME);
  InterlockedDecrement(&g_CheckpNumberOfActiveWorkQueueItems);
}

// Calculate SHA1
ALLOC_TEXT(PAGED, CheckpGetSha1)
_Success_(return == true) EXTERN_C
    static bool CheckpGetSha1(_Out_ UCHAR(&Sha1Hash)[20], _In_ void *Data,
                              _In_ ULONG DataSize) {
  PAGED_CODE();
  bool result = false;

  BCRYPT_HASH_HANDLE hashHandle = nullptr;
  auto status = BCryptCreateHash(g_CheckpSha1AlgorithmHandle, &hashHandle,
                                 nullptr, 0, nullptr, 0, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptCreateHash failed (%08x)", status);
    goto End;
  }

  status = BCryptHashData(hashHandle, static_cast<UCHAR *>(Data), DataSize, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptHashData failed (%08x)", status);
    goto End;
  }

  static_assert(sizeof(Sha1Hash) == 20, "Size check");
  status = BCryptFinishHash(hashHandle, Sha1Hash, sizeof(Sha1Hash), 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptFinishHash failed (%08x)", status);
    goto End;
  }
  result = true;

End:;
  if (hashHandle) {
    BCryptDestroyHash(hashHandle);
  }
  return result;
}

// Write data to a file
ALLOC_TEXT(PAGED, CheckpWriteFile)
EXTERN_C static NTSTATUS CheckpWriteFile(_In_ const wchar_t *OutPathW,
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
