// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver and initializes other
// components in this module.
//
#include "stdafx.h"
#include "log.h"
#include "asm.h"
#include "inline.h"
#include "check.h"
#include "ssdt.h"
#include "util.h"

namespace stdexp = std::experimental;

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C
NTSTATUS NTAPI
NtMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                   _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                   _In_ SIZE_T CommitSize,
                   _Inout_opt_ PLARGE_INTEGER SectionOffset,
                   _Inout_ PSIZE_T ViewSize,
                   _In_ SECTION_INHERIT InheritDisposition,
                   _In_ ULONG AllocationType, _In_ ULONG Win32Protect);
using NtMapViewOfSectionType = decltype(&NtMapViewOfSection);

EXTERN_C
NTSTATUS NTAPI NtWriteVirtualMemory(_In_ HANDLE ProcessHandle,
                                    _In_ PVOID BaseAddress, _In_ PVOID Buffer,
                                    _In_ ULONG BytesToWrite,
                                    _Out_opt_ PULONG BytesWritten);

using NtWriteVirtualMemoryType = decltype(&NtWriteVirtualMemory);

EXTERN_C DRIVER_INITIALIZE DriverEntry;

EXTERN_C static NTSTATUS RWMonpCreateDirectory(_In_ const wchar_t *PathW);

EXTERN_C static NTSTATUS RWMonpInitVersionDependentValues();

EXTERN_C static DRIVER_UNLOAD RWMonpDriverUnload;

EXTERN_C static NTSTATUS RWMonpSleep(_In_ LONG Millisecond);

EXTERN_C static NTSTATUS RWMonpInstallHooks();

EXTERN_C static NTSTATUS RWMonpUninstallHooks();

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

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static HookInfo g_RWMonpNtMapViewOfSectionInfo = {};
static HookInfo g_RWMonpNtWriteVirtualMemoryInfo = {};

static NtMapViewOfSectionType g_RWMonpNtMapViewOfSectionOriginal = nullptr;
static NtWriteVirtualMemoryType g_RWMonpNtWriteVirtualMemoryOriginal = nullptr;

static ULONG g_RWMonpNtMapViewOfSectionSSDTIndex = 0;
static ULONG g_RWMonpNtWriteVirtualMemorySSDTIndex = 0;

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

  // Init SSDT
  status = SSDTInitialization();
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedSSDTTermination =
      stdexp::make_scope_exit([] { SSDTTermination(); });

  // Init globals
  status = RWMonpInitVersionDependentValues();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Init the Check subsystem
  status = CheckInitialization(RWMONP_OUT_DIRECTORY_PATH);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedCheckTermination =
      stdexp::make_scope_exit([] { CheckTermination(); });

  status = RWMonpInstallHooks();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  scopedCheckTermination.release();
  scopedSSDTTermination.release();
  scopedLogTermination.release();
  LOG_INFO("RemoteWriteMonitor installed");
  return status;
}

ALLOC_TEXT(INIT, RWMonpInitVersionDependentValues)
EXTERN_C static NTSTATUS RWMonpInitVersionDependentValues() {
  PAGED_CODE();

  // Check the OS version and initialize right indexes for SSDT hook.
  RTL_OSVERSIONINFOW osVersion = {sizeof(osVersion)};
  auto status = RtlGetVersion(&osVersion);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("RtlGetVersion failed (%08x)", status);
    return status;
  }

  if (osVersion.dwMajorVersion == 6 && osVersion.dwMinorVersion == 1) {
    // Windows 7
    if (IsX64()) {
      // x64
      g_RWMonpNtMapViewOfSectionSSDTIndex = 0x25;
      g_RWMonpNtMapViewOfSectionOriginal =
          reinterpret_cast<NtMapViewOfSectionType>(
              AsmNtMapViewOfSection_Win81_7);
      status = InlineInitHookInfo(
          reinterpret_cast<UCHAR *>(
              SSDTGetProcAdderss(g_RWMonpNtMapViewOfSectionSSDTIndex)),
          reinterpret_cast<FARPROC>(RWMonpNtMapViewOfSection_Hook),
          reinterpret_cast<FARPROC>(AsmNtMapViewOfSection_Win81_7),
          reinterpret_cast<FARPROC>(AsmNtMapViewOfSection_Win81_7End),
          &g_RWMonpNtMapViewOfSectionInfo);
      if (!NT_SUCCESS(status)) {
        return status;
      }

      g_RWMonpNtWriteVirtualMemorySSDTIndex = 0x37;
      g_RWMonpNtWriteVirtualMemoryOriginal =
          reinterpret_cast<NtWriteVirtualMemoryType>(
              AsmNtWriteVirtualMemory_Win7);
      status = InlineInitHookInfo(
          reinterpret_cast<UCHAR *>(
              SSDTGetProcAdderss(g_RWMonpNtWriteVirtualMemorySSDTIndex)),
          reinterpret_cast<FARPROC>(RWMonpNtWriteVirtualMemory_Hook),
          reinterpret_cast<FARPROC>(AsmNtWriteVirtualMemory_Win7),
          reinterpret_cast<FARPROC>(AsmNtWriteVirtualMemory_Win7End),
          &g_RWMonpNtWriteVirtualMemoryInfo);
      if (!NT_SUCCESS(status)) {
        return status;
      }
    } else {
      // x86
      g_RWMonpNtMapViewOfSectionSSDTIndex = 0xa8;
      g_RWMonpNtMapViewOfSectionOriginal =
          reinterpret_cast<NtMapViewOfSectionType>(
              SSDTGetProcAdderss(g_RWMonpNtMapViewOfSectionSSDTIndex));

      g_RWMonpNtWriteVirtualMemorySSDTIndex = 0x18f;
      g_RWMonpNtWriteVirtualMemoryOriginal =
          reinterpret_cast<NtWriteVirtualMemoryType>(
              SSDTGetProcAdderss(g_RWMonpNtWriteVirtualMemorySSDTIndex));
    }
  } else if (osVersion.dwMajorVersion == 6 && osVersion.dwMinorVersion == 3) {
    // Windows 8.1
    if (IsX64()) {
      // x64
      g_RWMonpNtMapViewOfSectionSSDTIndex = 0x27;
      g_RWMonpNtMapViewOfSectionOriginal =
          reinterpret_cast<NtMapViewOfSectionType>(
              AsmNtMapViewOfSection_Win81_7);
      status = InlineInitHookInfo(
          reinterpret_cast<UCHAR *>(
              SSDTGetProcAdderss(g_RWMonpNtMapViewOfSectionSSDTIndex)),
          reinterpret_cast<FARPROC>(RWMonpNtMapViewOfSection_Hook),
          reinterpret_cast<FARPROC>(AsmNtMapViewOfSection_Win81_7),
          reinterpret_cast<FARPROC>(AsmNtMapViewOfSection_Win81_7End),
          &g_RWMonpNtMapViewOfSectionInfo);
      if (!NT_SUCCESS(status)) {
        return status;
      }

      g_RWMonpNtWriteVirtualMemorySSDTIndex = 0x39;
      g_RWMonpNtWriteVirtualMemoryOriginal =
          reinterpret_cast<NtWriteVirtualMemoryType>(
              AsmNtWriteVirtualMemory_Win81);
      status = InlineInitHookInfo(
          reinterpret_cast<UCHAR *>(
              SSDTGetProcAdderss(g_RWMonpNtWriteVirtualMemorySSDTIndex)),
          reinterpret_cast<FARPROC>(RWMonpNtWriteVirtualMemory_Hook),
          reinterpret_cast<FARPROC>(AsmNtWriteVirtualMemory_Win81),
          reinterpret_cast<FARPROC>(AsmNtWriteVirtualMemory_Win81End),
          &g_RWMonpNtWriteVirtualMemoryInfo);
      if (!NT_SUCCESS(status)) {
        return status;
      }

    } else {
      // x86
      g_RWMonpNtMapViewOfSectionSSDTIndex = 0xf6;
      g_RWMonpNtMapViewOfSectionOriginal =
          reinterpret_cast<NtMapViewOfSectionType>(
              SSDTGetProcAdderss(g_RWMonpNtMapViewOfSectionSSDTIndex));

      g_RWMonpNtWriteVirtualMemorySSDTIndex = 0x3;
      g_RWMonpNtWriteVirtualMemoryOriginal =
          reinterpret_cast<NtWriteVirtualMemoryType>(
              SSDTGetProcAdderss(g_RWMonpNtWriteVirtualMemorySSDTIndex));
    }
  } else {
    LOG_ERROR("Unsupported OS version");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }
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

// Unloading the driver. Close and restore everything.
ALLOC_TEXT(PAGED, RWMonpDriverUnload)
EXTERN_C static void RWMonpDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(DriverObject);

  LOG_DEBUG("Being terminated.");
  // DBG_BREAK();

  RWMonpUninstallHooks();
  RWMonpSleep(1000);
  CheckTermination();
  SSDTTermination();
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

ALLOC_TEXT(INIT, RWMonpInstallHooks)
EXTERN_C static NTSTATUS RWMonpInstallHooks() {
  PAGED_CODE();

  auto status = STATUS_SUCCESS;
  if (IsX64()) {
    status = InlineInstallHook(g_RWMonpNtMapViewOfSectionInfo);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    status = InlineInstallHook(g_RWMonpNtWriteVirtualMemoryInfo);
    if (!NT_SUCCESS(status)) {
      InlineUninstallHook(g_RWMonpNtMapViewOfSectionInfo);
      return status;
    }
  } else {
    SSDTSetProcAdderss(
        g_RWMonpNtMapViewOfSectionSSDTIndex,
        reinterpret_cast<FARPROC>(RWMonpNtMapViewOfSection_Hook));
    SSDTSetProcAdderss(
        g_RWMonpNtWriteVirtualMemorySSDTIndex,
        reinterpret_cast<FARPROC>(RWMonpNtWriteVirtualMemory_Hook));
  }
  return status;
}

ALLOC_TEXT(PAGED, RWMonpUninstallHooks)
EXTERN_C static NTSTATUS RWMonpUninstallHooks() {
  PAGED_CODE();

  auto status = STATUS_SUCCESS;
  if (IsX64()) {
    status = InlineUninstallHook(g_RWMonpNtWriteVirtualMemoryInfo);
    status = InlineUninstallHook(g_RWMonpNtMapViewOfSectionInfo);
  } else {
    SSDTSetProcAdderss(
        g_RWMonpNtMapViewOfSectionSSDTIndex,
        reinterpret_cast<FARPROC>(g_RWMonpNtMapViewOfSectionOriginal));
    SSDTSetProcAdderss(
        g_RWMonpNtWriteVirtualMemorySSDTIndex,
        reinterpret_cast<FARPROC>(g_RWMonpNtWriteVirtualMemoryOriginal));
  }
  return status;
}

//
// Hook Handlers
//

// A hook handler for NtMapViewOfSection
ALLOC_TEXT(PAGED, RWMonpNtMapViewOfSection_Hook)
EXTERN_C static NTSTATUS NTAPI RWMonpNtMapViewOfSection_Hook(
    _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect) {
  PAGED_CODE();

  const auto result = g_RWMonpNtMapViewOfSectionOriginal(
      SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
      SectionOffset, ViewSize, InheritDisposition, AllocationType,
      Win32Protect);
  if (NT_SUCCESS(result)) {
    CheckData(ProcessHandle, *BaseAddress, nullptr,
              static_cast<ULONG>(*ViewSize));
  }
  return result;
}

// A hook handler for NtWriteVirtualMemory
ALLOC_TEXT(PAGED, RWMonpNtWriteVirtualMemory_Hook)
EXTERN_C static NTSTATUS NTAPI
RWMonpNtWriteVirtualMemory_Hook(_In_ HANDLE ProcessHandle,
                                _In_ PVOID BaseAddress, _In_ PVOID Buffer,
                                _In_ ULONG BytesToWrite,
                                _Out_opt_ PULONG BytesWritten) {
  PAGED_CODE();

  const auto result = g_RWMonpNtWriteVirtualMemoryOriginal(
      ProcessHandle, BaseAddress, Buffer, BytesToWrite, BytesWritten);
  if (NT_SUCCESS(result)) {
    CheckData(ProcessHandle, BaseAddress, Buffer, BytesToWrite);
  }
  return result;
}