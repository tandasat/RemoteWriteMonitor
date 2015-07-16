// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements SSDT hook related functions.
//
#include "stdafx.h"
#include "ssdt.h"
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

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct SERVICE_DESCRIPTOR_TABLE {
  PULONG ServiceTable;
  PULONG CounterTable;
  ULONG_PTR TableSize;
  PUCHAR ArgumentTable;
};
static_assert(sizeof(SERVICE_DESCRIPTOR_TABLE) == sizeof(void *) * 4,
              "Size check");

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C PVOID NTAPI
RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

EXTERN_C static SERVICE_DESCRIPTOR_TABLE *SSDTpFindTable();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static SERVICE_DESCRIPTOR_TABLE *g_SSDTpTable = nullptr;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initialize the SSDT subsystem
ALLOC_TEXT(INIT, SSDTInitialization)
EXTERN_C NTSTATUS SSDTInitialization() {
  PAGED_CODE();

  g_SSDTpTable = SSDTpFindTable();
  if (!g_SSDTpTable) {
    return STATUS_UNSUCCESSFUL;
  }
  return STATUS_SUCCESS;
}

// Returns an address of KeServiceDescriptorTable
ALLOC_TEXT(INIT, SSDTpFindTable)
EXTERN_C static SERVICE_DESCRIPTOR_TABLE *SSDTpFindTable() {
  PAGED_CODE();

  if (!IsX64()) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"KeServiceDescriptorTable");
    return reinterpret_cast<SERVICE_DESCRIPTOR_TABLE *>(
        MmGetSystemRoutineAddress(&name));
  }

  //
  // On x64, we have to manually locate an address of nt!KeServiceDescriptorTable 
  // because it is neither exported and referenced from _ETHREAD.Tcb.ServiceTable.
  // A relatively widely used and stable way to get it is finding an offset to 
  // the table from the image base by searching KeAddSystemServiceTable. For more
  // details, see this thread.
  // https://code.google.com/p/volatility/issues/detail?id=189
  //
  UNICODE_STRING name = RTL_CONSTANT_STRING(L"KeAddSystemServiceTable");
  auto pKeAddSystemServiceTable =
      reinterpret_cast<UCHAR *>(MmGetSystemRoutineAddress(&name));
  if (!pKeAddSystemServiceTable) {
    return nullptr;
  }

  UNICODE_STRING name2 = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
  auto pRtlPcToFileHeader = reinterpret_cast<decltype(&RtlPcToFileHeader)>(
      MmGetSystemRoutineAddress(&name2));
  if (!pRtlPcToFileHeader) {
    return nullptr;
  }

  // Locate an offset to the KeServiceDescriptorTable
  ULONG offset = 0;
  for (auto i = 0; i < 0x40; ++i) {
    auto dwordBytes = *reinterpret_cast<ULONG *>(pKeAddSystemServiceTable + i);
    // 4?83bc??   cmp qword ptr [r?+r?+ ...
    if ((dwordBytes & 0x00fffff0) == 0x00bc8340) {
      // offset <= ... ????????h]
      offset = *reinterpret_cast<ULONG *>(pKeAddSystemServiceTable + i + 4);
      break;
    }
  }
  if (!offset) {
    return nullptr;
  }

  // Get a base address of ntoskrnl.exe
  UCHAR *base = nullptr;
  if (!pRtlPcToFileHeader(pKeAddSystemServiceTable,
                          reinterpret_cast<void **>(&base))) {
    return nullptr;
  }
  return reinterpret_cast<SERVICE_DESCRIPTOR_TABLE *>(base + offset);
}

// Terminates the SSDT subsystem
ALLOC_TEXT(PAGED, SSDTTermination)
EXTERN_C void SSDTTermination() { PAGED_CODE(); }

// Returns an address of a system service API specified by the Index
ALLOC_TEXT(PAGED, SSDTGetProcAdderss)
EXTERN_C FARPROC SSDTGetProcAdderss(_In_ ULONG Index) {
  PAGED_CODE();

  if (IsX64()) {
    return reinterpret_cast<FARPROC>(
        (g_SSDTpTable->ServiceTable[Index] >> 4) +
        reinterpret_cast<ULONG_PTR>(g_SSDTpTable->ServiceTable));
  } else {
    return reinterpret_cast<FARPROC>(g_SSDTpTable->ServiceTable[Index]);
  }
}

// Get an original value of the SSDT and replace it with a new value.
EXTERN_C void SSDTSetProcAdderss(_In_ ULONG Index, _In_ FARPROC HookRoutine) {
  // Need to rise IRQL not to allow the system to change an execution processor
  // during the operation because this code changes a state of processor (CR0).
  KIRQL oldIrql = 0;
  KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

  UtilDisableWriteProtect();
  g_SSDTpTable->ServiceTable[Index] = reinterpret_cast<ULONG>(HookRoutine);
  UtilEnableWriteProtect();
  KeLowerIrql(oldIrql);
}
