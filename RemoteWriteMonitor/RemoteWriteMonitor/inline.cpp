// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver and initializes other
// components in this module.
//
#include "stdafx.h"
#include "inline.h"
#include "log.h"
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

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// A structure reflects inline hook code.
#include <pshpack1.h>
struct TrampolineCode {
  UCHAR jmp[6];
  FARPROC FunctionAddress;
};
static const auto DISPGP_MININUM_EPILOGUE_LENGTH = sizeof(TrampolineCode);
static_assert(sizeof(TrampolineCode) == DISPGP_MININUM_EPILOGUE_LENGTH,
              "Size check");
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C
NTSTATUS static InlinepFixupAsmCode(_In_ UCHAR *OriginalRoutine,
                                    _In_ FARPROC AsmHandler,
                                    _In_ FARPROC AsmHandlerEnd);

EXTERN_C static TrampolineCode InlinepMakeTrampolineCode(
    _In_ UCHAR *HookAddress, _In_ FARPROC HookHandler);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Fill out HookInfo in order to hook the begging of the function. This is not
// designed to execute original code like what DispgpSetEpilogueHookInfo() does.
ALLOC_TEXT(INIT, InlineInitHookInfo)
EXTERN_C NTSTATUS
InlineInitHookInfo(_In_ UCHAR *HookAddress, _In_ FARPROC HookHandler,
                   _In_ FARPROC AsmHandler, _In_ FARPROC AsmHandlerEnd,
                   _Out_ HookInfo *Info) {
  PAGED_CODE();

  NT_ASSERT(HookHandler);
  NT_ASSERT(AsmHandler);
  NT_ASSERT(AsmHandlerEnd);
  NT_ASSERT(Info);

  if (!HookAddress) {
    return STATUS_INVALID_PARAMETER;
  }

  Info->HookHandler = HookHandler;
  Info->HookAddress = HookAddress;
  Info->OriginalCodeSize = DISPGP_MININUM_EPILOGUE_LENGTH;
  memcpy(Info->OriginalCode, Info->HookAddress, Info->OriginalCodeSize);

  auto status = InlinepFixupAsmCode(HookAddress, AsmHandler, AsmHandlerEnd);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  LOG_DEBUG("HookHandler= %p, HookAddress= %p, OriginalCodeSize= %d",
            Info->HookHandler, Info->HookAddress, Info->OriginalCodeSize);

  return status;
}

// Build and return trampoline code.
ALLOC_TEXT(PAGED, InlinepMakeTrampolineCode)
EXTERN_C static TrampolineCode InlinepMakeTrampolineCode(
    _In_ UCHAR *HookAddress, _In_ FARPROC HookHandler) {
  PAGED_CODE();
  //          jmp qword ptr [nextline]
  // nextline:
  //          dq HookHandler
  UNREFERENCED_PARAMETER(HookAddress);
  return {
      {
          0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
      },
      HookHandler,
  };
}

// Replaces placeholder (0xffffffffffffffff) in AsmHandler with a given
// ReturnAddress. AsmHandler does not has to be writable. Race condition between
// multiple processors should be taken care of by a programmer it exists; this
// function does not care about it.
ALLOC_TEXT(PAGED, InlinepFixupAsmCode)
EXTERN_C
NTSTATUS static InlinepFixupAsmCode(_In_ UCHAR *OriginalRoutine,
                                    _In_ FARPROC AsmHandler,
                                    _In_ FARPROC AsmHandlerEnd) {
  PAGED_CODE();
  ASSERT(AsmHandlerEnd > AsmHandler);
  SIZE_T asmHandlerSize = reinterpret_cast<ULONG_PTR>(AsmHandlerEnd) -
                          reinterpret_cast<ULONG_PTR>(AsmHandler);

  ULONG64 pattern = 0xffffffffffffffff;
  auto addressOfMarker = UtilMemMem(reinterpret_cast<void *>(AsmHandler),
                                    asmHandlerSize, &pattern, sizeof(pattern));
  ASSERT(addressOfMarker);
  auto destinationAddress =
      reinterpret_cast<ULONG64>(OriginalRoutine + asmHandlerSize - 15);
  return UtilForceMemCpy(addressOfMarker, &destinationAddress,
                         sizeof(destinationAddress));
}

// Install a inline hook (modify code) using HookInfo.
ALLOC_TEXT(PAGED, InlineInstallHook)
EXTERN_C NTSTATUS InlineInstallHook(_In_ const HookInfo &Info) {
  PAGED_CODE();
  LOG_DEBUG("%p => %p", Info.HookAddress, Info.HookHandler);
  auto newCode = InlinepMakeTrampolineCode(Info.HookAddress, Info.HookHandler);
  auto status = UtilForceMemCpy(Info.HookAddress, newCode.jmp, sizeof(newCode));
  UtilInvalidateInstructionCache(Info.HookAddress, sizeof(newCode));
  return status;
}

ALLOC_TEXT(PAGED, InlineUninstallHook)
EXTERN_C NTSTATUS InlineUninstallHook(_In_ const HookInfo &Info) {
  PAGED_CODE();
  auto status = UtilForceMemCpy(Info.HookAddress, Info.OriginalCode,
                                Info.OriginalCodeSize);
  UtilInvalidateInstructionCache(Info.HookAddress, Info.OriginalCodeSize);
  return status;
}
