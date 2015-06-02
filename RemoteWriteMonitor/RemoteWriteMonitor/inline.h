// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
//
//
#pragma once

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

// Acceptable the minimum function epilogue size in bytes for inline hooking.
// It limits the length to 32 bytes due to a size of a backup area allocated by
// a macro NOP_32.
static const ULONG DISPGP_MAXIMUM_EPILOGUE_LENGTH = 32;

// Holds a necessary context for installing and uninstalling inline hook.
struct HookInfo {
  UCHAR *HookAddress;       // An address to install inline hook
  FARPROC HookHandler;      // A hook handler to be called instead
  SIZE_T OriginalCodeSize;  // A size of saved original code
  UCHAR OriginalCode[DISPGP_MAXIMUM_EPILOGUE_LENGTH];  // A saved original code
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTSTATUS
InlineInitHookInfo(_In_ UCHAR *HookAddress, _In_ FARPROC HookHandler,
                   _In_ FARPROC AsmHandler, _In_ FARPROC AsmHandlerEnd,
                   _Out_ HookInfo *Info);

EXTERN_C NTSTATUS InlineInstallHook(_In_ const HookInfo &Info);

EXTERN_C NTSTATUS InlineUninstallHook(_In_ const HookInfo &Info);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
