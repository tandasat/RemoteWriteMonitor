// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to inline hook related functions.
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

// Holds a necessary context for installing and uninstalling inline hook.
struct InlineHookInfo {
  UCHAR *HookAddress;       // An address to install inline hook
  FARPROC HookHandler;      // A hook handler to be called instead
  SIZE_T OriginalCodeSize;  // A size of saved original code
  UCHAR OriginalCode[32];   // A saved original code
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTSTATUS
InlineInitHookInfo(_In_ UCHAR *HookAddress, _In_ FARPROC HookHandler,
                   _In_ FARPROC AsmHandler, _In_ FARPROC AsmHandlerEnd,
                   _Out_ InlineHookInfo *Info);

EXTERN_C NTSTATUS InlineInstallHook(_In_ const InlineHookInfo &Info);

EXTERN_C NTSTATUS InlineUninstallHook(_In_ const InlineHookInfo &Info);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
