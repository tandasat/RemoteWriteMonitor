// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to various utility functions.
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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C void UtilDisableWriteProtect();

EXTERN_C void UtilEnableWriteProtect();

EXTERN_C void *UtilMemMem(_In_ const void *SearchBase, _In_ SIZE_T SearchSize,
                          _In_ const void *Pattern, _In_ SIZE_T PatternSize);

EXTERN_C NTSTATUS UtilForceMemCpy(_In_ void *Destination,
                                  _In_ const void *Source, _In_ SIZE_T Length);

EXTERN_C void UtilInvalidateInstructionCache(_In_ void *BaseAddress,
                                             _In_ SIZE_T Length);

EXTERN_C NTSTATUS UtilSleep(_In_ LONG Millisecond);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
