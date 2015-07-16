// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements various utility functions.
//
#include "stdafx.h"
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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Disable the write protection
EXTERN_C void UtilDisableWriteProtect() {
  CR0_REGISTER cr0 = {__readcr0()};
  cr0.Fields.WP = false;
  __writecr0(cr0.Value);
}

// Enable the write protection
EXTERN_C void UtilEnableWriteProtect() {
  CR0_REGISTER cr0 = {__readcr0()};
  cr0.Fields.WP = true;
  __writecr0(cr0.Value);
}

// memmem().
EXTERN_C void *UtilMemMem(_In_ const void *SearchBase, _In_ SIZE_T SearchSize,
                          _In_ const void *Pattern, _In_ SIZE_T PatternSize) {
  if (PatternSize > SearchSize) {
    return nullptr;
  }
  auto searchBase = static_cast<const char *>(SearchBase);
  for (size_t i = 0; i <= SearchSize - PatternSize; i++) {
    if (!memcmp(Pattern, &searchBase[i], PatternSize)) {
      return const_cast<char *>(&searchBase[i]);
    }
  }
  return nullptr;
}

// Does memcpy safely even if Destination is a read only region.
EXTERN_C NTSTATUS UtilForceMemCpy(_In_ void *Destination,
                                  _In_ const void *Source, _In_ SIZE_T Length) {
  auto mdl = IoAllocateMdl(Destination, static_cast<ULONG>(Length), FALSE, FALSE,
                    nullptr);
  if (!mdl) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  MmBuildMdlForNonPagedPool(mdl);

  //
  // Following MmMapLockedPagesSpecifyCache() call causes bug check in case
  // you are using Driver Verifier. The reason is explained as follows:
  //
  // A driver must not try to create more than one system-address-space
  // mapping for an MDL. Additionally, because an MDL that is built by the
  // MmBuildMdlForNonPagedPool routine is already mapped to the system
  // address space, a driver must not try to map this MDL into the system
  // address space again by using the MmMapLockedPagesSpecifyCache routine.
  // -- MSDN
  //
  // This flag modification hacks Driver Verifier's check and prevent leading
  // bug check.
  //
  mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
  mdl->MdlFlags |= MDL_PAGES_LOCKED;

  auto writableDest = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr,
                                   FALSE, NormalPagePriority);
  if (!writableDest) {
    IoFreeMdl(mdl);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  memcpy(writableDest, Source, Length);
  MmUnmapLockedPages(writableDest, mdl);
  IoFreeMdl(mdl);
  return STATUS_SUCCESS;
}

// Invalidates an instruction cache for the specified region.
EXTERN_C void UtilInvalidateInstructionCache(_In_ void *BaseAddress,
                                             _In_ SIZE_T Length) {
  UNREFERENCED_PARAMETER(BaseAddress);
  UNREFERENCED_PARAMETER(Length);
#if _AMD64_
  __faststorefence();
#else
  _mm_sfence();
#endif
}