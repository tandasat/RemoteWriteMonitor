// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements empty functions for Asm functions to allow us to build
// the code on x86. Those Asm functions are not used on x86.
//
#include "stdafx.h"
#include "../../asm.h"

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

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

EXTERN_C void AsmNtMapViewOfSection_Win81_7(){};

EXTERN_C void AsmNtMapViewOfSection_Win81_7End(){};

EXTERN_C void AsmNtWriteVirtualMemory_Win81(){};

EXTERN_C void AsmNtWriteVirtualMemory_Win81End(){};

EXTERN_C void AsmNtWriteVirtualMemory_Win7(){};

EXTERN_C void AsmNtWriteVirtualMemory_Win7End(){};
