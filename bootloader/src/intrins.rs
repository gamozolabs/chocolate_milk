//! Microsoft specific (MSVC convention) intrinsics. We translate the MSVC
//! intrinsics to LLVM intrinsics to get support for 64-bit integer arithmetic
//! in a 32-bit bootloader.

// ---------------------------------------------------------------------------
// Microsoft specific intrinsics
//
// These intrinsics use the stdcall convention however are not decorated
// with an @<bytes> suffix. To override LLVM from appending this suffix we
// have an \x01 escape byte before the name, which prevents LLVM from all
// name mangling.
// ---------------------------------------------------------------------------

/// Perform n % d
#[export_name="\x01__aullrem"]
pub extern "stdcall" fn __aullrem(n: u64, d: u64) -> u64 {
    compiler_builtins::int::udiv::__umoddi3(n, d)
}

/// Perform n / d
#[export_name="\x01__aulldiv"]
pub extern "stdcall" fn __aulldiv(n: u64, d: u64) -> u64 {
    compiler_builtins::int::udiv::__udivdi3(n, d)
}

/// Perform n % d
#[export_name="\x01__allrem"]
pub extern "stdcall" fn __allrem(n: i64, d: i64) -> i64 {
    compiler_builtins::int::sdiv::__moddi3(n, d)
}

/// Perform n / d
#[export_name="\x01__alldiv"]
pub extern "stdcall" fn __alldiv(n: i64, d: i64) -> i64 {
    compiler_builtins::int::sdiv::__divdi3(n, d)
}

global_asm!(r#"
.intel_syntax

    // eax -> Size of the stack allocation needed
    .global __chkstk
    __chkstk:
        // Compute the offset needed to the current stack.
        // We subtract off 4 from the requested stack frame size, because the
        // return address is already present
        sub eax, 4

        // Allocate the room on the stack as requested
        sub esp, eax

        // Jump to the return location
        jmp dword ptr [esp + eax]

.att_syntax
"#);

