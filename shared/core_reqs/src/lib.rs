//! Requirements for Rust libcore. These are just basic libc `mem*()` routines
//! as well as some intrinsics to get access to 64-bit integers in 32-bit land

#![no_std]

use core::arch::{asm, global_asm};

/// libc `memcpy` implementation in Rust
///
/// This implementation of `memcpy` is overlap safe, making it technically
/// `memmove`.
///
/// # Parameters
///
/// * `dest` - Pointer to memory to copy to
/// * `src`  - Pointer to memory to copy from
/// * `n`    - Number of bytes to copy
///
#[no_mangle]
pub unsafe extern fn memcpy(dest: *mut u8, src: *const u8, n: usize)
        -> *mut u8 {
    memmove(dest, src, n)
}

/// libc `memmove` implementation in Rust
///
/// # Parameters
///
/// * `dest` - Pointer to memory to copy to
/// * `src`  - Pointer to memory to copy from
/// * `n`    - Number of bytes to copy
///
#[no_mangle]
pub unsafe extern fn memmove(dest: *mut u8, src: *const u8, n: usize)
        -> *mut u8 {
    if src < dest as *const u8 {
        // copy backwards
        let mut ii = n;
        while ii != 0 {
            ii -= 1;
            *dest.offset(ii as isize) = *src.offset(ii as isize);
        }
    } else {
        // copy forwards
        let mut ii = 0;
        while ii < n {
            *dest.offset(ii as isize) = *src.offset(ii as isize);
            ii += 1;
        }
    }

    dest
}

/// libc `memset` implementation in Rust
///
/// # Parameters
///
/// * `s` - Pointer to memory to set
/// * `c` - Character to set `n` bytes in `s` to
/// * `n` - Number of bytes to set
///
#[no_mangle]
#[cfg(target_arch = "x86")]
pub unsafe extern fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    if n == 0 { return s; }

    asm!(
        "rep stosb",
        inout("edi") s => _,
        inout("ecx") n => _,
        inout("eax") c => _,
    );

    s
}

/// libc `memset` implementation in Rust
///
/// # Parameters
///
/// * `s` - Pointer to memory to set
/// * `c` - Character to set `n` bytes in `s` to
/// * `n` - Number of bytes to set
///
#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub unsafe extern fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    if n == 0 { return s; }

    asm!(
        "rep stosb",
        inout("rdi") s => _,
        inout("rcx") n => _,
        inout("rax") c => _,
    );

    s
}

/// libc `memcmp` implementation in Rust
///
/// # Parameters
///
/// * `s1` - Pointer to memory to compare with s2
/// * `s2` - Pointer to memory to compare with s1
/// * `n`  - Number of bytes to set
#[no_mangle]
pub unsafe extern fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut ii = 0;
    while ii < n {
        let a = *s1.offset(ii as isize);
        let b = *s2.offset(ii as isize);
        if a != b {
            return a as i32 - b as i32
        }
        ii += 1;
    }
    
    0
}

#[no_mangle]
pub unsafe fn strlen(start: *const u8) -> usize
{
    let mut pos = start;

    while *pos != 0 {
        pos = pos.offset(1);
    }

    pos.offset_from(start) as _
}

// Making a fake __CxxFrameHandler3 in Rust causes a panic, this is hacky
// workaround where we declare it as a function that will just crash if it.
// We should never hit this so it doesn't matter.
global_asm!(r#"
    .global __CxxFrameHandler3
    __CxxFrameHandler3:
        ud2
"#);

/// Whether or not floats are used. This is used by the MSVC calling convention
/// and it just has to exist.
#[export_name="_fltused"]
pub static FLTUSED: usize = 0;

