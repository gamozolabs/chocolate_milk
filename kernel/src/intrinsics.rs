//! Implements intrinsics required for MSVC targets
//!
//! Since we build our kernel as a PE as an MSVC target it's required that
//! we implement some of these intrinsics.

global_asm!(r#"
    .global __chkstk
    __chkstk:
        ret
"#);

