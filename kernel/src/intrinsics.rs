global_asm!(r#"
    .global __chkstk
    __chkstk:
        ret
"#);

