# Summary

This is a bootloader and kernel written nearly entirely in Rust with no third
party dependencies at all. Everything in this code base is all you need code
wise.

# Building

## Requirements

To build this you need Rust, `nasm`, and `lld-link` (from LLVM's linker). This
bootloader and kernel are built identically regardless of the build system. It
should build just fine on Linux, Windows, OSX, BSD, whatever.

You can get nasm [here](https://nasm.us/) or from `apt install nasm`

You can get LLVM binaries [here](https://llvm.org/builds/) or `apt install lld`

You can get Rust [here](https://rustup.rs/). You must use nightly Rust!

This project requires that you have the `i586-pc-windows-msvc` and
`x86_64-pc-windows-msvc` Rust targets installed.

`rustup target add i586-pc-windows-msvc x86_64-pc-windows-msvc`

Specifically `nasm`, `lld-link`, `rustup`, and `cargo` must be in your PATH. If
one of these are not in your path, you may need to create a symlink to the
specific version (eg: `lld-link-10`)

## Building

To build this simply run `cargo run`

# Usage

This bootloader and kernel require PXE booting. They do not support disks in
any way, shape, or form. Everything is done over the network. To use this
bootloader and kernel you need to set up a valid PXE boot environment. This is
done with a DHCP server and a TFTP server.

The TFTP server must point to the directory containing `chocolate_milk.boot`
and `chocolate_milk.kern`. And the DHCP server should be configured to point
to using `chocolate_milk.boot` as the boot image. This is a BIOS specific
bootloader and will not work with EFI/UEFI.

# Design

## Build System

We use a Rust-based build system found at `src/main.rs`. We built the build
system in Rust such that we don't have to take on any other dependencies for
the build process. This build system has some checks for installed programs
which are required for building, builds and flattens the bootloader, and
assembles the bootloader.

## Bootloader

The bootloader is a simple i586 Rust program emit as a MSVC calling convention
PE. This is flattened by our build system `src/main.rs` into an
in-memory image of the loaded PE. This is then directly appended to the initial
`bootloader/src/stage0.asm` entry stub. Once 32-bit mode has been entered and
selectors have been set up, we branch directly into `bootloader::entry()`!

