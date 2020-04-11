//! Build script for the chocolate milk bootloader and OS

use std::path::Path;
use std::error::Error;
use std::convert::TryInto;
use std::process::Command;

use pe_parser::PeParser;

/// Base address for the Rust bootloader
const BOOTLOADER_BASE: u32 = 0x7e00;

/// Maximum size allowed by PXE
const MAX_BOOTLOADER_SIZE: u64 = 32 * 1024;

/// Create a flattened PE image
/// Returns a tuple (entry point vaddr, base vaddr, image)
fn flatten_pe<P: AsRef<Path>>(filename: P) -> Option<(u32, u32, Vec<u8>)> {
    let pe = std::fs::read(filename).ok()?;
    let pe = PeParser::parse(&pe)?;

    // Compute the bounds of the _loaded_ image
    let mut image_start = None;
    let mut image_end   = None;
    pe.sections(|base, size, _raw| {
        // Convert the size from 32-bits to 64-bits
        let size = size as u64;
        let end  = base.checked_add(size.checked_sub(1)?)?;

        // Set up initial values
        if image_start.is_none() {
            image_start = Some(base);
            image_end   = Some(end);
        }

        // Find the lowest base address
        image_start = image_start.map(|x| core::cmp::min(x, base));
        image_end   = image_end.map(|x| core::cmp::max(x, end));

        Some(())
    })?;

    // Make sure there was at least one section
    let image_start = image_start?;
    let image_end   = image_end?;

    // Compute the flattened image size
    let image_size: usize =
        image_end.checked_sub(image_start)?.checked_add(1)?
        .try_into().ok()?;

    // Allocate a zeroed image
    let mut flattened = std::vec![0u8; image_size];

    // Flatten the image!
    pe.sections(|base, size, raw | {
        // Find the offset for this section in the flattened image
        let flat_off: usize = (base - image_start).try_into().ok()?;
        let size:     usize = size.try_into().ok()?;

        // Compute the number of bytes to initialize
        let to_copy = std::cmp::min(size, raw.len());

        // Copy the initialized bytes from the PE into the flattened image
        flattened[flat_off..flat_off.checked_add(to_copy)?]
            .copy_from_slice(raw);

        Some(())
    })?;

    // Make sure the entry point falls within the image
    if pe.entry_point < image_start || pe.entry_point > image_end {
        return None;
    }

    Some((
            pe.entry_point.try_into().ok()?,
            image_start.try_into().ok()?,
            flattened
    ))
}

/// Check if a command is working and returning the expected results.
fn check_install(command: &str, args: &[&str],
                 expected: &[&str]) -> Option<()> {
    // Invoke the command
    let result = Command::new(command).args(args).output().ok()?;
                
    // Check if the command was successful
    if !result.status.success() { return None; }

    // Convert the stdout bytes to a string
    let stdout = std::str::from_utf8(&result.stdout).ok()?;

    // Make sure `stdout` contains everything we expected
    if expected.iter().all(|x| stdout.contains(x)) {
        Some(())
    } else { 
        None
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Handle clean to remove all artifacts
    if args.len() == 2 && args[1] == "clean" {
        if Path::new("build").is_dir() {
            std::fs::remove_dir_all("build")?;
        }
        if Path::new("pxe").is_dir() {
            std::fs::remove_dir_all("pxe")?;
        }

        return Ok(());
    }

    // Check for nasm
    check_install("nasm", &["-v"], &["NASM version"])
        .ok_or("nasm not present in the path")?;
    
    // Check for rust and needed targets
    check_install("rustup", &["target", "list"],
        &[
            "i586-pc-windows-msvc (installed)",
            "x86_64-pc-windows-msvc (installed)",
        ]).ok_or("rustup not present or i586-pc-windows-msvc or \
                  x86_64-pc-windows-msvc targets not installed")?;

    // Check for lld-link
    check_install("lld-link", &["--version"], &["LLD "])
        .ok_or("lld-link not present in the path")?;

    // Create a build folder, if it does not exist
    std::fs::create_dir_all("build")?;
    std::fs::create_dir_all("build/bootloader")?;

    // Create the boot file name
    let bootfile = Path::new("build").join("chocolate_milk.boot");

    // Build the assembly routines for the bootloader
    if !Command::new("nasm")
            .args(&["-f", "win32",
                &format!("-DPROGRAM_BASE={:#x}", BOOTLOADER_BASE),
                Path::new("bootloader").join("src").join("asm_routines.asm")
                .to_str().unwrap(),
                "-o", Path::new("build").join("bootloader")
                .join("asm_routines.obj").to_str().unwrap()
            ]).status()?.success() {
        return Err("Failed to build bootloader assembly routines".into());
    }

    // Build the bootloader
    let bootloader_build_dir =
        Path::new("build").join("bootloader").canonicalize()?;
    if !Command::new("cargo")
            .current_dir("bootloader")
            .args(&[
                "build", "--release", "--target-dir",
                bootloader_build_dir.to_str().unwrap()
            ]).status()?.success() {
        return Err("Failed to build bootloader".into());
    }

    // Flatten the PE image
    let (entry, base, image) =
        flatten_pe(bootloader_build_dir.join("i586-pc-windows-msvc")
            .join("release").join("bootloader.exe"))
        .ok_or("Failed to flatten bootloader PE image")?;

    // Make sure the PE gets loaded to where we expect
    if base != BOOTLOADER_BASE {
        return
            Err("Base address for bootloader did not match expected".into());
    }

    // Write out the flattened bootloader image
    std::fs::write(Path::new("build").join("chocolate_milk.flat"), image)?;

    // Build the stage0
    let stage0 = Path::new("bootloader").join("src").join("stage0.asm");
    if !Command::new("nasm")
            .args(&["-f", "bin", &format!("-Dentry_point={:#x}", entry),
                  "-o", bootfile.to_str().unwrap(),
                  stage0.to_str().unwrap()])
            .status()?.success() {
        return Err("Failed to assemble stage0".into());
    }

    let bl_size = bootfile.metadata()?.len();
    print!("Current bootloader size is {} of {} bytes [{:8.4} %]\n",
        bl_size, MAX_BOOTLOADER_SIZE,
        bl_size as f64 / MAX_BOOTLOADER_SIZE as f64 * 100.);
    if bl_size > MAX_BOOTLOADER_SIZE {
        return Err("Bootloader size is too large".into());
    }
    
    // Deploy the images to the PXE directory
    std::fs::create_dir_all("pxe")?;
    std::fs::copy(bootfile, Path::new("pxe").join("chocolate_milk.boot"))?;

    Ok(())
}

