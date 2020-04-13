#![no_std]

use core::convert::TryInto;

const IMAGE_FILE_MACHINE_I386:   u16 = 0x014c;
const IMAGE_FILE_MACHINE_X86_64: u16 = 0x8664;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ:    u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE:   u32 = 0x80000000;

/// A validated PE file that has had some basic information parsed out of it.
/// You can use functions on this structure to extract things like sections.
pub struct PeParser<'a> {
    /// Raw PE file
    bytes: &'a [u8],

    /// Number of sections
    num_sections: usize,

    /// Offset into the raw PE file where the section headers are
    section_off: usize,

    /// Base of the image
    image_base: u64,

    /// Virtual address of the entry point
    pub entry_point: u64,
}

impl<'a> PeParser<'a> {
    /// Validate a PE file is sane, and return out a "parsed" version which
    /// can be used to access different information from the PE
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let bytes: &[u8] = bytes.as_ref();

        // Check for an MZ header
        if bytes.get(0..2) != Some(b"MZ") { return None; }

        // Get the PE offset
        let pe_offset: usize =
            u32::from_le_bytes(bytes.get(0x3c..0x40)?.try_into().ok()?)
            .try_into().ok()?;

        // Check for the PE signature
        if bytes.get(pe_offset..pe_offset.checked_add(4)?) != Some(b"PE\0\0") {
            return None;
        }

        // Make sure the COFF header is within bounds of our input
        if pe_offset.checked_add(0x18)? > bytes.len() {
            return None;
        }

        // Determine the machine type and make sure it's for x86 or x86_64
        let machine = u16::from_le_bytes(
            bytes[pe_offset + 4..pe_offset + 6].try_into().ok()?);
        if machine != IMAGE_FILE_MACHINE_I386 &&
                machine != IMAGE_FILE_MACHINE_X86_64 {
            return None;
        }
        
        // Get the number of sections
        let num_sections: usize = u16::from_le_bytes(
            bytes[pe_offset + 6..pe_offset + 8].try_into().ok()?)
            .try_into().ok()?;

        // Get the size of the optional header
        let opt_header_size: usize = u16::from_le_bytes(
            bytes[pe_offset + 0x14..pe_offset + 0x16].try_into().ok()?)
            .try_into().ok()?;
        
        // Get the base for the program
        let image_base = if machine == IMAGE_FILE_MACHINE_I386 {
            u32::from_le_bytes(
                bytes.get(pe_offset + 0x34..pe_offset + 0x38)?
                .try_into().ok()?) as u64
        } else if machine == IMAGE_FILE_MACHINE_X86_64 {
            u64::from_le_bytes(
                bytes.get(pe_offset + 0x30..pe_offset + 0x38)?
                .try_into().ok()?)
        } else {
            unreachable!();
        };
        
        // Get the entry point for the image
        let entry_point: u64 = u32::from_le_bytes(
            bytes.get(pe_offset + 0x28..pe_offset + 0x2c)?
            .try_into().ok()?) as u64;
        let entry_point = image_base.checked_add(entry_point)?;

        // Compute the size of all headers, including sections and make sure
        // everything is in bounds
        let header_size = pe_offset.checked_add(0x18)?
            .checked_add(opt_header_size)?
            .checked_add(num_sections.checked_mul(0x28)?)?;
        if header_size > bytes.len() {
            return None;
        }

        Some(PeParser {
            bytes,
            image_base,
            num_sections,
            entry_point,
            section_off: pe_offset + 0x18 + opt_header_size,
        })
    }

    /// Invoke a closure with the format
    /// (virtual addr, virtual size, raw initialize bytes,
    ///  read, write, execute) for each section in the PE file
    pub fn sections<F>(&self, mut func: F) -> Option<()>
            where F: FnMut(u64, u32, &[u8], bool, bool, bool) -> Option<()> {
        let bytes = self.bytes;

        for section in 0..self.num_sections {
            let off = self.section_off + section * 0x28;

            // Get the virtual and raw sizes and offsets
            let virt_size = u32::from_le_bytes(
                bytes[off + 0x8..off + 0xc].try_into().ok()?);
            let virt_addr = u32::from_le_bytes(
                bytes[off + 0xc..off + 0x10].try_into().ok()?);
            let raw_size = u32::from_le_bytes(
                bytes[off + 0x10..off + 0x14].try_into().ok()?);
            let raw_off: usize = u32::from_le_bytes(
                bytes[off + 0x14..off + 0x18].try_into().ok()?)
                .try_into().ok()?;

            // Get the section characteristics
            let characteristics = u32::from_le_bytes(
                bytes[off + 0x24..off + 0x28].try_into().ok()?);

            // Truncate the raw size if it exceeds the section size
            let raw_size: usize = core::cmp::min(raw_size, virt_size)
                .try_into().ok()?;

            // Invoke the closure
            func(
                self.image_base.checked_add(virt_addr as u64)?,
                virt_size,
                bytes.get(raw_off..raw_off.checked_add(raw_size)?)?,
                (characteristics & IMAGE_SCN_MEM_READ)    != 0,
                (characteristics & IMAGE_SCN_MEM_WRITE)   != 0,
                (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)?;
        }

        Some(())
    }
}

