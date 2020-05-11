use alloc::sync::Arc;
use alloc::string::String;
use alloc::collections::BTreeMap;
use crate::vtx::Register;
use crate::fuzz_session::Worker;
use page_table::VirtAddr;

/// Windows enlightenment
#[derive(Default)]
pub struct Enlightenment {
    /// Address of the kernel module list (flink, blink)
    kernel_modlist_addr: Option<(VirtAddr, VirtAddr)>,
}

impl Enlightenment {
    /// Get a 64-bit Windows module list
    fn get_module_list_win64(&mut self, worker: &mut Worker, 
                             mut mod_flink: VirtAddr, mod_blink: VirtAddr)
            -> Option<BTreeMap<u64, (u64, Arc<String>)>> {
        // Create a new module list
        let mut module_list = BTreeMap::new();

        // Traverse the linked list
        while mod_flink.0 != 0 {
            let mut get_mod = || {
                let base =
                    worker.read_virt::<u64>(VirtAddr(mod_flink.0 + 0x30))?;
                let size =
                    worker.read_virt::<u32>(VirtAddr(mod_flink.0 + 0x40))?;
                if size <= 0 {
                    return None;
                }

                // Get the length of the module name unicode string
                let name_len =
                    worker.read_virt::<u16>(VirtAddr(mod_flink.0 + 0x58))?;
                let name_ptr =
                    worker.read_virt::<u64>(VirtAddr(mod_flink.0 + 0x60))?;
                if name_ptr == 0 || name_len <= 0 || (name_len % 2) != 0 {
                    return None;
                }

                let mut name = vec![0u16; name_len as usize / 2];
                for (ii, wc) in name.iter_mut().enumerate() {
                    *wc = worker.read_virt::<u16>(VirtAddr(
                        name_ptr.checked_add((ii as u64).checked_mul(2)?)?))?;
                }

                // Convert the module name into a UTF-8 Rust string
                let name_utf8 = Arc::new(String::from_utf16(&name).ok()?);

                // Save the module information into the module list
                module_list.insert(base,
                    (base.checked_add(size as u64 - 1)?, name_utf8));
                Some(())
            };

            let _ = get_mod();

            // Go to the next link in the table
            if mod_flink == mod_blink { break; }
            mod_flink.0 = worker.read_virt::<u64>(VirtAddr(mod_flink.0))?;
        }

        // Establish the new module list
        Some(module_list)
    }
    
    /// Find the flink address of the kernel module list
    fn find_module_list_win64_kernel(&mut self, worker: &mut Worker)
            -> Option<(VirtAddr, VirtAddr)> {
        // Ignore non-kernel states
        if worker.cpl() != 0 { return None; }

        // Get the LStar
        let lstar = worker.reg(Register::LStar);

        // Get the current CR3
        let cr3 = worker.reg(Register::Cr3);

        // Scan a bit around LStar
        for offset in (0..16 * 1024 * 1024).step_by(16) {
            let list_addr = VirtAddr(lstar.checked_add(offset)?);

            // Read what might be a pointer at this location
            if let Some(flink) = worker.read_virt_cr3::<u64>(list_addr, cr3) {
                // _KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Blink
                let blink = worker.read_virt_cr3::<u64>(
                    VirtAddr(flink.wrapping_add(0x08)), cr3);

                // Make sure the blink for the first entry of the list refers
                // to the list start. If it does not, this is probably not
                // a kernel module list.
                if blink != Some(list_addr.0) { continue; }
                
                // _KLDR_DATA_TABLE_ENTRY.BaseDllName.Length
                let size = worker.read_virt_cr3::<u16>(
                    VirtAddr(flink.wrapping_add(0x58)), cr3);

                // _KLDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
                let nameptr = worker.read_virt_cr3::<u64>(
                    VirtAddr(flink.wrapping_add(0x60)), cr3);

                // Make sure the length is 0x18 and all reads succeeded
                if let (Some(0x18), Some(nameptr)) = (size, nameptr) {
                    // Make room to read the name
                    let mut buf = [0u8; 0x18];

                    // Read the name
                    if worker.read_virt_cr3_into(
                            VirtAddr(nameptr), &mut buf, cr3).is_some() {
                        // Check if the module name is "ntoskrnl.exe"
                        if &buf == b"n\0t\0o\0s\0k\0r\0n\0l\0.\0e\0x\0e\0" {
                            return Some((VirtAddr(flink), VirtAddr(blink?)));
                        }
                    }
                }
            }
        }

        // Couldn't find it
        None
    }
}

impl crate::fuzz_session::Enlightenment for Enlightenment {
    fn get_module_list(&mut self, worker: &mut Worker)
            -> Option<BTreeMap<u64, (u64, Arc<String>)>> {
        if worker.cpl() == 0 {
            if self.kernel_modlist_addr.is_none() {
                self.kernel_modlist_addr =
                    Some(self.find_module_list_win64_kernel(worker)?);
            }

            if let Some((flink, blink)) = self.kernel_modlist_addr {
                let tmp = self.get_module_list_win64(worker, flink, blink)?;
                Some(tmp)
            } else {
                None
            }
        } else {
            // Get the base of the TEB
            let gs_base = worker.reg(Register::GsBase);

            // Get the address of the `_PEB`
            let peb = worker.read_virt::<u64>(VirtAddr(gs_base + 0x60))?;

            // Get the address of the `_PEB_LDR_DATA`
            let peb_ldr_data = worker.read_virt::<u64>(VirtAddr(peb + 0x18))?;

            // Get the in load order module list links
            let mod_flink =
                worker.read_virt::<u64>(VirtAddr(peb_ldr_data + 0x10))?;
            let mod_blink =
                worker.read_virt::<u64>(VirtAddr(peb_ldr_data + 0x18))?;

            self.get_module_list_win64(worker, VirtAddr(mod_flink),
                VirtAddr(mod_blink))
        }
    }
}

