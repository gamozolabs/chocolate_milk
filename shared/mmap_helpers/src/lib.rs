//! OS-agnostic helpers for mapping files and memory regions

use std::io;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::ops::{Deref, DerefMut};

#[cfg(unix)]    use std::os::unix::io::AsRawFd;
#[cfg(windows)] use std::os::windows::io::AsRawHandle;
#[cfg(windows)] use std::os::windows::fs::OpenOptionsExt;

#[cfg(unix)]
mod unix_specific_apis {
    extern "system" {
	pub fn mmap(
            addr:   *mut u8,
            length: usize,
            prot:   i32,
            flags:  i32,
            fd:     i32,
            offset: usize) -> *mut u8;
	
        pub fn munmap(
            addr:   *mut u8,
            length: usize) -> i32;
    }

    pub const PROT_READ:  i32 = 1;
    pub const PROT_WRITE: i32 = 2;
    pub const PROT_EXEC:  i32 = 4;

    pub const MAP_SHARED:    i32 = 0x01;
    pub const MAP_PRIVATE:   i32 = 0x02;
    pub const MAP_ANONYMOUS: i32 = 0x20;
}
#[cfg(unix)] use crate::unix_specific_apis::*;

#[cfg(windows)]
mod windows_specific_apis {
    extern "system" {
        pub fn CreateFileMappingA(
            hFile:                   usize,
            lpFileMappingAttributes: *mut u8,
            flProtect:               u32,
            dwMaximumSizeHigh:       u32,
            dwMaximumSizeLow:        u32,
            lpName:                  *mut u8) -> usize;

        pub fn MapViewOfFileEx(
            hFileMappingObject:   usize,
            dwDesiredAccess:      u32,
            dwFileOffsetHigh:     u32,
            dwFileOffsetLow:      u32,
            dwNumberOfBytesToMap: usize,
            lpBaseAddress:        *mut u8) -> *mut u8;

        pub fn VirtualAlloc(
            lpAddress:        *mut u8,
            dwSize:           usize,
            flAllocationType: u32,
            flProtect: u32) -> *mut u8;

        pub fn VirtualFree(
            lpAddress:  *mut u8,
            dwSize:     usize,
            dwFreeType: u32) -> bool;

        pub fn CloseHandle(hObject: usize) -> bool;

        pub fn UnmapViewOfFile(lpBaseAddress: *mut u8) -> bool;
    }

    // Define some constants
    pub const MEM_COMMIT:      u32 = 0x1000;
    pub const MEM_RESERVE:     u32 = 0x2000;
    pub const MEM_WRITE_WATCH: u32 = 0x00200000;

    // VirtualFree() flags
    pub const MEM_RELEASE: u32 = 0x8000;

    // Protection constants
    pub const PAGE_NOACCESS:          u32 = 0x01;
    pub const PAGE_READONLY:          u32 = 0x02;
    pub const PAGE_READWRITE:         u32 = 0x04;
    pub const PAGE_WRITECOPY:         u32 = 0x08;
    pub const PAGE_EXECUTE:           u32 = 0x10;
    pub const PAGE_EXECUTE_READ:      u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    // MapViewOfFileEx() permissions
    pub const FILE_MAP_COPY:    u32 = 0x01;
    pub const FILE_MAP_WRITE:   u32 = 0x02;
    pub const FILE_MAP_READ:    u32 = 0x04;
    pub const FILE_MAP_EXECUTE: u32 = 0x20;
}
#[cfg(windows)] use crate::windows_specific_apis::*;

/// Map memory into the current process
/// 
/// Attempts to map memory at `address` (if null a random address is chosen
/// by the OS) for `size` bytes.
/// 
/// The permissions of this region are specified based on `read`, `write`,
/// `execute`, and `cow` parameters.
/// 
/// If `file` is not `None` then the mapping will be backed by a file. This
/// may be a UNIX `fd` or a Windows `HANDLE`.
/// 
/// Note that the address returned by this function may be different than the
/// requested `address`.
#[cfg(unix)]
fn map_memory_int(address: *mut u8, size: usize, file: Option<usize>,
        read: bool, write: bool, execute: bool, cow: bool)
            -> Result<*mut u8, &'static str> {
    // Convert permission bools to bitmap
    let mut perms = 0;
    if read    { perms |= PROT_READ;  }
    if write   { perms |= PROT_WRITE; }
    if execute { perms |= PROT_EXEC;  }

    // Determine if this is a shared or private mapping based on `cow`
    let mut flags = if cow {
        MAP_PRIVATE
    } else {
        MAP_SHARED
    };
    
    // Determine if this allocation is not backed by a file
    if file.is_none() {
        flags |= MAP_ANONYMOUS;
    }

    // Convert the file to an i32 if one is supplied, otherwise the fd
    // will be -1
    let fd = file.map(|x| x as i32).unwrap_or(-1);

    unsafe {
        // Perform actual mmap()
        let ret = mmap(address, size, perms, flags, fd, 0);

        // Validate mmap() succeeded
        if (ret as usize) == !0 {
            return Err("Call to mmap() failed");
        }

        // Cast to our return type
        let ret = ret as *mut u8;

        // Now check if the mmap() got the correct address but only if we
        // requested a specific base address
        if !address.is_null() && ret != address {
            // We got a result back but not at the address requested, unmap
            // it and return an error
            // This munmap() shouldn't fail so we assert success on it rather
            // than using `Result`
            assert!(munmap(ret, size) == 0, "Failed to munmap()");
            
            return Err("mmap() returned non-requested address");
        }

        // We did it!
        Ok(ret)
    }
}

/// Map memory into the current process
/// 
/// Attempts to map memory at `address` (if null a random address is chosen
/// by the OS) for `size` bytes.
/// 
/// The permissions of this region are specified based on `read`, `write`,
/// `execute`, and `cow` parameters.
/// 
/// If `file` is not `None` then the mapping will be backed by a file. This
/// may be a UNIX `fd` or a Windows `HANDLE`.
/// 
/// Note that the address returned by this function may be different than the
/// requested `address`.
#[cfg(windows)]
fn map_memory_int(address: *mut u8, size: usize, file: Option<usize>,
        read: bool, write: bool, execute: bool, cow: bool)
            -> Result<*mut u8, &'static str> {
    // Convert perm booleans to the correct constants
    let perms = if !read && !write && !execute {
        PAGE_NOACCESS
    } else if read && !write && !execute {
        PAGE_READONLY
    } else if read && write && !execute && !cow {
        PAGE_READWRITE
    } else if read && write && !execute && cow {
        PAGE_WRITECOPY
    } else if !read && !write && execute {
        PAGE_EXECUTE
    } else if read && !write && execute {
        PAGE_EXECUTE_READ
    } else if read && write && execute && !cow {
        PAGE_EXECUTE_READWRITE
    } else if read && write && execute && cow {
        PAGE_EXECUTE_WRITECOPY
    } else {
        panic!("Unsupported permission combination");
    };

    let fileperms = if !read && !write && !execute {
        panic!("Cannot map file with no permissions");
    } else if read && !write && !execute {
        FILE_MAP_READ
    } else if read && write && !execute && !cow {
        FILE_MAP_READ | FILE_MAP_WRITE
    } else if read && write && !execute && cow {
        // RW implied by COPY
        FILE_MAP_COPY
    } else if !read && !write && execute {
        panic!("Cannot map file execute-only");
    } else if read && !write && execute {
        FILE_MAP_READ | FILE_MAP_EXECUTE
    } else if read && write && execute && !cow {
        FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE
    } else if read && write && execute && cow {
        // RW implied by COPY
        FILE_MAP_EXECUTE | FILE_MAP_COPY
    } else {
        panic!("Unsupported file permission combination");
    };

    unsafe {
        if let Some(file) = file {
            // Create file mapping object
            let fmap = CreateFileMappingA(file, std::ptr::null_mut(), perms,
                (size >> 32) as u32, size as u32, std::ptr::null_mut());
            if fmap == 0 {
                return Err("CreateFileMappingA() failed");
            }

            // Map file
            let res = MapViewOfFileEx(fmap, fileperms, 0, 0, size, address);

            // We no longer need file mapping object
            assert!(CloseHandle(fmap), "Failed to close fmap");

            // Check for failure
            if res.is_null() {
                return Err("MapViewOfFileEx() failed");
            }

            // Check that we got the requested address if one was requested
            if !address.is_null() && res != address {
                assert!(UnmapViewOfFile(res), "UnmapViewOfFile() failed");
                return Err("MapViewOfFileEx() returned unexpected address");
            }

            Ok(res)
        } else {
            // Anonymous mapping, directly VirtualAlloc()
            let res = VirtualAlloc(address, size,
                MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, perms);

            // Check for failure
            if res.is_null() {
                return Err("VirtualAlloc() failed");
            }

            // Check that we got the requested address if one was requested
            if !address.is_null() && res != address {
                assert!(VirtualFree(res, 0, MEM_RELEASE),
                    "VirtualFree() error");
                return Err("VirtualAlloc() returned unexpected address");
            }

            Ok(res)
        }
    }
}

pub struct Mapping {
    /// Read permissions
    read: bool,

    /// Write permissions
    write: bool,

    /// Path to the file which is mapped. `None` if this is an anonymous
    /// mapping
    _path: Option<PathBuf>,

    /// Pointer to mapped region
    base: usize,

    /// Size (in bytes) of mapped region
    size: usize,
}

impl Mapping {
    /// Saves all the contents of this memory region to `path` and then returns
    /// a tuple with (read, write, base, size)
    pub fn save<P: AsRef<Path>>(&self, path: P)
            -> io::Result<(bool, bool, usize, usize)> {
        // Construct the return tuple
        let ret = (self.read, self.write, self.base, self.size);

        // Write out the memory contents
        std::fs::write(path, &self[..])?;

        Ok(ret)
    }

    /// Creates an anonymous mapping at `address` for `size` bytes with
    /// `read`, `write`, and `execute` permissions
    pub fn anonymous_addr(address: *mut u8, size: usize, read: bool,
            write: bool, execute: bool) -> Result<Self, &'static str> {
        // Create mapping
        let res = map_memory_int(address, size, None,
            read, write, execute, false)?;

        // Return result
        Ok(Self {
            base:  res as usize,
            size:  size,
            _path: None,
            read,  write,
        })
    }

    /// Creates an anonymous mapping at an OS-decided address for `size` bytes
    /// with `read`, `write`, and `execute` permissions
    pub fn anonymous(size: usize, read: bool, write: bool,
            execute: bool) -> Result<Self, &'static str> {
        Self::anonymous_addr(std::ptr::null_mut(), size, read, write, execute)
    }

    /// Creates a mapping of a file `filename`. The file is mapped at `address`
    /// for `size` bytes and if `address` is null then an OS-decided address
    /// is used.
    ///
    /// If `create` is specified the file will be created if it does not exist
    /// If `truncate` is specified the file will be truncated and then resized
    /// to `size` bytes
    /// 
    /// `read`, `write`, `execute`, and `cow` specify the permissions of the
    /// mapped region in memory.
    pub fn file<P: AsRef<Path>>(filename: P, address: *mut u8, size: usize,
            create: bool, truncate: bool,
            read: bool, write: bool, execute: bool, cow: bool)
                -> Result<Self, &'static str> {
        let file;

        #[cfg(unix)] {
            // Open the file with specified attributes
            file = OpenOptions::new().read(read).write(write).create(create)
                .truncate(truncate).open(&filename)
                .map_err(|_| "Failed to open UNIX file")?;
        }

        #[cfg(windows)] {
            // Sadly on Windows execute is a separate bit. So we must manually
            // set the `access_mode` when we use `OpenOptions`
            const GENERIC_READ:    u32 = 0x80000000;
            const GENERIC_WRITE:   u32 = 0x40000000;
            const GENERIC_EXECUTE: u32 = 0x20000000;

            {
                // Rust doesn't seem to respect `access_mode` and
                // `create` or `truncate` options in the same call. We create
                // the file here first, then open it later.
                let _ = OpenOptions::new().read(read).write(write)
                    .create(create).truncate(truncate).open(&filename);
            }

            // Compute attributes
            let mut access = 0;
            if read    { access |= GENERIC_READ;    }
            if write   { access |= GENERIC_WRITE;   }
            if execute { access |= GENERIC_EXECUTE; }

            // Open the file with specified attributes
            file = OpenOptions::new().access_mode(access).open(&filename)
                .map_err(|_| "Failed to open Windows file open")?;
        }

        if truncate {
            // Resize the file if we just created or truncated it
            file.set_len(size as u64).map_err(|_| "Failed to resize file")?;
        }

        // Create mappings based on OS
        let res;

        #[cfg(unix)] {
            res = map_memory_int(
                address, size, Some(file.as_raw_fd() as usize),
                read, write, execute, cow)?;
        }

        #[cfg(windows)] {
            res = map_memory_int(
                address, size, Some(file.as_raw_handle() as usize),
                read, write, execute, cow)?;
        }

        // Return result
        Ok(Self {
            base:  res as usize,
            size:  size,
            _path: Some(filename.as_ref().into()),
            read,  write,
        })
    }
}

impl Deref for Mapping {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe {
            assert!(self.read, "Cannot read from non-readable mapping");
            std::slice::from_raw_parts(self.base as *const u8, self.size)
        }
    }
}

impl DerefMut for Mapping {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            assert!(self.write, "Cannot write to non-writable mapping");
            std::slice::from_raw_parts_mut(self.base as *mut u8, self.size)
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // All we have to do here is unmap the mapping. The file will be dropped
        // by Rust for us

        #[cfg(unix)]
        unsafe {
            // Unmap the mapping
            assert!(munmap(self.base as *mut u8, self.size) == 0,
                "Failed to munmap()");
        }

        #[cfg(windows)]
        unsafe {
            if self._path.is_some() {
                // Free file mapping
                assert!(UnmapViewOfFile(self.base as *mut u8),
                    "UnmapViewOfFile() failed");
            } else {
                // Free anonymous mapping
                assert!(VirtualFree(self.base as *mut u8, 0, MEM_RELEASE),
                    "VirtualFree() error");
            }
        }
    }
}

#[test]
fn test_anon_mapping() {
    Mapping::anonymous(1024, true, false, false).expect("Failed to map");
}

#[test]
fn test_rwx_anon_mapping() {
    Mapping::anonymous(1024, true, true, true).expect("Failed to map");
}

#[test]
fn test_existing_file_mapping() {
    let mut dir = std::env::temp_dir();
    dir.push("mmap_helpers_test_existing_file_mapping");
    let _ = std::fs::remove_file(&dir);

    std::fs::write(&dir, "TESTEXISTING").unwrap();

    // Open existing file and validate it has the contest we expect
    let mapping = Mapping::file(&dir, std::ptr::null_mut(), 12,
        false, false, true, false, false, false).expect("Failed to map");
    assert!(&*mapping == b"TESTEXISTING");
}

#[test]
fn test_create_file_mapping() {
    let mut dir = std::env::temp_dir();
    dir.push("mmap_helpers_test_create_file_mapping");
    let _ = std::fs::remove_file(&dir);

    {
        // Create a new file (or truncate existing) as RW and write in
        // "TESTCONTENTS" to it
        let mut mapping = Mapping::file(&dir, std::ptr::null_mut(), 12,
            true, true, true, true, false, false).expect("Failed to map");
        mapping[..12].copy_from_slice(b"TESTCONTENTS");
    }

    // Make sure the write worked
    assert!(&std::fs::read(&dir).unwrap() == b"TESTCONTENTS");
}

#[test]
fn test_rmw_file_mapping() {
    let mut dir = std::env::temp_dir();
    dir.push("mmap_helpers_test_rmw_file_mapping");
    let _ = std::fs::remove_file(&dir);

    std::fs::write(&dir, "TESTEXISTING").unwrap();

    {
        // Open existing file and validate it has the contest we expect
        let mut mapping = Mapping::file(&dir, std::ptr::null_mut(), 12,
            false, false, true, true, false, false).expect("Failed to map");
        assert!(&*mapping == b"TESTEXISTING");

        // Update contents
        mapping[..12].copy_from_slice(b"UPDTCONTENTS");
    }

    // Make sure the write worked
    assert!(&std::fs::read(&dir).unwrap() == b"UPDTCONTENTS");
}

#[test]
fn test_cow_file_mapping() {
    let mut dir = std::env::temp_dir();
    dir.push("mmap_helpers_test_cow_file_mapping");
    let _ = std::fs::remove_file(&dir);

    std::fs::write(&dir, "TESTEXISTING").unwrap();

    {
        // Open existing file and validate it has the contest we expect
        let mut mapping = Mapping::file(&dir, std::ptr::null_mut(), 12,
            false, false, true, true, false, true).expect("Failed to map");
        assert!(&*mapping == b"TESTEXISTING");

        // Update contents
        mapping[..12].copy_from_slice(b"UPDTCONTENTS");
    }

    // Make sure the writes were discarded as we mapped as CoW
    assert!(&std::fs::read(&dir).unwrap() == b"TESTEXISTING");
}

#[test]
fn test_cow_file_mapping_rwx() {
    let mut dir = std::env::temp_dir();
    dir.push("mmap_helpers_test_cow_file_mapping_rwx");
    let _ = std::fs::remove_file(&dir);

    std::fs::write(&dir, "TESTEXISTING").unwrap();

    {
        // Open existing file and validate it has the contest we expect
        let mut mapping = Mapping::file(&dir, std::ptr::null_mut(), 12,
            false, false, true, true, true, true).expect("Failed to map");
        assert!(&*mapping == b"TESTEXISTING");

        // Update contents
        mapping[..12].copy_from_slice(b"UPDTCONTENTS");
    }

    // Make sure the writes were discarded as we mapped as CoW
    assert!(&std::fs::read(&dir).unwrap() == b"TESTEXISTING");
}
