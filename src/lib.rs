use std::{
    ffi::{CStr, c_char, c_int, c_void},
    num::Wrapping,
};

use libsqlite3_sys::{
    sqlite3_file, sqlite3_int64, sqlite3_io_methods, sqlite3_load_extension, sqlite3_vfs,
    sqlite3_vfs_find,
};

#[repr(C)]
struct MaidenhairVFS {
    backing_vfs: *mut sqlite3_vfs,
}

type ReadPtr = unsafe extern "C" fn(*mut sqlite3_file, *mut c_void, c_int, sqlite3_int64) -> c_int;
type WritePtr =
    unsafe extern "C" fn(*mut sqlite3_file, *const c_void, c_int, sqlite3_int64) -> c_int;

#[repr(C)]
struct BackingPtrs {
    //pointers to backing funcs
    read_ptr: ReadPtr,
    write_ptr: WritePtr,
}

#[repr(C)]
struct MaidenhairFile {
    //has to be at the base for pointer offsets to match
    file: sqlite3_file,
    pointers: BackingPtrs,
}

// TODO build safe buffer abstraction around the c buffer
// struct Buffer {
//     size: usize,
//     ptr: *mut c_void,
// }

// impl Buffer {
//     pub fn new(buffer: *mut c_void, size: c_int) -> Result<Self, ()> {
//         if size < 0 {
//             return Err(());
//         }
//         if buffer.is_null() {
//             return Err(());
//         }
//         Ok(Self {
//             #[allow(clippy::cast_sign_loss)]
//             size: size as usize,
//             ptr: buffer,
//         })
//     }
// }

// impl IntoIterator for Buffer
// where
//     <Self::IntoIter as Iterator>::Item = Self::Item,
// {
//     type Item = u8;

//     type IntoIter = Iterator;

//     fn into_iter(self) -> Self::IntoIter {
//         todo!()
//     }
// }

#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
unsafe extern "C" fn encrypt(
    file: *mut sqlite3_file,
    buffer: *const c_void,
    size: c_int,
    offset: sqlite3_int64,
) -> c_int {
    let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
    //rot13 for now
    for i in 0..buf.len() {
        buf[i] = unsafe { *(buffer.byte_offset(i as isize).cast::<u8>()) }.wrapping_add(13);
    }
    let act_file: *mut MaidenhairFile = file.cast::<MaidenhairFile>();
    unsafe { ((*act_file).pointers.write_ptr)(file, (&raw const buf[0]).cast(), size, offset) }
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
unsafe extern "C" fn decrypt(
    file: *mut sqlite3_file,
    buffer: *mut c_void,
    size: c_int,
    offset: sqlite3_int64,
) -> c_int {
    //read actual file
    let act_file: *mut MaidenhairFile = file.cast::<MaidenhairFile>();
    let ret = unsafe { ((*act_file).pointers.read_ptr)(file, buffer, size, offset) };
    //decrypt in place
    for i in 0..(size as isize) {
        unsafe {
            *buffer.byte_offset(i) = std::mem::transmute::<u8, c_void>(
                *buffer.byte_offset(i).cast::<u8>().wrapping_byte_sub(13),
            );
        };
    }
    ret
}

/// opens the backing file and passes the en/de-cryption shim functions
///
/// # Safety
/// Passes function pointers of the VFS, which are either safe-ish rust ffi or come
/// from the backing VFS. No arithmetic is performed. Involves some type erasure
/// lets pray that the pointer offsets always match.
#[allow(unused_variables, non_snake_case, clippy::missing_const_for_fn)]
unsafe extern "C" fn maidenhair_open(
    vfs: *mut sqlite3_vfs,
    zName: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    pOutFlags: *mut c_int,
) -> c_int {
    let vfs: *mut MaidenhairVFS = unsafe { (*vfs).pAppData.cast::<MaidenhairVFS>() };
    let backing: sqlite3_vfs = unsafe { *(*vfs).backing_vfs };

    //run backing open function to obtain r/w function pointers
    let mut ret_code = backing.xOpen.map_or(-100, |open| unsafe {
        open((*vfs).backing_vfs, zName, file, flags, pOutFlags)
    });

    //should have been initialized by backing VFS
    let methods: sqlite3_io_methods = unsafe { *(*file).pMethods };
    let read = methods.xRead;
    let write = methods.xWrite;

    //need to realloc file to make space for the extra two pointers
    unsafe {
        #[allow(clippy::cast_sign_loss)]
        libc::realloc(
            file.cast(),
            backing.szOsFile as usize + size_of::<BackingPtrs>(),
        )
    };

    let extendedFile: *mut MaidenhairFile = file.cast::<MaidenhairFile>();

    if let (Some(read), Some(write)) = (read, write) {
        unsafe {
            //wrapping function pointers for crypto
            let methods: *mut sqlite3_io_methods = ((*extendedFile).file).pMethods.cast_mut();
            (*methods).xRead = Some(decrypt);
            (*methods).xWrite = Some(encrypt);

            //backing ptrs
            (*extendedFile).pointers.read_ptr = read;
            (*extendedFile).pointers.write_ptr = write;
        }
    } else {
        //what the hell happend?
        ret_code = -100;
    }

    ret_code
}

#[must_use]
pub fn vfs_maidenhair_init(z_old_vfs: &CStr) -> sqlite3_vfs {
    let backing_vfs = unsafe { sqlite3_vfs_find(z_old_vfs.as_ptr()) };
    let backing: sqlite3_vfs = unsafe { *backing_vfs };

    // leak as its passed to sqlite3
    // i have no idea to get it free'ed after this
    let vfs = Box::new(MaidenhairVFS { backing_vfs });
    let mut vfs = Box::leak(vfs);
    sqlite3_vfs {
        iVersion: backing.iVersion,
        //unwrap should never fail and be optimized out
        szOsFile: backing.szOsFile + i32::try_from(size_of::<BackingPtrs>()).unwrap_or(0),
        mxPathname: backing.mxPathname,
        pNext: backing_vfs,
        zName: b"maidenhair".as_ptr().cast::<i8>(),
        pAppData: (&raw mut vfs).cast::<std::ffi::c_void>(),
        xOpen: Some(maidenhair_open),
        xDelete: backing.xDelete,
        xAccess: backing.xAccess,
        xFullPathname: backing.xFullPathname,
        xDlOpen: backing.xDlOpen,
        xDlError: backing.xDlError,
        xDlSym: backing.xDlSym,
        xDlClose: backing.xDlClose,
        xRandomness: backing.xRandomness,
        xSleep: backing.xSleep,
        xCurrentTime: backing.xCurrentTime,
        xGetLastError: backing.xGetLastError,
        xCurrentTimeInt64: backing.xCurrentTimeInt64,
        xSetSystemCall: backing.xSetSystemCall,
        xGetSystemCall: backing.xGetSystemCall,
        xNextSystemCall: backing.xNextSystemCall,
    }
}
