use std::ffi::{CStr, CString, c_char, c_int, c_void};

use sqlite3ext_sys::{
    SQLITE_ERROR, SQLITE_OK, sqlite3, sqlite3_api_routines, sqlite3_create_module, sqlite3_file,
    sqlite3_int64, sqlite3_io_methods, sqlite3_realloc64, sqlite3_vfs, sqlite3_vfs_find,
    sqlite3_vfs_register,
};

fn debug(msg: &str) {
    #[cfg(debug_assertions)]
    println!("{msg}");
}

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
    debug("Encrypt called");
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
    debug("Decrypt called");
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
#[allow(
    unused_variables,
    non_snake_case,
    clippy::missing_const_for_fn,
    clippy::cast_possible_wrap
)]
unsafe extern "C" fn maidenhair_open(
    vfs: *mut sqlite3_vfs,
    zName: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    pOutFlags: *mut c_int,
) -> c_int {
    debug("Opening File");
    let mvfs: *mut MaidenhairVFS = unsafe { (*vfs).pAppData.cast::<MaidenhairVFS>() };
    debug("cast successful");

    let backing: sqlite3_vfs = unsafe { *(*mvfs).backing_vfs };
    debug("recovered backing");

    //run backing open function to obtain r/w function pointers
    let mut ret_code: i32 = backing.xOpen.map_or(SQLITE_ERROR as i32, |open| unsafe {
        open(vfs, zName, file, flags, pOutFlags)
    });
    debug("Opened db file");

    if ret_code == SQLITE_OK as i32 {
        debug("Backing Open OK");
    }

    debug("Saving backing pointers");
    //should have been initialized by backing VFS
    let methods: sqlite3_io_methods = unsafe { *(*file).pMethods };
    let read = methods.xRead;
    let write = methods.xWrite;

    debug("Extending file object length");
    //need to realloc file to make space for the extra two pointers
    unsafe {
        #[allow(clippy::cast_sign_loss)]
        sqlite3_realloc64(
            file.cast(),
            backing.szOsFile as u64 + size_of::<BackingPtrs>() as u64,
        );
    };

    let extendedFile: *mut MaidenhairFile = file.cast::<MaidenhairFile>();

    if let (Some(read), Some(write)) = (read, write) {
        unsafe {
            debug("adding wrapper functions");
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
        ret_code = SQLITE_ERROR as i32;
    }

    ret_code
}

/// .
///
/// # Safety
/// Only Deferences a passed pointer to backing VFS, nullptr check is performed.
///
/// # Errors
/// Returns `SQLITE_ERROR` if a nullptr is passed as backing VFS
///
#[allow(clippy::missing_panics_doc)]
pub unsafe fn vfs_maidenhair_init(
    backing_vfs: *mut sqlite3_vfs,
) -> Result<*mut sqlite3_vfs, c_int> {
    if backing_vfs.is_null() {
        #[allow(clippy::cast_possible_wrap)]
        return Err(SQLITE_ERROR as c_int);
    }
    let backing = unsafe { *backing_vfs };
    debug(
        format!(
            "backing name:{}",
            unsafe { CStr::from_ptr(backing.zName) }
                .to_str()
                .unwrap_or_default()
        )
        .as_str(),
    );
    // leak as its passed to sqlite3
    // i have no idea to get it free'ed after this
    let vfs = Box::new(MaidenhairVFS { backing_vfs });
    let vfs = Box::into_raw(vfs);

    let name = Box::new(CString::from(c"maidenhair"));
    let name = Box::leak(name);

    let res = Box::new(sqlite3_vfs {
        iVersion: backing.iVersion,
        //unwrap should never fail and be optimized out
        szOsFile: backing.szOsFile + i32::try_from(size_of::<BackingPtrs>()).unwrap_or(0),
        mxPathname: backing.mxPathname,
        pNext: std::ptr::null_mut(),
        zName: name.as_ptr(),
        pAppData: vfs.cast(),
        // xOpen: backing.xOpen,
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
    });
    let res = Box::into_raw(res);
    Ok(res)
}

#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
#[used]
pub static mut sqlite3_api: *mut sqlite3_api_routines = std::ptr::null_mut();

/// .
///
/// # Safety
/// This is C land. Memory is managed by sqlite, there be dragons.
///
//entrypoint
#[allow(clippy::cast_possible_wrap, clippy::missing_panics_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_maidenhair_init(
    db: *mut sqlite3,
    err_msg: *mut *mut c_char,
    p_api: *mut sqlite3_api_routines,
) -> c_int {
    //get default VFS
    unsafe { sqlite3_api = p_api };
    debug("construct backing VFS");
    let backing = unsafe { ((*sqlite3_api).vfs_find.unwrap())(std::ptr::null()) };
    let vfs = unsafe { vfs_maidenhair_init(backing) };
    match vfs {
        Ok(vfs) => {
            // let rc = unsafe { sqlite3_vfs_register(&raw mut vfs, 1) };
            let rc = unsafe { ((*sqlite3_api).vfs_register.unwrap())(vfs, 0) };
            if rc == SQLITE_OK as i32 {
                debug("VFS register OK");
                //test if autoload is ok
                // rc = unsafe { sqlite3_auto_extension(None) };
            }
            rc
        }
        Err(e) => e,
    }
}

#[allow(clippy::missing_panics_doc)]
#[test]
pub fn load_and_run() {
    use sqlx::{Connection, SqliteConnection};
    use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
    use std::str::FromStr;
    let opts = SqliteConnectOptions::new()
        .in_memory(true)
        .extension("libmaidenhair.so");
    let opts_with_vfs = SqliteConnectOptions::from_str("./test.db")
        .unwrap()
        .create_if_missing(true)
        .extension("libmaidenhair.so")
        .vfs("maidenhair");
    smol::block_on(async {
        //load extension
        let mut a = SqliteConnection::connect_with(&opts).await.unwrap();
        // for e in vfss {
        // }
        //open with VFS
        let db = SqlitePool::connect_with(opts_with_vfs).await.unwrap();
        sqlx::query("CREATE TABLE hello (id INTEGER);")
            .execute(&db)
            .await
            .unwrap();
    });
}
