use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    str::FromStr,
    thread::sleep,
    time::Duration,
};

use sqlite3ext_sys::{
    SQLITE_ERROR, SQLITE_OK, sqlite3, sqlite3_api_routines, sqlite3_file, sqlite3_int64,
    sqlite3_io_methods, sqlite3_vfs,
};

fn debug(msg: &str) {
    #[cfg(debug_assertions)]
    println!("{msg}");
}

//api function table from the SQLite proccess that loads this
#[allow(non_upper_case_globals)]
#[used]
static mut sqlite3_api: *mut sqlite3_api_routines = std::ptr::null_mut();

unsafe fn sqlite3_vfs_find(vfs: Option<&str>) -> *mut sqlite3_vfs {
    let vfs: *const i8 = vfs.map_or(std::ptr::null(), |vfs| {
        CString::from_str(vfs)
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null())
    });
    unsafe { ((*sqlite3_api).vfs_find.unwrap_unchecked())(vfs) }
}

unsafe fn sqlite3_vfs_register(vfs: *mut sqlite3_vfs, default: bool) -> c_int {
    unsafe { (*sqlite3_api).vfs_register.unwrap_unchecked()(vfs, i32::from(default)) }
}

unsafe fn sqlite3_realloc64(buf: *mut c_void, len: u64) {
    unsafe { ((*sqlite3_api).realloc64.unwrap_unchecked())(buf, len) };
}

type ReadPtr = unsafe extern "C" fn(*mut sqlite3_file, *mut c_void, c_int, sqlite3_int64) -> c_int;
type WritePtr =
    unsafe extern "C" fn(*mut sqlite3_file, *const c_void, c_int, sqlite3_int64) -> c_int;

#[repr(C)]
struct BackendPtrs {
    //pointers to backend funcs
    read_ptr: ReadPtr,
    write_ptr: WritePtr,
}

#[repr(C)]
struct MaidenhairFile {
    //has to be at the base for pointer offsets to match
    file: sqlite3_file,
    pointers: BackendPtrs,
}

#[repr(C)]
struct MaidenhairVFS {
    backend: *mut sqlite3_vfs,
}

// #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
// unsafe extern "C" fn encrypt(
//     file: *mut sqlite3_file,
//     buffer: *const c_void,
//     size: c_int,
//     offset: sqlite3_int64,
// ) -> c_int {
//     debug("Encrypt called");
//     let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
//     //rot13 for now
//     for i in 0..buf.len() {
//         buf[i] = unsafe { *(buffer.byte_offset(i as isize).cast::<u8>()) }.wrapping_add(13);
//     }
//     let act_file: *mut MaidenhairFile = file.cast::<MaidenhairFile>();
//     unsafe { ((*act_file).pointers.write_ptr)(file, (&raw const buf[0]).cast(), size, offset) }
// }

// #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
// unsafe extern "C" fn decrypt(
//     file: *mut sqlite3_file,
//     buffer: *mut c_void,
//     size: c_int,
//     offset: sqlite3_int64,
// ) -> c_int {
//     debug("Decrypt called");
//     //read actual file
//     let act_file: *mut MaidenhairFile = file.cast::<MaidenhairFile>();
//     let ret = unsafe { ((*act_file).pointers.read_ptr)(file, buffer, size, offset) };
//     //decrypt in place
//     for i in 0..(size as isize) {
//         unsafe {
//             *buffer.byte_offset(i) = std::mem::transmute::<u8, c_void>(
//                 *buffer.byte_offset(i).cast::<u8>().wrapping_byte_sub(13),
//             );
//         };
//     }
//     ret
// }

// /// opens the backend file and passes the en/de-cryption shim functions
// ///
// /// # Safety
// /// Passes function pointers of the VFS, which are either safe-ish rust ffi or come
// /// from the backend VFS. No arithmetic is performed. Involves some type erasure
// /// lets pray that the pointer offsets always match.
// #[allow(
//     unused_variables,
//     non_snake_case,
//     clippy::missing_const_for_fn,
//     clippy::cast_possible_wrap
// )]
// pub unsafe extern "C" fn maidenhair_open(
//     vfs: *mut sqlite3_vfs,
//     zName: *const c_char,
//     file: *mut sqlite3_file,
//     flags: c_int,
//     pOutFlags: *mut c_int,
// ) -> c_int {
//     if vfs.is_null() || zName.is_null() || file.is_null() || pOutFlags.is_null() {
//         debug("open failed, some value was null");
//         return SQLITE_ERROR as i32;
//     }
//     debug("Opening File");
//     // let mvfs: *mut MaidenhairVFS = unsafe { (*vfs).pAppData.cast::<MaidenhairVFS>() };

//     let backend: sqlite3_vfs = unsafe { *vfs };
//     debug("recovered backend");

//     //run backend open function to obtain r/w function pointers
//     let mut ret_code: i32 = backend.xOpen.map_or(SQLITE_ERROR as i32, |open| unsafe {
//         open(vfs, zName, file, flags, pOutFlags)
//     });
//     debug("Opened db file");

//     if ret_code == SQLITE_OK as i32 {
//         debug("Backend Open OK");
//     }

//     debug("Saving backend pointers");
//     //should have been initialized by backend VFS
//     let methods: &sqlite3_io_methods = unsafe { &*(*file).pMethods };
//     let read = methods.xRead;
//     let write = methods.xWrite;

//     debug("Extending file object length");
//     // shouldn't be needed as OS file size has already been increased
//     // unsafe {
//     //     #[allow(clippy::cast_sign_loss)]
//     //     sqlite3_realloc64(
//     //         file.cast(),
//     //         backend.szOsFile as u64 + size_of::<BackendPtrs>() as u64,
//     //     );
//     // };

//     let extendedFile: *mut MaidenhairFile = file.cast::<MaidenhairFile>();

//     if let (Some(read), Some(write)) = (read, write) {
//         unsafe {
//             debug("adding wrapper functions");
//             //wrapping function pointers for crypto
//             let methods: *mut sqlite3_io_methods = ((*extendedFile).file).pMethods.cast_mut();
//             (*methods).xRead = Some(decrypt);
//             (*methods).xWrite = Some(encrypt);

//             //backend ptrs
//             (*extendedFile).pointers.read_ptr = read;
//             (*extendedFile).pointers.write_ptr = write;
//         }
//     } else {
//         //what the hell happend?
//         ret_code = SQLITE_ERROR as i32;
//     }

//     ret_code
// }

#[unsafe(no_mangle)]
unsafe extern "C" fn test(
    vfs: *mut sqlite3_vfs,
    zName: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    pOutFlags: *mut c_int,
) -> c_int {
    debug("Hello from test");
    sleep(Duration::from_secs(2));
    0
}

/// .
///
/// # Safety
/// Only Deferences a passed pointer to backend VFS, nullptr check is performed.
///
/// # Errors
/// Returns `SQLITE_ERROR` if a nullptr is passed as backend VFS
///
#[allow(clippy::missing_panics_doc)]
pub unsafe fn vfs_maidenhair_init(
    backend_vfs: *mut sqlite3_vfs,
) -> Result<*mut sqlite3_vfs, c_int> {
    if backend_vfs.is_null() {
        #[allow(clippy::cast_possible_wrap)]
        return Err(SQLITE_ERROR as c_int);
    }

    //convenience
    let backend = unsafe { &mut *backend_vfs };

    debug(&format!(
        "backend name:{}",
        unsafe { CStr::from_ptr((*backend_vfs).zName) }
            .to_str()
            .unwrap_or_default()
    ));
    // i have no idea to get it free'ed after this
    // let vfs = Box::leak(Box::new(MaidenhairVFS { backend }));

    let name = Box::leak(Box::new(CString::from(c"maidenhair")));

    Ok(Box::into_raw(Box::new(sqlite3_vfs {
        iVersion: backend.iVersion,
        //unwrap should never fail and be optimized out
        szOsFile: backend.szOsFile + i32::try_from(size_of::<BackendPtrs>()).unwrap_or(0),
        mxPathname: backend.mxPathname,
        //should be set by sqlite upon register if i understand correctly
        pNext: std::ptr::null_mut(),
        zName: name.as_ptr(),
        pAppData: backend.pAppData,
        // xOpen: backend.xOpen,
        xOpen: Some(test),
        xDelete: backend.xDelete,
        xAccess: backend.xAccess,
        xFullPathname: backend.xFullPathname,
        xDlOpen: backend.xDlOpen,
        xDlError: backend.xDlError,
        xDlSym: backend.xDlSym,
        xDlClose: backend.xDlClose,
        xRandomness: backend.xRandomness,
        xSleep: backend.xSleep,
        xCurrentTime: backend.xCurrentTime,
        xGetLastError: backend.xGetLastError,
        xCurrentTimeInt64: backend.xCurrentTimeInt64,
        xSetSystemCall: backend.xSetSystemCall,
        xGetSystemCall: backend.xGetSystemCall,
        xNextSystemCall: backend.xNextSystemCall,
    })))
}

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
    debug("construct VFS shim using default backend");
    let backend = unsafe { sqlite3_vfs_find(None) };
    let vfs = unsafe { vfs_maidenhair_init(backend) };
    match vfs {
        Ok(vfs) => {
            let rc = unsafe { sqlite3_vfs_register(vfs, false) };
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
        let _ = SqliteConnection::connect_with(&opts).await.unwrap();
        //open with VFS
        let db = SqlitePool::connect_with(opts_with_vfs).await.unwrap();
        sqlx::query("CREATE TABLE hello (id INTEGER);")
            .execute(&db)
            .await
            .unwrap();
    });
}
